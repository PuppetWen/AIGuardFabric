//! 案件的创建、查询、状态流转、事件与 SLA。

use super::*;

impl ApiStore {
    // ---------------------------------------------------------------- 案件

    /// 新建案件（自动编号 `CASE-<年>-<序号>`）。
    ///
    /// # Errors
    /// 锁中毒。
    #[allow(clippy::too_many_arguments)]
    pub fn case_create(
        &self,
        tenant: TenantId,
        title: &str,
        summary: &str,
        severity: Severity,
        alert_ids: &[Id],
        finding_ids: &[Id],
        asset_ids: &[Id],
        owner: Option<&str>,
    ) -> DomainResult<Case> {
        let now = Timestamp::now();
        let year = chrono::Datelike::year(&now.as_datetime());
        let mut mem = self.lock()?;
        if alert_ids.iter().any(|id| mem.alerts.get(&(tenant, *id)).is_some_and(|alert| alert.case_id.is_some())) {
            return Err(DomainError::Conflict("An alert already belongs to another case".into()));
        }
        let seq = mem.case_seq.entry(year).or_insert(0);
        *seq = seq.saturating_add(1);
        let code = Case::make_code(year, *seq);
        let case = Case {
            id: Id::new(),
            tenant_id: tenant,
            code,
            title: title.to_string(),
            summary: summary.to_string(),
            severity,
            state: CaseState::New,
            alert_ids: alert_ids.to_vec(),
            finding_ids: finding_ids.to_vec(),
            asset_ids: asset_ids.to_vec(),
            owner: owner.map(ToString::to_string),
            collaborators: Vec::new(),
            security_incident: false,
            resolution: None,
            root_cause: None,
            lessons: None,
            evidence_bundle_ref: None,
            sla_due_at: Some(now.offset_secs(agf_core::alert::Alert::sla_secs(severity))),
            sla_breached: false,
            tags: Vec::new(),
            created_at: now,
            closed_at: None,
            updated_at: now,
        };
        mem.cases.insert((tenant, case.id), case.clone());
        // 关系是双向的：`Case.alert_ids` 指向告警，`Alert.case_id` 必须指回案件。
        // 只写一侧会让"告警 → 案件"的下游动作（升级时追加案件时间线、按案件收敛告警）
        // 永远拿不到案件，属真实的数据完整性缺口，这里补齐（同租户、已存在才写）。
        for alert_id in alert_ids {
            if let Some(alert) = mem.alerts.get_mut(&(tenant, *alert_id)) {
                alert.case_id = Some(case.id);
                alert.updated_at = now;
            }
        }
        drop(mem);
        self.journal(PgWrite::CaseCreate { case: Box::new(case.clone()) });
        Ok(case)
    }

    /// 列出案件（创建时间倒序）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn case_list(&self, tenant: TenantId) -> DomainResult<Vec<Case>> {
        let mut items: Vec<Case> =
            self.lock()?.cases.iter().filter(|((t, _), _)| *t == tenant).map(|(_, c)| c.clone()).collect();
        items.sort_by_key(|c| std::cmp::Reverse(c.created_at));
        Ok(items)
    }

    /// 读取案件。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn case_get(&self, tenant: TenantId, id: Id) -> DomainResult<Option<Case>> {
        Ok(self.lock()?.cases.get(&(tenant, id)).cloned())
    }

    /// 案件状态流转（按 [`Case::can_transition_to`] 校验）。
    ///
    /// # Errors
    /// 不存在或非法流转。
    pub fn case_set_state(
        &self,
        tenant: TenantId,
        id: Id,
        state: CaseState,
        resolution: Option<String>,
    ) -> DomainResult<Case> {
        self.case_set_state_as(tenant, id, state, resolution, "api")
    }

    pub(super) fn case_set_state_as(
        &self,
        tenant: TenantId,
        id: Id,
        state: CaseState,
        resolution: Option<String>,
        actor: &str,
    ) -> DomainResult<Case> {
        let mut mem = self.lock()?;
        let Some(case) = mem.cases.get_mut(&(tenant, id)) else {
            return Err(DomainError::NotFound { entity: "case", id: id.to_string() });
        };
        if case.state != state && !case.can_transition_to(state) {
            return Err(DomainError::Conflict(format!("非法案件流转: {} → {}", case.state.as_str(), state.as_str())));
        }
        if case.state == state && resolution.as_ref().is_none_or(|value| Some(value) == case.resolution.as_ref()) {
            return Ok(case.clone());
        }
        case.state = state;
        if let Some(res) = resolution {
            case.resolution = Some(res);
        }
        if state == CaseState::Closed && case.closed_at.is_none() {
            case.closed_at = Some(Timestamp::now());
        }
        case.updated_at = Timestamp::now();
        let snapshot = case.clone();
        drop(mem);
        self.journal(PgWrite::CaseSetState { tenant, id, state, resolution: snapshot.resolution.clone() });
        self.case_add_event(
            tenant,
            id,
            agf_core::case::CaseEventKind::StateChanged,
            actor,
            &format!("状态流转到 {}", state.as_str()),
        )?;
        Ok(snapshot)
    }

    /// 追加案件时间线事件。
    ///
    /// # Errors
    /// 案件不存在或锁中毒。
    pub fn case_add_event(
        &self,
        tenant: TenantId,
        case_id: Id,
        kind: agf_core::case::CaseEventKind,
        actor: &str,
        note: &str,
    ) -> DomainResult<CaseEvent> {
        let mut mem = self.lock()?;
        if !mem.cases.contains_key(&(tenant, case_id)) {
            return Err(DomainError::NotFound { entity: "case", id: case_id.to_string() });
        }
        let event = CaseEvent {
            id: Id::new(),
            tenant_id: tenant,
            case_id,
            kind,
            actor: actor.to_string(),
            note: note.to_string(),
            detail: serde_json::Value::Null,
            automated: false,
            at: Timestamp::now(),
        };
        mem.case_events.push(event.clone());
        drop(mem);
        self.journal(PgWrite::CaseAddEvent { event: Box::new(event.clone()) });
        Ok(event)
    }

    /// 案件时间线。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn case_events(&self, tenant: TenantId, case_id: Id) -> DomainResult<Vec<CaseEvent>> {
        Ok(self.lock()?.case_events.iter().filter(|e| e.tenant_id == tenant && e.case_id == case_id).cloned().collect())
    }

    /// 写回案件的 SLA 派生字段（`sla_due_at` / `sla_breached`）。
    ///
    /// 与 [`ApiStore::alert_set_sla`] 同口径：`GET /api/v1/cases/{id}/sla` 的结论来自
    /// `agf_correlate::sla` 的三档判定（`case_sla_fields`：最近未逾期的截止 + 汇总违约位），
    /// 写回台账的两个派生字段，让控制台/报表读到的口径与引擎一致；**不触碰**状态、决议、
    /// 时间线等业务字段。
    ///
    /// # Errors
    /// 案件不存在或锁中毒。
    pub fn case_set_sla(
        &self,
        tenant: TenantId,
        id: Id,
        due_at: Option<Timestamp>,
        breached: bool,
    ) -> DomainResult<Case> {
        let mut mem = self.lock()?;
        let Some(case) = mem.cases.get_mut(&(tenant, id)) else {
            return Err(DomainError::NotFound { entity: "case", id: id.to_string() });
        };
        case.sla_due_at = due_at;
        case.sla_breached = breached;
        case.updated_at = Timestamp::now();
        Ok(case.clone())
    }
}
