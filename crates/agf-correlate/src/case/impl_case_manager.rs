//! 由 `case.rs` 拆分：`CaseManager` 的实现（纯搬移，逻辑不变）。
use super::*;

impl Default for CaseManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CaseManager {
    /// 构造（无默认负责人）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            severity_policy: CaseSeverityPolicy::default(),
            default_owner: None,
            cases: BTreeMap::new(),
            code_seq: BTreeMap::new(),
        }
    }
    /// 设置默认负责人。
    #[must_use]
    pub fn with_default_owner(mut self, owner: impl Into<String>) -> Self {
        self.default_owner = Some(owner.into());
        self
    }
    /// 已登记案件数（全部租户）。
    #[must_use]
    pub fn len(&self) -> usize {
        self.cases.len()
    }
    /// 是否没有任何案件。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cases.is_empty()
    }
    /// 只读案件（租户校验）。
    ///
    /// # Errors
    /// 案件存在但不属于 `tenant` 时返回 [`CaseError::TenantViolation`]。
    pub fn get(&self, tenant: TenantId, case_id: Id) -> Result<Option<&CaseDetail>, CaseError> {
        match self.cases.get(&case_id) {
            None => Ok(None),
            Some(detail) if detail.case.tenant_id != tenant => Err(CaseError::TenantViolation {
                expected: tenant.to_string(),
                actual: detail.case.tenant_id.to_string(),
            }),
            Some(detail) => Ok(Some(detail)),
        }
    }
    /// 列出某租户的案件（按创建时间升序）。
    #[must_use]
    pub fn list(&self, tenant: TenantId) -> Vec<&CaseDetail> {
        let mut items: Vec<&CaseDetail> = self.cases.values().filter(|c| c.case.tenant_id == tenant).collect();
        items.sort_by(|a, b| a.case.created_at.cmp(&b.case.created_at).then_with(|| a.case.id.cmp(&b.case.id)));
        items
    }
    /// 某租户某状态下的案件数。
    #[must_use]
    pub fn count_by_state(&self, tenant: TenantId, state: CaseState) -> usize {
        self.cases.values().filter(|c| c.case.tenant_id == tenant && c.case.state == state).count()
    }
    /// 登记一个已构建好的案件（外部回填/持久化重建）。
    ///
    /// # Errors
    /// 案件 id 已登记时返回 [`CaseError::Duplicate`]。
    pub fn register(
        &mut self,
        case: Case,
        findings: Vec<Id>,
        timeline: Vec<CaseTimelineEvent>,
    ) -> Result<(), CaseError> {
        if self.cases.contains_key(&case.id) {
            return Err(CaseError::Duplicate(case.id));
        }
        self.bump_seq(case.tenant_id, &case.code);
        let mut timeline = timeline;
        timeline.sort_by(|a, b| a.at.cmp(&b.at).then_with(|| a.seq.cmp(&b.seq)));
        self.cases.insert(case.id, CaseDetail { case, findings, timeline });
        Ok(())
    }
    /// 由事件簇升级为案件。
    ///
    /// `affected_entities` 为簇覆盖的实体数（用于影响面与等级提升）；`actor` 记入时间线。
    ///
    /// # Errors
    /// 标题为空、簇租户与 `tenant` 不一致时返回错误。
    pub fn promote_cluster(
        &mut self,
        tenant: TenantId,
        cluster: &EventCluster,
        affected_entities: usize,
        actor: &str,
        now: Timestamp,
    ) -> Result<&CaseDetail, CaseError> {
        if cluster.tenant_id != tenant {
            return Err(CaseError::TenantViolation {
                expected: tenant.to_string(),
                actual: cluster.tenant_id.to_string(),
            });
        }
        if cluster.representative_title.trim().is_empty() {
            return Err(CaseError::InvalidInput("事件簇标题为空，不能升级为案件".to_string()));
        }
        let severity = self.severity_policy.derive(cluster, affected_entities);
        let title = format!("{}（{} 条聚合告警）", cluster.representative_title, cluster.occurrences);
        let summary = format!(
            "{}；实体 {}；类目 {}",
            cluster.summary(),
            cluster.entity_key.as_deref().unwrap_or("无"),
            cluster.category
        );
        let code = self.next_code(tenant, now);
        let case = Case {
            id: Id::new(),
            tenant_id: tenant,
            code,
            title,
            summary,
            severity,
            state: CaseState::New,
            alert_ids: cluster.alert_ids.clone(),
            finding_ids: Vec::new(),
            asset_ids: Vec::new(),
            owner: self.default_owner.clone(),
            collaborators: Vec::new(),
            security_incident: severity.weight() >= Severity::High.weight(),
            resolution: None,
            root_cause: None,
            lessons: None,
            evidence_bundle_ref: None,
            sla_due_at: None,
            sla_breached: false,
            tags: cluster.tags.iter().cloned().collect(),
            created_at: cluster.first_seen_at.max(now),
            closed_at: None,
            updated_at: now,
        };
        let case_id = case.id;
        let created = CaseTimelineEvent {
            id: Id::new(),
            tenant_id: tenant,
            case_id,
            kind: TimelineKind::Created,
            actor: actor.to_string(),
            note: format!(
                "由事件簇 {} 升级（原始 {} 条 / 去重 {} 条，影响实体 {}）",
                cluster.id, cluster.occurrences, cluster.dedup_count, affected_entities
            ),
            detail: serde_json::json!({
                "cluster_id": cluster.id,
                "occurrences": cluster.occurrences,
                "dedup_count": cluster.dedup_count,
                "entity": cluster.entity_key,
                "affected_entities": affected_entities,
            }),
            automated: false,
            at: now,
            seq: 0,
        };
        self.register(case, Vec::new(), vec![created])?;
        self.cases.get(&case_id).ok_or(CaseError::NotFound(case_id))
    }
    /// 直接创建案件（人工登记）。
    ///
    /// # Errors
    /// 标题为空时返回 [`CaseError::InvalidInput`]。
    pub fn create(
        &mut self,
        tenant: TenantId,
        title: &str,
        severity: Severity,
        owner: Option<&str>,
        actor: &str,
        now: Timestamp,
    ) -> Result<&CaseDetail, CaseError> {
        if title.trim().is_empty() {
            return Err(CaseError::InvalidInput("案件标题不能为空".to_string()));
        }
        let code = self.next_code(tenant, now);
        let case = Case {
            id: Id::new(),
            tenant_id: tenant,
            code,
            title: title.trim().to_string(),
            summary: String::new(),
            severity,
            state: CaseState::New,
            alert_ids: Vec::new(),
            finding_ids: Vec::new(),
            asset_ids: Vec::new(),
            owner: owner.map(ToString::to_string).or_else(|| self.default_owner.clone()),
            collaborators: Vec::new(),
            security_incident: severity.weight() >= Severity::High.weight(),
            resolution: None,
            root_cause: None,
            lessons: None,
            evidence_bundle_ref: None,
            sla_due_at: None,
            sla_breached: false,
            tags: Vec::new(),
            created_at: now,
            closed_at: None,
            updated_at: now,
        };
        let case_id = case.id;
        let created = CaseTimelineEvent {
            id: Id::new(),
            tenant_id: tenant,
            case_id,
            kind: TimelineKind::Created,
            actor: actor.to_string(),
            note: "人工创建案件".to_string(),
            detail: serde_json::Value::Null,
            automated: false,
            at: now,
            seq: 0,
        };
        self.register(case, Vec::new(), vec![created])?;
        self.cases.get(&case_id).ok_or(CaseError::NotFound(case_id))
    }
    /// 状态流转（**非法迁移报错**）。
    ///
    /// # Errors
    /// 案件不存在、跨租户、非法迁移时返回错误。
    pub fn transition(
        &mut self,
        tenant: TenantId,
        case_id: Id,
        next: CaseState,
        actor: &str,
        note: &str,
        now: Timestamp,
    ) -> Result<&CaseDetail, CaseError> {
        let current = {
            let detail = self.detail_for(tenant, case_id)?;
            detail.case.state
        };
        if !allowed_transitions(current).contains(&next) {
            return Err(CaseError::IllegalTransition {
                from: current.as_str(),
                to: next.as_str(),
                allowed: allowed_transitions(current).iter().map(CaseState::as_str).collect::<Vec<_>>().join(","),
            });
        }
        let seq = self.next_seq(case_id);
        let detail = self.cases.get_mut(&case_id).ok_or(CaseError::NotFound(case_id))?;
        apply_transition(&mut detail.case, next, now);
        let kind = if next == CaseState::Closed { TimelineKind::Closed } else { TimelineKind::StateChanged };
        detail.timeline.push(CaseTimelineEvent {
            id: Id::new(),
            tenant_id: tenant,
            case_id,
            kind,
            actor: actor.to_string(),
            note: if note.is_empty() {
                format!("状态流转 {} → {}", current.as_str(), next.as_str())
            } else {
                note.to_string()
            },
            detail: serde_json::json!({ "from": current.as_str(), "to": next.as_str() }),
            automated: false,
            at: now,
            seq,
        });
        self.cases.get(&case_id).ok_or(CaseError::NotFound(case_id))
    }
    /// 指派负责人（记录 `assigned` 时间线）。
    ///
    /// # Errors
    /// 案件不存在、跨租户、或已关闭时返回错误。
    pub fn assign(
        &mut self,
        tenant: TenantId,
        case_id: Id,
        owner: &str,
        actor: &str,
        now: Timestamp,
    ) -> Result<&CaseDetail, CaseError> {
        if owner.trim().is_empty() {
            return Err(CaseError::InvalidInput("负责人不能为空".to_string()));
        }
        {
            let detail = self.detail_for(tenant, case_id)?;
            if detail.is_closed() {
                return Err(CaseError::StateConflict { state: "closed", action: "assign" });
            }
        }
        let seq = self.next_seq(case_id);
        let detail = self.cases.get_mut(&case_id).ok_or(CaseError::NotFound(case_id))?;
        detail.case.owner = Some(owner.trim().to_string());
        detail.case.updated_at = now;
        detail.timeline.push(CaseTimelineEvent {
            id: Id::new(),
            tenant_id: tenant,
            case_id,
            kind: TimelineKind::Assigned,
            actor: actor.to_string(),
            note: format!("指派给 {owner}"),
            detail: serde_json::json!({ "owner": owner }),
            automated: false,
            at: now,
            seq,
        });
        self.cases.get(&case_id).ok_or(CaseError::NotFound(case_id))
    }
    /// 追加评论（自动化动作也可写入，`automated` 标记区分）。
    ///
    /// # Errors
    /// 案件不存在、跨租户时返回错误。
    pub fn comment(
        &mut self,
        tenant: TenantId,
        case_id: Id,
        actor: &str,
        note: &str,
        automated: bool,
        now: Timestamp,
    ) -> Result<&CaseDetail, CaseError> {
        self.detail_for(tenant, case_id)?;
        let seq = self.next_seq(case_id);
        let detail = self.cases.get_mut(&case_id).ok_or(CaseError::NotFound(case_id))?;
        detail.case.updated_at = now;
        detail.timeline.push(CaseTimelineEvent {
            id: Id::new(),
            tenant_id: tenant,
            case_id,
            kind: TimelineKind::Comment,
            actor: actor.to_string(),
            note: note.to_string(),
            detail: serde_json::Value::Null,
            automated,
            at: now,
            seq,
        });
        self.cases.get(&case_id).ok_or(CaseError::NotFound(case_id))
    }
    /// 关联 finding（去重，返回本次新增数）。
    ///
    /// # Errors
    /// 案件不存在、跨租户时返回错误。
    pub fn attach_finding(
        &mut self,
        tenant: TenantId,
        case_id: Id,
        finding_id: Id,
        actor: &str,
        now: Timestamp,
    ) -> Result<usize, CaseError> {
        self.detail_for(tenant, case_id)?;
        let seq = self.next_seq(case_id);
        let detail = self.cases.get_mut(&case_id).ok_or(CaseError::NotFound(case_id))?;
        if detail.findings.contains(&finding_id) {
            return Ok(0);
        }
        detail.findings.push(finding_id);
        detail.case.finding_ids.push(finding_id);
        detail.case.updated_at = now;
        detail.timeline.push(CaseTimelineEvent {
            id: Id::new(),
            tenant_id: tenant,
            case_id,
            kind: TimelineKind::EvidenceAdded,
            actor: actor.to_string(),
            note: format!("关联 finding {finding_id}"),
            detail: serde_json::json!({ "finding_id": finding_id }),
            automated: false,
            at: now,
            seq,
        });
        Ok(1)
    }
}
