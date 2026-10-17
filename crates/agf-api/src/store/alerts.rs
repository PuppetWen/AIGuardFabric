//! 告警的去重 upsert、查询、状态流转与 SLA 更新。

use super::*;

impl ApiStore {
    // ---------------------------------------------------------------- 告警

    /// 按去重键 upsert 告警（活动态合并，返回 `(id, 是否新建)`）。
    ///
    /// # Errors
    /// 锁中毒。
    #[allow(clippy::too_many_arguments)]
    pub fn alert_upsert_dedup(
        &self,
        tenant: TenantId,
        dedup_key: &str,
        title: &str,
        description: &str,
        severity: Severity,
        domain: Option<RiskDomain>,
        asset_ids: &[Id],
        finding_ids: &[Id],
    ) -> DomainResult<(Id, bool)> {
        let mut mem = self.lock()?;
        let existing = mem
            .alerts
            .iter()
            .find(|((t, _), a)| *t == tenant && a.dedup_key == dedup_key && a.is_active())
            .map(|((_, id), a)| (*id, a.clone()));
        if let Some((id, mut alert)) = existing {
            alert.merge_occurrence(Timestamp::now(), &[]);
            if severity > alert.severity {
                alert.severity = severity;
            }
            for a in asset_ids {
                if !alert.asset_ids.contains(a) {
                    alert.asset_ids.push(*a);
                }
            }
            for f in finding_ids {
                if !alert.finding_ids.contains(f) {
                    alert.finding_ids.push(*f);
                }
            }
            alert.updated_at = Timestamp::now();
            let sla_due_at = alert.sla_due_at;
            mem.alerts.insert((tenant, id), alert);
            drop(mem);
            self.journal(PgWrite::AlertDedup {
                write: Box::new(AlertWrite {
                    tenant,
                    memory_id: id,
                    dedup_key: dedup_key.to_string(),
                    title: title.to_string(),
                    description: description.to_string(),
                    severity,
                    domain,
                    asset_ids: asset_ids.to_vec(),
                    finding_ids: finding_ids.to_vec(),
                    sla_due_at,
                }),
            });
            return Ok((id, false));
        }
        let now = Timestamp::now();
        let alert = agf_core::alert::Alert {
            id: Id::new(),
            tenant_id: tenant,
            title: title.to_string(),
            description: description.to_string(),
            severity,
            domain,
            state: AlertState::Open,
            finding_ids: finding_ids.to_vec(),
            dedup_count: 1,
            dedup_key: dedup_key.to_string(),
            asset_ids: asset_ids.to_vec(),
            event_ids: Vec::new(),
            affected_hosts: Vec::new(),
            first_seen_at: now,
            last_seen_at: now,
            assignee: None,
            case_id: None,
            escalation_level: 0,
            sla_due_at: Some(now.offset_secs(agf_core::alert::Alert::sla_secs(severity))),
            sla_breached: false,
            tags: Vec::new(),
            created_at: now,
            updated_at: now,
        };
        let id = alert.id;
        let sla_due_at = alert.sla_due_at;
        mem.alerts.insert((tenant, id), alert);
        drop(mem);
        self.journal(PgWrite::AlertDedup {
            write: Box::new(AlertWrite {
                tenant,
                memory_id: id,
                dedup_key: dedup_key.to_string(),
                title: title.to_string(),
                description: description.to_string(),
                severity,
                domain,
                asset_ids: asset_ids.to_vec(),
                finding_ids: finding_ids.to_vec(),
                sla_due_at,
            }),
        });
        Ok((id, true))
    }

    /// 列出告警。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn alert_list(
        &self,
        tenant: TenantId,
        state: Option<AlertState>,
        severity: Option<Severity>,
    ) -> DomainResult<Vec<agf_core::alert::Alert>> {
        let mut items: Vec<agf_core::alert::Alert> = self
            .lock()?
            .alerts
            .iter()
            .filter(|((t, _), _)| *t == tenant)
            .map(|(_, a)| a.clone())
            .filter(|a| state.is_none_or(|s| a.state == s))
            .filter(|a| severity.is_none_or(|s| a.severity == s))
            .collect();
        items.sort_by(|a, b| {
            b.severity.weight().cmp(&a.severity.weight()).then_with(|| b.last_seen_at.cmp(&a.last_seen_at))
        });
        Ok(items)
    }

    /// 读取告警。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn alert_get(&self, tenant: TenantId, id: Id) -> DomainResult<Option<agf_core::alert::Alert>> {
        Ok(self.lock()?.alerts.get(&(tenant, id)).cloned())
    }

    /// 更新告警状态。
    ///
    /// # Errors
    /// 不存在或锁中毒。
    pub fn alert_set_state(
        &self,
        tenant: TenantId,
        id: Id,
        state: AlertState,
        assignee: Option<String>,
    ) -> DomainResult<agf_core::alert::Alert> {
        let mut mem = self.lock()?;
        let Some(alert) = mem.alerts.get_mut(&(tenant, id)) else {
            return Err(DomainError::NotFound { entity: "alert", id: id.to_string() });
        };
        alert.state = state;
        if let Some(who) = assignee {
            alert.assignee = Some(who);
        }
        alert.updated_at = Timestamp::now();
        let updated = alert.clone();
        drop(mem);
        self.journal(PgWrite::AlertSetState { tenant, id, state, assignee: updated.assignee.clone() });
        Ok(updated)
    }

    /// 写回告警的 SLA 派生字段（`sla_due_at` / `sla_breached` / `escalation_level`）。
    ///
    /// ## 为什么需要它
    /// `POST /api/v1/alerts/sla-refresh` 与 `POST /api/v1/alerts/{id}/escalate` 的结论来自
    /// `agf_correlate::sla` 的**三档实时判定**（响应目标/遏制目标/解决目标 + 逾期 + 升级阶梯），
    /// 而 `agf-core` 的 [`agf_core::alert::Alert::refresh_sla`] 是**单值口径**（一个截止 + 一个超时位）。
    /// 两者不落回同一行就会长期分叉：控制台看到的 `sla_due_at` 与引擎判定不一致。
    /// 本方法把引擎结论写回台账的那三个字段，**不触碰**状态/指派/去重计数等业务字段。
    ///
    /// # Errors
    /// 告警不存在或锁中毒。
    pub fn alert_set_sla(
        &self,
        tenant: TenantId,
        id: Id,
        due_at: Option<Timestamp>,
        breached: bool,
        escalation_level: u8,
    ) -> DomainResult<agf_core::alert::Alert> {
        let mut mem = self.lock()?;
        let Some(alert) = mem.alerts.get_mut(&(tenant, id)) else {
            return Err(DomainError::NotFound { entity: "alert", id: id.to_string() });
        };
        alert.sla_due_at = due_at;
        alert.sla_breached = breached;
        alert.escalation_level = alert.escalation_level.max(escalation_level);
        alert.updated_at = Timestamp::now();
        Ok(alert.clone())
    }
}
