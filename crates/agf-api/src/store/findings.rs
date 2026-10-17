//! 风险发现的写入与查询，以及策略库的增删改查。

use super::*;

impl ApiStore {
    // ---------------------------------------------------------------- 发现

    /// 写入发现。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn finding_insert(&self, finding: &Finding) -> DomainResult<Id> {
        self.lock()?.findings.insert((finding.tenant_id, finding.id), finding.clone());
        self.journal(PgWrite::FindingInsert { finding: Box::new(finding.clone()) });
        Ok(finding.id)
    }

    /// 读取发现。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn finding_get(&self, tenant: TenantId, id: Id) -> DomainResult<Option<Finding>> {
        Ok(self.lock()?.findings.get(&(tenant, id)).cloned())
    }

    /// 列出全部发现。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn finding_list_all(&self, tenant: TenantId) -> DomainResult<Vec<Finding>> {
        Ok(self.lock()?.findings.iter().filter(|((t, _), _)| *t == tenant).map(|(_, f)| f.clone()).collect())
    }

    /// 分页列出发现（支持域/等级/状态过滤）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn finding_list(
        &self,
        tenant: TenantId,
        req: &PageRequest,
        domain: Option<RiskDomain>,
        min_severity: Option<Severity>,
        state: Option<agf_core::risk::FindingState>,
    ) -> DomainResult<Page<Finding>> {
        let items: Vec<Finding> = self
            .lock()?
            .findings
            .iter()
            .filter(|((t, _), _)| *t == tenant)
            .map(|(_, f)| f.clone())
            .filter(|f| domain.is_none_or(|d| f.domain == d))
            .filter(|f| min_severity.is_none_or(|s| f.severity >= s))
            .filter(|f| state.is_none_or(|s| f.state == s))
            .collect();
        Ok(super::pagination_page(items, req))
    }

    /// 更新发现状态与注记。
    ///
    /// # Errors
    /// 发现不存在或锁中毒。
    pub fn finding_set_state(
        &self,
        tenant: TenantId,
        id: Id,
        state: agf_core::risk::FindingState,
        verify_note: Option<String>,
        evidence_level: Option<EvidenceLevel>,
    ) -> DomainResult<Finding> {
        let mut mem = self.lock()?;
        let Some(finding) = mem.findings.get_mut(&(tenant, id)) else {
            return Err(DomainError::NotFound { entity: "finding", id: id.to_string() });
        };
        finding.state = state;
        if let Some(note) = verify_note {
            finding.verify_note = Some(note);
        }
        if let Some(level) = evidence_level {
            finding.evidence_level = level;
        }
        finding.updated_at = Timestamp::now();
        let updated = finding.clone();
        drop(mem);
        self.journal(PgWrite::FindingSetState {
            tenant,
            id,
            state,
            verify_note: updated.verify_note.clone(),
            evidence_level: Some(updated.evidence_level),
        });
        Ok(updated)
    }

    // ---------------------------------------------------------------- 策略

    /// 按名称 upsert 策略（同租户同名覆盖并递增版本号）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn policy_upsert(&self, tenant: TenantId, mut policy: Policy) -> DomainResult<Policy> {
        let mut mem = self.lock()?;
        if let Some(existing) = mem.policies.values().find(|p| p.tenant_id == tenant && p.name == policy.name).cloned()
        {
            policy.id = existing.id;
            policy.version = existing.version.saturating_add(1);
            policy.created_at = existing.created_at;
        }
        policy.tenant_id = tenant;
        policy.updated_at = Timestamp::now();
        policy.content_hash = policy.compute_hash();
        mem.policies.insert((tenant, policy.id), policy.clone());
        drop(mem);
        self.journal(PgWrite::PolicyUpsert { policy: Box::new(policy.clone()) });
        Ok(policy)
    }

    /// 读取策略。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn policy_get(&self, tenant: TenantId, id: Id) -> DomainResult<Option<Policy>> {
        Ok(self.lock()?.policies.get(&(tenant, id)).cloned())
    }

    /// 列出策略（按优先级升序）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn policy_list(&self, tenant: TenantId) -> DomainResult<Vec<Policy>> {
        let mut items: Vec<Policy> =
            self.lock()?.policies.iter().filter(|((t, _), _)| *t == tenant).map(|(_, p)| p.clone()).collect();
        items.sort_by_key(|p| p.priority);
        Ok(items)
    }

    /// 删除策略。
    ///
    /// # Errors
    /// 不存在或锁中毒。
    pub fn policy_delete(&self, tenant: TenantId, id: Id) -> DomainResult<()> {
        let removed = self.lock()?.policies.remove(&(tenant, id));
        removed.map(|_| ()).ok_or(DomainError::NotFound { entity: "policy", id: id.to_string() })
    }
}
