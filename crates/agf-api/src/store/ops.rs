//! 审计哈希链与租户配额。

use super::*;

impl ApiStore {
    // ---------------------------------------------------------------- 审计

    /// 离线精确读取一条审计；只复制命中项，不能用于数据库部署的持久性证明。
    pub(crate) fn runtime_audit_entry(&self, tenant: TenantId, id: Id) -> DomainResult<Option<AuditLog>> {
        let memory = self.lock()?;
        Ok(memory.audits.get(&tenant).and_then(|entries| entries.iter().find(|entry| entry.id == id)).cloned())
    }

    /// 追加审计记录（维护哈希链；链尾取同租户最后一条）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn audit_append(&self, mut entry: AuditLog) -> DomainResult<AuditLog> {
        let mut mem = self.lock()?;
        let chain = mem.audits.entry(entry.tenant_id).or_default();
        let (sequence, prev_hash) = match chain.last() {
            Some(last) => (
                last.sequence
                    .checked_add(1)
                    .ok_or_else(|| DomainError::Validation("Audit sequence overflow".into()))?,
                last.entry_hash.clone(),
            ),
            None => (1, GENESIS_HASH.to_string()),
        };
        entry.sequence = sequence;
        entry.prev_hash = prev_hash;
        entry.entry_hash = String::new();
        entry.seal();
        chain.push(entry.clone());
        Ok(entry)
    }

    /// 读取审计链。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn audit_chain(&self, tenant: TenantId, from_sequence: i64, limit: i64) -> DomainResult<Vec<AuditLog>> {
        let mem = self.lock()?;
        Ok(mem
            .audits
            .get(&tenant)
            .map(|chain| {
                chain
                    .iter()
                    .filter(|e| e.sequence >= from_sequence)
                    .take(usize::try_from(limit.max(0)).unwrap_or(usize::MAX))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }

    /// 审计链统计 `(条数, 链尾哈希)`。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn audit_stats(&self, tenant: TenantId) -> DomainResult<(i64, String)> {
        let mem = self.lock()?;
        Ok(match mem.audits.get(&tenant).and_then(|c| c.last()) {
            Some(last) => (last.sequence, last.entry_hash.clone()),
            None => (0, GENESIS_HASH.to_string()),
        })
    }

    // ---------------------------------------------------------------- 配额

    /// upsert 配额（同名同租户覆盖）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn quota_upsert(&self, tenant: TenantId, mut quota: Quota) -> DomainResult<Quota> {
        let mut mem = self.lock()?;
        if let Some(existing) = mem.quotas.values().find(|q| q.tenant_id == tenant && q.name == quota.name).cloned() {
            quota.id = existing.id;
            quota.created_at = existing.created_at;
        }
        quota.tenant_id = tenant;
        quota.updated_at = Timestamp::now();
        mem.quotas.insert((tenant, quota.id), quota.clone());
        Ok(quota)
    }

    /// 列出配额。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn quota_list(&self, tenant: TenantId) -> DomainResult<Vec<Quota>> {
        Ok(self.lock()?.quotas.iter().filter(|((t, _), _)| *t == tenant).map(|(_, q)| q.clone()).collect())
    }

    /// 读取配额用量。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn quota_usage(&self, tenant: TenantId) -> DomainResult<BTreeMap<Id, i64>> {
        Ok(self
            .lock()?
            .quota_usage
            .iter()
            .filter(|((t, _), _)| *t == tenant)
            .map(|((_, id), used)| (*id, *used))
            .collect())
    }

    /// 累加配额用量（供运行时计量与测试使用）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn quota_add_usage(&self, tenant: TenantId, quota_id: Id, delta: i64) -> DomainResult<i64> {
        let mut mem = self.lock()?;
        let slot = mem.quota_usage.entry((tenant, quota_id)).or_insert(0);
        *slot = slot.saturating_add(delta);
        Ok(*slot)
    }

    /// 确保租户存在默认配额（首次调用时写入租户级四个维度）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn quota_ensure_defaults(
        &self,
        tenant: TenantId,
        defaults: &agf_core::config::QuotaDefaults,
    ) -> DomainResult<()> {
        let pairs = [
            (QuotaDimension::Tokens, defaults.tenant_tokens_per_day, QuotaWindow::Day),
            (QuotaDimension::Requests, defaults.tenant_req_per_min, QuotaWindow::Minute),
            (QuotaDimension::Concurrency, 64, QuotaWindow::Total),
            (QuotaDimension::Cost, 1_000_000, QuotaWindow::Day),
        ];
        for (dimension, limit, window) in pairs {
            let exists = self.lock()?.quotas.iter().any(|((t, _), q)| *t == tenant && q.dimension == dimension);
            if !exists {
                let mut quota = Quota::tenant_default(tenant, dimension, limit);
                quota.window = window;
                self.quota_upsert(tenant, quota)?;
            }
        }
        Ok(())
    }
}
