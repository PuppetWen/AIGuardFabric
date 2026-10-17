//! API Key、模型路由策略与剧本执行记录。

use super::*;

impl ApiStore {
    /// 每次认证读取权威状态，避免其他副本仍接受已吊销凭据。
    pub async fn api_key_by_prefix_durable(&self, prefix: &str) -> DomainResult<Option<ApiKey>> {
        let Some(db) = self.database() else { return self.api_key_by_prefix(prefix) };
        let tenant: Option<uuid::Uuid> =
            sqlx::query_scalar("SELECT agf_api_key_tenant($1)").bind(prefix).fetch_one(db.db().pool()).await.map_err(
                |_| DomainError::DependencyUnavailable {
                    dependency: "postgres".into(),
                    cause: "API Key 状态读取失败".into(),
                },
            )?;
        let Some(tenant) = tenant else { return Ok(None) };
        let mut tx = db.db().begin_tenant(TenantId::from_uuid(tenant)).await?;
        let key = agf_storage::repository::ApiKeyRepo::by_prefix(&mut tx, prefix).await?;
        tx.commit().await?;
        Ok(key)
    }

    pub async fn api_key_list_durable(&self, tenant: TenantId) -> DomainResult<Vec<ApiKey>> {
        let Some(db) = self.database() else { return self.api_key_list(tenant) };
        let mut tx = db.db().begin_tenant(tenant).await?;
        let keys = agf_storage::repository::ApiKeyRepo::list_all(&mut tx, 10000).await?;
        tx.commit().await?;
        Ok(keys)
    }
    /// 凭据管理必须先提交数据库，再更新本进程缓存。
    pub async fn api_key_create_durable(&self, key: &ApiKey) -> DomainResult<()> {
        if let Some(db) = self.database() {
            let mut tx = db.db().begin_tenant(key.tenant_id).await?;
            agf_storage::repository::ApiKeyRepo::insert(&mut tx, key).await?;
            tx.commit().await?;
        }
        self.hydrate_api_key(key)
    }

    /// 吊销失败不伪装成功，也不在重启后恢复已吊销凭据。
    pub async fn api_key_revoke_durable(&self, tenant: TenantId, id: Id) -> DomainResult<()> {
        if let Some(db) = self.database() {
            let mut tx = db.db().begin_tenant(tenant).await?;
            let mut key = agf_storage::repository::ApiKeyRepo::by_id(&mut tx, id)
                .await?
                .ok_or_else(|| DomainError::NotFound { entity: "api-key", id: id.to_string() })?;
            agf_storage::repository::ApiKeyRepo::revoke(&mut tx, id).await?;
            tx.commit().await?;
            key.revoked = true;
            return self.hydrate_api_key(&key);
        }
        let mut key = self
            .api_key_list(tenant)?
            .into_iter()
            .find(|k| k.id == id)
            .ok_or_else(|| DomainError::NotFound { entity: "api-key", id: id.to_string() })?;
        key.revoked = true;
        self.hydrate_api_key(&key)
    }

    // ------------------------------------------------------------ API Key

    /// 写入 API Key（明文不落库，仅存指纹）。
    ///
    /// 内存层改完后塞一条写意图（`ApiKeyRepo::insert`），使已签发的服务凭据
    /// **在 agf-server 重启后仍然可校验**（见 [`crate::persistence`] 模块文档）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn api_key_insert(&self, key: ApiKey) -> DomainResult<()> {
        self.lock()?.api_keys.push(key.clone());
        self.journal(PgWrite::ApiKeyInsert { key: Box::new(key) });
        Ok(())
    }

    /// 列出 API Key（**不含**明文与指纹）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn api_key_list(&self, tenant: TenantId) -> DomainResult<Vec<ApiKey>> {
        Ok(self.lock()?.api_keys.iter().filter(|k| k.tenant_id == tenant).cloned().collect())
    }

    /// 按前缀查找候选 Key。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn api_key_by_prefix(&self, prefix: &str) -> DomainResult<Option<ApiKey>> {
        Ok(self.lock()?.api_keys.iter().find(|k| k.prefix == prefix && !k.revoked).cloned())
    }

    /// 吊销 API Key。
    ///
    /// # Errors
    /// 不存在或锁中毒。
    pub fn api_key_revoke(&self, tenant: TenantId, id: Id) -> DomainResult<()> {
        {
            let mut mem = self.lock()?;
            let Some(key) = mem.api_keys.iter_mut().find(|k| k.id == id && k.tenant_id == tenant) else {
                return Err(DomainError::NotFound { entity: "api-key", id: id.to_string() });
            };
            key.revoked = true;
        }
        self.journal(PgWrite::ApiKeyRevoke { tenant, id });
        Ok(())
    }

    // ---------------------------------------------------------- 模型路由策略

    /// 写入/更新模型路由策略（按 `(tenant, id)` 覆盖）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn route_policy_upsert(&self, policy: &ModelRoutePolicy) -> DomainResult<Id> {
        self.lock()?.route_policies.insert((policy.tenant_id, policy.id), policy.clone());
        Ok(policy.id)
    }

    /// 读取模型路由策略（租户隔离）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn route_policy_get(&self, tenant: TenantId, id: Id) -> DomainResult<Option<ModelRoutePolicy>> {
        Ok(self.lock()?.route_policies.get(&(tenant, id)).cloned())
    }

    /// 列出模型路由策略（租户隔离；按名称排序保证输出顺序确定）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn route_policy_list(&self, tenant: TenantId) -> DomainResult<Vec<ModelRoutePolicy>> {
        let mut items: Vec<ModelRoutePolicy> =
            self.lock()?.route_policies.iter().filter(|((t, _), _)| *t == tenant).map(|(_, p)| p.clone()).collect();
        items.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(items)
    }

    // ------------------------------------------------------------ 剧本执行

    /// 写入案件剧本执行记录（按 `(tenant, id)` 覆盖）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn soar_run_insert(&self, record: SoarRunRecord) -> DomainResult<Id> {
        self.lock()?.soar_runs.insert((record.tenant_id, record.id), record.clone());
        Ok(record.id)
    }

    /// 列出某案件的剧本执行记录（租户隔离；最新在前）。
    ///
    /// # Errors
    /// 锁中毒。
    pub fn soar_run_list(&self, tenant: TenantId, case_id: Id) -> DomainResult<Vec<SoarRunRecord>> {
        let mut items: Vec<SoarRunRecord> = self
            .lock()?
            .soar_runs
            .iter()
            .filter(|((t, _), r)| *t == tenant && r.case_id == case_id)
            .map(|(_, r)| r.clone())
            .collect();
        items.sort_by_key(|r| std::cmp::Reverse(r.started_at));
        Ok(items)
    }
}
