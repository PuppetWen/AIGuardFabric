//! A discovery batch, lifecycle change or baseline is one tenant-scoped SQL transaction.
use super::*;
mod agentteams_failure;
mod agentteams_roles;
mod gateway_idempotency;
mod gateway_sources;
mod redteam_multi;
mod runtime_authority;
pub(crate) use runtime_authority::authorize_transaction;
mod semantic_admission;
use agf_storage::{AssetRepo, AuditRepo, TenantTransaction};
use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};

pub(crate) struct AssetTransaction<'a> {
    tenant: TenantId,
    tx: AsyncMutex<TenantTransaction<'a>>,
    remembered: AsyncMutex<BTreeMap<Id, Asset>>,
    remembered_audit: AsyncMutex<Vec<AuditLog>>,
}

/// Shared by discovery, manual governance and cloud inventory; never acquire these in reverse order.
pub(crate) async fn lock_tenant(tx: &mut TenantTransaction<'_>) -> DomainResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("agf.asset-governance:{}", tx.tenant()))
        .execute(&mut **tx)
        .await
        .map_err(|e| agf_storage::map_sqlx_err("asset_governance_lock", &e))?;
    Ok(())
}

impl<'a> AssetTransaction<'a> {
    /// Detect retired discovery identities without reviving them. The governance lock
    /// acquired by `begin` serializes this check with every ordinary lifecycle writer.
    pub(crate) async fn retired_fingerprints(
        &self,
        fingerprints: &[String],
    ) -> DomainResult<std::collections::BTreeSet<String>> {
        if fingerprints.len() > 2000 {
            return Err(DomainError::PreconditionFailed(
                "Retired-asset check exceeds 2000 discovery identities".into(),
            ));
        }
        let mut fingerprints = fingerprints.to_vec();
        fingerprints.sort();
        fingerprints.dedup();
        let mut tx = self.transaction(self.tenant).await?;
        let retired: Vec<String> = sqlx::query_scalar(
            "SELECT fingerprint FROM assets WHERE tenant_id=$1 AND fingerprint=ANY($2) AND deleted_at IS NOT NULL ORDER BY fingerprint FOR SHARE",
        )
        .bind(self.tenant.as_uuid()).bind(fingerprints).fetch_all(&mut **tx).await
        .map_err(|error| agf_storage::map_sqlx_err("retired_asset_fingerprints", &error))?;
        Ok(retired.into_iter().collect())
    }

    pub(crate) async fn tenant_enabled(&self) -> DomainResult<()> {
        let mut tx = self.transaction(self.tenant).await?;
        let enabled: bool = sqlx::query_scalar("SELECT agf_agentteams_lock_tenant()")
            .fetch_one(&mut **tx)
            .await
            .map_err(|e| agf_storage::map_sqlx_err("agentteams_tenant_guard", &e))?;
        if !enabled {
            return Err(DomainError::Forbidden("租户已停用".into()));
        }
        Ok(())
    }

    pub(crate) async fn configuration_lock(&self, kind: &str, id: Id) -> DomainResult<()> {
        let mut tx = self.transaction(self.tenant).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("{}:{kind}:{id}", self.tenant))
            .execute(&mut **tx)
            .await
            .map_err(|e| agf_storage::map_sqlx_err("agentteams_configuration_lock", &e))?;
        Ok(())
    }

    pub(crate) async fn begin(db: &'a agf_storage::Store, tenant: TenantId) -> DomainResult<Self> {
        let mut tx = db.db().begin_tenant(tenant).await?;
        lock_tenant(&mut tx).await?;
        Ok(Self {
            tenant,
            tx: AsyncMutex::new(tx),
            remembered: AsyncMutex::new(BTreeMap::new()),
            remembered_audit: AsyncMutex::new(Vec::new()),
        })
    }

    async fn transaction(&self, tenant: TenantId) -> DomainResult<AsyncMutexGuard<'_, TenantTransaction<'a>>> {
        if tenant != self.tenant {
            return Err(DomainError::TenantViolation {
                tenant: self.tenant.to_string(),
                resource: format!("assets:{tenant}"),
            });
        }
        Ok(self.tx.lock().await)
    }

    pub(crate) async fn commit(self, store: &ApiStore) -> DomainResult<()> {
        self.tx.into_inner().commit().await?;
        for asset in self.remembered.into_inner().into_values() {
            if let Err(error) = store.remember_asset(&asset) {
                tracing::warn!(%error, "已提交资产事务的内存投影刷新失败");
            }
        }
        for entry in self.remembered_audit.into_inner() {
            if let Err(error) = store.hydrate_audit(&entry) {
                tracing::warn!(%error, "已提交审计记录的内存投影刷新失败");
            }
        }
        Ok(())
    }

    pub(crate) async fn soft_delete(&self, tenant: TenantId, asset: &Asset) -> DomainResult<()> {
        AssetRepo::soft_delete(&mut *self.transaction(tenant).await?, asset.id).await?;
        let mut removed = asset.clone();
        removed.deleted_at = Some(Timestamp::now());
        self.remembered.lock().await.insert(asset.id, removed);
        Ok(())
    }

    pub(crate) async fn configuration<T: serde::de::DeserializeOwned>(
        &self,
        kind: &str,
        id: Id,
    ) -> DomainResult<Option<T>> {
        let mut tx = self.transaction(self.tenant).await?;
        let value: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT payload FROM console_configurations WHERE kind=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE",
        )
        .bind(kind)
        .bind(id.as_uuid())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| agf_storage::map_sqlx_err("asset_configuration_read", &e))?;
        value.map(serde_json::from_value).transpose().map_err(Into::into)
    }

    pub(crate) async fn configure(&self, kind: &str, id: Id, value: Option<serde_json::Value>) -> DomainResult<()> {
        let mut tx = self.transaction(self.tenant).await?;
        if let Some(value) = value {
            sqlx::query("INSERT INTO console_configurations(tenant_id,kind,id,payload) VALUES ($1,$2,$3,$4)
                ON CONFLICT (tenant_id,kind,id) DO UPDATE SET payload=EXCLUDED.payload,updated_at=now(),deleted_at=NULL")
                .bind(self.tenant.as_uuid()).bind(kind).bind(id.as_uuid()).bind(value).execute(&mut **tx).await
                .map_err(|e|agf_storage::map_sqlx_err("asset_configuration_save",&e))?;
        } else {
            sqlx::query("UPDATE console_configurations SET deleted_at=now(),updated_at=now() WHERE kind=$1 AND id=$2 AND deleted_at IS NULL")
                .bind(kind).bind(id.as_uuid()).execute(&mut **tx).await.map_err(|e|agf_storage::map_sqlx_err("asset_configuration_delete",&e))?;
        }
        Ok(())
    }

    /// Lock an entire configuration kind in deterministic order before acquiring its audit-chain lock.
    pub(crate) async fn configurations<T: serde::de::DeserializeOwned>(
        &self,
        kind: &str,
    ) -> DomainResult<Vec<(Id, T)>> {
        let mut tx = self.transaction(self.tenant).await?;
        let rows: Vec<(uuid::Uuid, serde_json::Value)> = sqlx::query_as(
            "SELECT id,payload FROM console_configurations WHERE kind=$1 AND deleted_at IS NULL ORDER BY id FOR UPDATE",
        )
        .bind(kind)
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| agf_storage::map_sqlx_err("asset_configuration_list", &e))?;
        rows.into_iter().map(|(id, payload)| Ok((Id::from_uuid(id), serde_json::from_value(payload)?))).collect()
    }

    pub(crate) async fn audit(&self, entry: AuditLog) -> DomainResult<()> {
        let mut tx = self.transaction(entry.tenant_id).await?;
        let sealed = AuditRepo::append_log(&mut tx, entry).await?;
        self.remembered_audit.lock().await.push(sealed);
        Ok(())
    }

    /// 同事务锁定精确审计条目，供持锁的事实证明核对；不扫描租户整链。
    pub(crate) async fn runtime_audit_entry(&self, id: Id) -> DomainResult<Option<AuditLog>> {
        let mut tx = self.transaction(self.tenant).await?;
        let sequence: Option<i64> = sqlx::query_scalar(
            "SELECT sequence FROM audit_logs WHERE tenant_id=$1 AND id=$2
            AND octet_length(row_to_json(audit_logs)::text)<=16384 FOR SHARE",
        )
        .bind(self.tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| agf_storage::map_sqlx_err("runtime_audit_entry", &error))?;
        let Some(sequence) = sequence else { return Ok(None) };
        Ok(AuditRepo::load_chain(&mut tx, sequence, 1).await?.into_iter().find(|entry| entry.id == id))
    }

    /// 读取固定编号的 MCP 事实；拒绝把异常超大配置传回应用进程，JSON null 视为不匹配。
    pub(crate) async fn runtime_interception(&self, id: Id) -> DomainResult<Option<serde_json::Value>> {
        let mut tx = self.transaction(self.tenant).await?;
        sqlx::query_scalar("SELECT CASE WHEN octet_length(payload::text)<=131072 THEN payload ELSE 'null'::jsonb END
            FROM console_configurations WHERE tenant_id=$1 AND kind='runtime-interception' AND id=$2 AND deleted_at IS NULL FOR UPDATE")
            .bind(self.tenant.as_uuid()).bind(id.as_uuid()).fetch_optional(&mut **tx).await
            .map_err(|error| agf_storage::map_sqlx_err("runtime_fact_bounded_read", &error))
    }
}

#[async_trait]
impl AssetBackend for AssetTransaction<'_> {
    async fn find_by_fingerprint(&self, tenant: TenantId, fingerprint: &str) -> DomainResult<Option<Asset>> {
        AssetRepo::get_by_fingerprint(&mut *self.transaction(tenant).await?, fingerprint).await
    }

    async fn find(&self, tenant: TenantId, id: Id) -> DomainResult<Option<Asset>> {
        AssetRepo::get(&mut *self.transaction(tenant).await?, id).await
    }

    async fn list_all(&self, tenant: TenantId) -> DomainResult<Vec<Asset>> {
        let mut tx = self.transaction(tenant).await?;
        let rows = AssetRepo::list_all(&mut tx, 100_001).await?;
        if rows.len() > 100_000 {
            return Err(DomainError::PreconditionFailed(
                "This operation exceeds 100000 assets; use a scoped inventory job".into(),
            ));
        }
        Ok(rows)
    }

    async fn upsert(&self, tenant: TenantId, asset: &Asset) -> DomainResult<Id> {
        if asset.tenant_id != tenant {
            return Err(DomainError::TenantViolation { tenant: tenant.to_string(), resource: asset.id.to_string() });
        }
        let mut tx = self.transaction(tenant).await?;
        let id = AssetRepo::upsert(&mut tx, asset).await?;
        if id != asset.id {
            return Err(DomainError::Conflict(
                "Asset fingerprint belongs to a different canonical ID; reload it".into(),
            ));
        }
        // Discovery upsert intentionally preserves lifecycle. A governance transaction persists the reviewed state too.
        AssetRepo::set_lifecycle(&mut tx, id, asset.lifecycle).await?;
        // SQL triggers own updated_at; cache the committed representation used by the next revision check.
        let saved = AssetRepo::get(&mut tx, id)
            .await?
            .ok_or_else(|| DomainError::NotFound { entity: "asset", id: id.to_string() })?;
        self.remembered.lock().await.insert(id, saved);
        Ok(id)
    }

    async fn record_change(&self, tenant: TenantId, change: &AssetChange) -> DomainResult<()> {
        if change.tenant_id != tenant {
            return Err(DomainError::TenantViolation {
                tenant: tenant.to_string(),
                resource: change.asset_id.to_string(),
            });
        }
        AssetRepo::insert_change(&mut *self.transaction(tenant).await?, change).await
    }

    async fn snapshot(&self, tenant: TenantId, date: &str, asset: &Asset) -> DomainResult<()> {
        if asset.tenant_id != tenant {
            return Err(DomainError::TenantViolation { tenant: tenant.to_string(), resource: asset.id.to_string() });
        }
        AssetRepo::snapshot(&mut *self.transaction(tenant).await?, date, asset).await
    }

    async fn snapshot_hashes(&self, tenant: TenantId, date: &str) -> DomainResult<BTreeMap<Id, String>> {
        let mut tx = self.transaction(tenant).await?;
        let rows: Vec<serde_json::Value> =
            sqlx::query_scalar("SELECT payload FROM asset_snapshots WHERE snapshot_date=$1::date")
                .bind(date)
                .fetch_all(&mut **tx)
                .await
                .map_err(|e| agf_storage::map_sqlx_err("asset_snapshot_content", &e))?;
        // Historic SQL snapshots hashed the entire row (including timestamps); drift uses only governance content.
        rows.into_iter()
            .map(|value| {
                let asset: Asset = serde_json::from_value(value)?;
                Ok((
                    asset.id,
                    agf_asset::asset_content_hash(
                        asset.kind,
                        asset.endpoint.as_deref(),
                        asset.protocol,
                        asset.version.as_deref(),
                        asset.vendor.as_deref(),
                        asset.data_class,
                        asset.lifecycle,
                        &asset.dependencies,
                        asset.discovery_source,
                    ),
                ))
            })
            .collect()
    }
}
