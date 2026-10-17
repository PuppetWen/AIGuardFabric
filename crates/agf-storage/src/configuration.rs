//! Transactional control-plane configuration store; offline mode stays explicitly in memory.
use agf_core::{
    audit::AuditLog,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

type Records = BTreeMap<(TenantId, String, Id), Value>;

mod batch;
mod bounded;
pub use bounded::BoundedConfigurationList;
mod conditional;
mod mutation;
mod offline_guarded;
mod offline_guarded_batch;
pub use batch::{BatchDecision, BatchMutation};
pub use conditional::{ConditionalMutation, ConfigurationGuard, MutationDecision};
pub use offline_guarded::{OfflineGuardedMutation, OfflineGuardedSnapshot, OfflineSecurityRecords};
pub use offline_guarded_batch::{GuardedBatchDecision, OfflineGuardedBatch};
#[cfg(test)]
mod tests;

/// Audit and optional collection limit for one configuration revision.
#[derive(Debug)]
pub struct AuditedMutation {
    /// Maximum active records of this kind in the tenant, checked only on creation.
    pub limit: Option<i64>,
    /// Success audit committed only when the candidate revision is accepted.
    pub audit: AuditLog,
}

/// Tenant-scoped SQL or explicit offline memory configuration storage.
#[derive(Debug)]
pub struct ConfigStore {
    database: Option<Arc<crate::Store>>,
    memory: Mutex<Records>,
}

impl ConfigStore {
    /// 判断配置权威是否使用同一个 SQL Store；事务内读取不得猜测或替换配置来源。
    pub fn uses_database(&self, database: &Arc<crate::Store>) -> bool {
        self.database.as_ref().is_some_and(|own| Arc::ptr_eq(own, database))
    }

    /// Remove only expired ephemeral records that carry a numeric Unix `expires_at`.
    pub async fn purge_expired(&self, tenant: TenantId, kind: &str, now: i64) -> DomainResult<()> {
        if let Some(db) = &self.database {
            let mut tx = db.db().begin_tenant(tenant).await?;
            sqlx::query(
                "DELETE FROM console_configurations WHERE tenant_id=$1 AND kind=$2
                AND jsonb_typeof(payload->'expires_at')='number' AND (payload->>'expires_at')::bigint <= $3",
            )
            .bind(tenant.as_uuid())
            .bind(kind)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(storage_error)?;
            tx.commit().await?;
        } else {
            self.memory.lock().map_err(lock_error)?.retain(|(t, k, _), v| {
                *t != tenant || k != kind || v["expires_at"].as_i64().is_none_or(|expiry| expiry > now)
            });
        }
        Ok(())
    }
    /// Build a store; None selects explicitly ephemeral offline memory.
    pub fn new(database: Option<Arc<crate::Store>>) -> Self {
        Self { database, memory: Mutex::new(BTreeMap::new()) }
    }

    /// Read active records belonging to this tenant and kind.
    pub async fn list<T: DeserializeOwned>(&self, tenant: TenantId, kind: &str) -> DomainResult<Vec<T>> {
        let values: Vec<Value> = if let Some(db) = &self.database {
            let mut tx = db.db().begin_tenant(tenant).await?;
            let values = sqlx::query_scalar(
                "SELECT payload FROM console_configurations WHERE tenant_id=$1 AND kind=$2
                 AND deleted_at IS NULL ORDER BY created_at, id",
            )
            .bind(tenant.as_uuid())
            .bind(kind)
            .fetch_all(&mut *tx)
            .await
            .map_err(storage_error)?;
            tx.commit().await?;
            values
        } else {
            self.memory
                .lock()
                .map_err(lock_error)?
                .iter()
                .filter(|((t, k, _), _)| *t == tenant && k == kind)
                .map(|(_, v)| v.clone())
                .collect()
        };
        values.into_iter().map(|v| serde_json::from_value(v).map_err(Into::into)).collect()
    }

    /// Read one active record in the tenant.
    pub async fn get<T: DeserializeOwned>(&self, tenant: TenantId, kind: &str, id: Id) -> DomainResult<Option<T>> {
        let value: Option<Value> = if let Some(db) = &self.database {
            let mut tx = db.db().begin_tenant(tenant).await?;
            let value = sqlx::query_scalar(
                "SELECT payload FROM console_configurations WHERE tenant_id=$1 AND kind=$2 AND id=$3 AND deleted_at IS NULL")
                .bind(tenant.as_uuid()).bind(kind).bind(id.as_uuid()).fetch_optional(&mut *tx).await.map_err(storage_error)?;
            tx.commit().await?;
            value
        } else {
            self.memory.lock().map_err(lock_error)?.get(&(tenant, kind.into(), id)).cloned()
        };
        value.map(|v| serde_json::from_value(v).map_err(Into::into)).transpose()
    }

    /// Persist a record, replacing the previous value atomically.
    pub async fn put<T: Serialize>(&self, tenant: TenantId, kind: &str, id: Id, value: &T) -> DomainResult<()> {
        let payload = serde_json::to_value(value)?;
        if let Some(db) = &self.database {
            let mut tx = db.db().begin_tenant(tenant).await?;
            sqlx::query(
                "INSERT INTO console_configurations (tenant_id, kind, id, payload) VALUES ($1,$2,$3,$4)
                 ON CONFLICT (tenant_id,kind,id) DO UPDATE SET payload=excluded.payload,
                 updated_at=now(), deleted_at=NULL",
            )
            .bind(tenant.as_uuid())
            .bind(kind)
            .bind(id.as_uuid())
            .bind(payload)
            .execute(&mut *tx)
            .await
            .map_err(storage_error)?;
            tx.commit().await?;
        } else {
            self.memory.lock().map_err(lock_error)?.insert((tenant, kind.into(), id), payload);
        }
        Ok(())
    }

    /// Create a record and its success audit together; retries must not audit an existing record again.
    /// Offline memory callers append the audit separately.
    pub async fn create_audited<T: Serialize>(
        &self,
        tenant: TenantId,
        kind: &str,
        id: Id,
        value: &T,
        audit: AuditLog,
    ) -> DomainResult<Option<AuditLog>> {
        if audit.tenant_id != tenant {
            return Err(DomainError::TenantViolation { tenant: audit.tenant_id.to_string(), resource: kind.into() });
        }
        let payload = serde_json::to_value(value)?;
        if let Some(db) = &self.database {
            let mut tx = db.db().begin_tenant(tenant).await?;
            let inserted = sqlx::query(
                "INSERT INTO console_configurations (tenant_id,kind,id,payload) VALUES ($1,$2,$3,$4)
                 ON CONFLICT (tenant_id,kind,id) DO NOTHING",
            )
            .bind(tenant.as_uuid())
            .bind(kind)
            .bind(id.as_uuid())
            .bind(payload)
            .execute(&mut *tx)
            .await
            .map_err(storage_error)?;
            if inserted.rows_affected() == 0 {
                return Err(DomainError::Conflict(format!("{kind}: 记录编号已存在")));
            }
            let sealed = crate::AuditRepo::append_log(&mut tx, audit).await?;
            tx.commit().await?;
            return Ok(Some(sealed));
        }
        let mut records = self.memory.lock().map_err(lock_error)?;
        let key = (tenant, kind.into(), id);
        if records.contains_key(&key) {
            return Err(DomainError::Conflict(format!("{kind}: 记录编号已存在")));
        }
        records.insert(key, payload);
        Ok(None)
    }

    /// Soft-delete one record in the tenant.
    pub async fn delete(&self, tenant: TenantId, kind: &str, id: Id) -> DomainResult<()> {
        if let Some(db) = &self.database {
            let mut tx = db.db().begin_tenant(tenant).await?;
            sqlx::query(
                "UPDATE console_configurations SET deleted_at=now(), updated_at=now()
                 WHERE tenant_id=$1 AND kind=$2 AND id=$3 AND deleted_at IS NULL",
            )
            .bind(tenant.as_uuid())
            .bind(kind)
            .bind(id.as_uuid())
            .execute(&mut *tx)
            .await
            .map_err(storage_error)?;
            tx.commit().await?;
        } else {
            self.memory.lock().map_err(lock_error)?.remove(&(tenant, kind.into(), id));
        }
        Ok(())
    }

    /// 对同一租户记录进行串行的读-改-写；用于配额预留和并发控制。
    pub async fn mutate<T, F>(&self, tenant: TenantId, kind: &str, id: Id, apply: F) -> DomainResult<T>
    where
        T: Serialize + DeserializeOwned + Default,
        F: FnOnce(&mut T) -> DomainResult<()> + Send,
    {
        self.mutate_bounded(tenant, kind, id, None, apply).await
    }

    /// Commit one configuration revision and its success audit in the same tenant transaction.
    /// Offline memory mode returns no sealed audit; its caller must append there separately.
    pub async fn mutate_audited<T, F>(
        &self,
        tenant: TenantId,
        kind: &str,
        id: Id,
        audit: AuditLog,
        apply: F,
    ) -> DomainResult<(T, Option<AuditLog>)>
    where
        T: Serialize + DeserializeOwned + Default,
        F: FnOnce(&mut T) -> DomainResult<()> + Send,
    {
        self.mutate_bounded_audited(tenant, kind, id, None, audit, apply).await
    }

    /// Enforce an optional collection size atomically across instances when creating a record.
    pub async fn mutate_bounded<T, F>(
        &self,
        tenant: TenantId,
        kind: &str,
        id: Id,
        limit: Option<i64>,
        apply: F,
    ) -> DomainResult<T>
    where
        T: Serialize + DeserializeOwned + Default,
        F: FnOnce(&mut T) -> DomainResult<()> + Send,
    {
        let options = mutation::MutationOptions { limit, audit: None };
        self.mutate_inner(tenant, kind, id, options, apply, |_| Ok(None)).await.map(|(value, _)| value)
    }
}

fn lock_error<T>(error: std::sync::PoisonError<T>) -> DomainError {
    DomainError::Internal(error.to_string())
}

fn storage_error(error: sqlx::Error) -> DomainError {
    tracing::error!(error = %error, "配置存储失败");
    DomainError::DependencyUnavailable {
        dependency: "postgres".into(),
        cause: "配置未能保存，请检查数据库连接与迁移状态".into(),
    }
}
