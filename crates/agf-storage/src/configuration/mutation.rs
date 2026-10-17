//! One engine keeps collection limits, record serialization and optional auditing consistent.
use super::*;

pub(super) struct MutationOptions {
    pub limit: Option<i64>,
    pub audit: Option<AuditLog>,
}

impl ConfigStore {
    /// Commit a bounded revision and its audit in one SQL transaction.
    /// Offline callers receive no sealed audit and append it separately, as with `mutate_audited`.
    pub async fn mutate_bounded_audited<T, F>(
        &self,
        tenant: TenantId,
        kind: &str,
        id: Id,
        limit: Option<i64>,
        audit: AuditLog,
        apply: F,
    ) -> DomainResult<(T, Option<AuditLog>)>
    where
        T: Serialize + DeserializeOwned + Default,
        F: FnOnce(&mut T) -> DomainResult<()> + Send,
    {
        let options = AuditedMutation { limit, audit };
        self.mutate_bounded_audited_with(tenant, kind, id, options, apply, |_| Ok(None)).await
    }

    /// In offline mode, append through a synchronous callback before publishing the candidate.
    /// The callback runs under the configuration lock: it must not await or reenter this store.
    /// SQL ignores it and appends in its own transaction. A returned audit is already appended
    /// exactly once; callers may refresh a SQL projection, but must not append that audit again.
    /// Offline memory remains ephemeral and cannot provide crash or cross-process durability.
    pub async fn mutate_bounded_audited_with<T, F, A>(
        &self,
        tenant: TenantId,
        kind: &str,
        id: Id,
        options: AuditedMutation,
        apply: F,
        offline_audit: A,
    ) -> DomainResult<(T, Option<AuditLog>)>
    where
        T: Serialize + DeserializeOwned + Default,
        F: FnOnce(&mut T) -> DomainResult<()> + Send,
        A: FnOnce(AuditLog) -> DomainResult<Option<AuditLog>> + Send,
    {
        let options = MutationOptions { limit: options.limit, audit: Some(options.audit) };
        self.mutate_inner(tenant, kind, id, options, apply, offline_audit).await
    }

    pub(super) async fn mutate_inner<T, F, A>(
        &self,
        tenant: TenantId,
        kind: &str,
        id: Id,
        options: MutationOptions,
        apply: F,
        offline_audit: A,
    ) -> DomainResult<(T, Option<AuditLog>)>
    where
        T: Serialize + DeserializeOwned + Default,
        F: FnOnce(&mut T) -> DomainResult<()> + Send,
        A: FnOnce(AuditLog) -> DomainResult<Option<AuditLog>> + Send,
    {
        let MutationOptions { limit, audit } = options;
        if let Some(audit) = &audit {
            if audit.tenant_id != tenant {
                return Err(DomainError::TenantViolation {
                    tenant: audit.tenant_id.to_string(),
                    resource: kind.into(),
                });
            }
        }
        if let Some(db) = &self.database {
            let mut tx = db.db().begin_tenant(tenant).await?;
            // Every bounded writer locks the collection before its record; workers only need the record.
            if limit.is_some() {
                sql_lock(&mut tx, &format!("{tenant}:{kind}:collection")).await?;
            }
            sql_lock(&mut tx, &format!("{tenant}:{kind}:{id}")).await?;
            let previous: Option<Value> = sqlx::query_scalar(
                "SELECT payload FROM console_configurations
                 WHERE tenant_id=$1 AND kind=$2 AND id=$3 AND deleted_at IS NULL",
            )
            .bind(tenant.as_uuid())
            .bind(kind)
            .bind(id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage_error)?;
            if previous.is_none() {
                if let Some(limit) = limit {
                    let count: i64 = sqlx::query_scalar(
                        "SELECT count(*) FROM console_configurations
                         WHERE tenant_id=$1 AND kind=$2 AND deleted_at IS NULL",
                    )
                    .bind(tenant.as_uuid())
                    .bind(kind)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(storage_error)?;
                    check_capacity(kind, count, limit)?;
                }
            }
            let mut value: T = previous.map(serde_json::from_value).transpose()?.unwrap_or_default();
            apply(&mut value)?;
            let payload = serde_json::to_value(&value)?;
            sqlx::query(
                "INSERT INTO console_configurations (tenant_id,kind,id,payload) VALUES ($1,$2,$3,$4)
                 ON CONFLICT (tenant_id,kind,id) DO UPDATE
                 SET payload=excluded.payload,updated_at=now(),deleted_at=NULL",
            )
            .bind(tenant.as_uuid())
            .bind(kind)
            .bind(id.as_uuid())
            .bind(payload)
            .execute(&mut *tx)
            .await
            .map_err(storage_error)?;
            let sealed = match audit {
                Some(entry) => Some(crate::AuditRepo::append_log(&mut tx, entry).await?),
                None => None,
            };
            tx.commit().await?;
            return Ok((value, sealed));
        }
        let mut records = self.memory.lock().map_err(lock_error)?;
        let key = (tenant, kind.into(), id);
        if !records.contains_key(&key) {
            if let Some(limit) = limit {
                let count = records.keys().filter(|(t, k, _)| *t == tenant && k == kind).count();
                check_capacity(kind, i64::try_from(count).unwrap_or(i64::MAX), limit)?;
            }
        }
        let mut value: T = records.get(&key).cloned().map(serde_json::from_value).transpose()?.unwrap_or_default();
        apply(&mut value)?;
        // No fallible serialization remains after an offline success audit is appended.
        let payload = serde_json::to_value(&value)?;
        let sealed = audit.map(offline_audit).transpose()?.flatten();
        records.insert(key, payload);
        Ok((value, sealed))
    }
}

fn check_capacity(kind: &str, count: i64, limit: i64) -> DomainResult<()> {
    if count >= limit {
        return Err(DomainError::Validation(format!("{kind}: 每租户最多 {limit} 个配置")));
    }
    Ok(())
}

async fn sql_lock(tx: &mut crate::TenantTransaction<'_>, key: &str) -> DomainResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(key)
        .execute(&mut **tx)
        .await
        .map_err(storage_error)?;
    Ok(())
}
