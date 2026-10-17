//! Conditional publication and its audit share one lock and transaction.
use super::*;
#[cfg(test)]
mod tests;

/// An existing configuration that must be checked before publishing another record.
#[derive(Debug)]
pub struct ConfigurationGuard<'a> {
    /// Configuration kind, using the same advisory key as its ordinary writer.
    pub kind: &'a str,
    /// Tenant-scoped configuration identity.
    pub id: Id,
}

/// Publication target and optional prerequisite, locked in prerequisite-first order.
#[derive(Debug)]
pub struct ConditionalMutation<'a> {
    /// Target kind.
    pub kind: &'a str,
    /// Target identity.
    pub id: Id,
    /// A prerequisite record, read under its writer's lock.
    pub guard: Option<ConfigurationGuard<'a>>,
}

/// A no-op does not write the record or append another audit.
#[derive(Debug)]
pub enum MutationDecision {
    /// Return the existing record unchanged.
    Unchanged,
    /// Publish the candidate and optionally seal its audit in the same transaction.
    Write(Option<Box<AuditLog>>),
}

impl ConfigStore {
    /// Check an optional prerequisite and conditionally publish a record with its audit.
    /// SQL locks prerequisite, target, then audit chain. Offline mode uses one configuration
    /// mutex and a synchronous audit callback before inserting the serialized candidate.
    /// The callback must not await or reenter this store; it is not used in SQL mode.
    pub async fn mutate_conditional_audited<T, F, A>(
        &self,
        tenant: TenantId,
        mutation: ConditionalMutation<'_>,
        apply: F,
        offline_audit: A,
    ) -> DomainResult<(T, Option<AuditLog>)>
    where
        T: Serialize + DeserializeOwned + Default,
        F: FnOnce(Option<Value>, &mut T) -> DomainResult<MutationDecision> + Send,
        A: FnOnce(AuditLog) -> DomainResult<Option<AuditLog>> + Send,
    {
        let ConditionalMutation { kind, id, guard } = mutation;
        if let Some(db) = &self.database {
            let mut tx = db.db().begin_tenant(tenant).await?;
            let prerequisite = if let Some(guard) = guard {
                lock(&mut tx, tenant, guard.kind, guard.id).await?;
                read(&mut tx, tenant, guard.kind, guard.id).await?
            } else {
                None
            };
            lock(&mut tx, tenant, kind, id).await?;
            let previous = read(&mut tx, tenant, kind, id).await?;
            let mut value: T = previous.clone().map(serde_json::from_value).transpose()?.unwrap_or_default();
            let MutationDecision::Write(audit) = apply(prerequisite, &mut value)? else {
                tx.commit().await?;
                return Ok((previous.map(serde_json::from_value).transpose()?.unwrap_or_default(), None));
            };
            check_audit(tenant, kind, audit.as_deref())?;
            let payload = serde_json::to_value(&value)?;
            sqlx::query(
                "INSERT INTO console_configurations(tenant_id,kind,id,payload) VALUES($1,$2,$3,$4)
                 ON CONFLICT(tenant_id,kind,id) DO UPDATE
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
                Some(audit) => Some(crate::AuditRepo::append_log(&mut tx, *audit).await?),
                None => None,
            };
            tx.commit().await?;
            return Ok((value, sealed));
        }
        let mut records = self.memory.lock().map_err(lock_error)?;
        let prerequisite = guard.and_then(|guard| records.get(&(tenant, guard.kind.into(), guard.id)).cloned());
        let key = (tenant, kind.into(), id);
        let previous = records.get(&key).cloned();
        let mut value: T = previous.clone().map(serde_json::from_value).transpose()?.unwrap_or_default();
        let MutationDecision::Write(audit) = apply(prerequisite, &mut value)? else {
            return Ok((previous.map(serde_json::from_value).transpose()?.unwrap_or_default(), None));
        };
        check_audit(tenant, kind, audit.as_deref())?;
        let payload = serde_json::to_value(&value)?;
        let sealed = audit.map(|audit| offline_audit(*audit)).transpose()?.flatten();
        records.insert(key, payload);
        Ok((value, sealed))
    }
}

fn check_audit(tenant: TenantId, kind: &str, audit: Option<&AuditLog>) -> DomainResult<()> {
    if let Some(audit) = audit {
        if audit.tenant_id != tenant {
            return Err(DomainError::TenantViolation { tenant: audit.tenant_id.to_string(), resource: kind.into() });
        }
    }
    Ok(())
}

async fn lock(tx: &mut crate::TenantTransaction<'_>, tenant: TenantId, kind: &str, id: Id) -> DomainResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("{tenant}:{kind}:{id}"))
        .execute(&mut **tx)
        .await
        .map_err(storage_error)?;
    Ok(())
}

async fn read(
    tx: &mut crate::TenantTransaction<'_>,
    tenant: TenantId,
    kind: &str,
    id: Id,
) -> DomainResult<Option<Value>> {
    sqlx::query_scalar(
        "SELECT payload FROM console_configurations
         WHERE tenant_id=$1 AND kind=$2 AND id=$3 AND deleted_at IS NULL",
    )
    .bind(tenant.as_uuid())
    .bind(kind)
    .bind(id.as_uuid())
    .fetch_optional(&mut **tx)
    .await
    .map_err(storage_error)
}
