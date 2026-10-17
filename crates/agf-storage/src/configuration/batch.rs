//! A bounded main record and declared related records publish with one audit.
use super::*;
#[cfg(test)]
mod tests;

/// Bounded keys locked in prerequisite, main, sorted-related, then audit order.
#[derive(Debug)]
pub struct BatchMutation<'a> {
    /// Main configuration kind.
    pub kind: &'a str,
    /// Main identity in the supplied tenant.
    pub id: Id,
    /// Optional existing prerequisite, checked under its ordinary writer lock.
    pub guard: Option<ConfigurationGuard<'a>>,
    /// One kind for all declared related records.
    pub related_kind: &'a str,
    /// At most 100 unique identities. Undeclared writes are rejected.
    pub related_ids: &'a [Id],
    /// Positive main payload bound, at most 4 MiB.
    pub max_main_bytes: usize,
    /// Positive per-related payload bound, at most 8 KiB.
    pub max_related_bytes: usize,
}

/// A no-op ignores every candidate mutation and produces no audit.
#[derive(Debug)]
pub enum BatchDecision {
    /// Return the original main record without publishing candidates.
    Unchanged,
    /// Atomically replace the main record and declared related candidates.
    Write {
        /// Only keys declared in `BatchMutation::related_ids` may be written.
        related: BTreeMap<Id, Value>,
        /// Optional audit committed with all candidates.
        audit: Option<Box<AuditLog>>,
    },
}

impl ConfigStore {
    /// Publish bounded candidates and their audit together. SQL uses one tenant
    /// transaction. Offline uses one mutex and serializes every candidate before
    /// its synchronous callback; the callback must not await or reenter ConfigStore.
    /// The callback is a trusted atomic audit sink: it returns the correctly
    /// sealed entry on commit, and an error only if no audit was committed.
    /// All local validation runs before the callback. Its side effects cannot
    /// be rolled back by this store; successful callbacks are followed only by
    /// infallible inserts. No-op candidates neither call it nor publish mutations.
    pub async fn mutate_batch_audited<T, F, A>(
        &self,
        tenant: TenantId,
        mutation: BatchMutation<'_>,
        apply: F,
        offline_audit: A,
    ) -> DomainResult<(T, Option<AuditLog>)>
    where
        T: Serialize + DeserializeOwned + Default,
        F: FnOnce(Option<Value>, &mut T, &BTreeMap<Id, Option<Value>>) -> DomainResult<BatchDecision> + Send,
        A: FnOnce(AuditLog) -> DomainResult<AuditLog> + Send,
    {
        let ids = validate(&mutation)?;
        if let Some(db) = &self.database {
            let mut tx = db.db().begin_tenant(tenant).await?;
            let guard = if let Some(guard) = &mutation.guard {
                lock(&mut tx, tenant, guard.kind, guard.id).await?;
                read(&mut tx, tenant, guard.kind, guard.id).await?
            } else {
                None
            };
            lock(&mut tx, tenant, mutation.kind, mutation.id).await?;
            let original = read(&mut tx, tenant, mutation.kind, mutation.id).await?;
            let mut main = original.clone().map(serde_json::from_value).transpose()?.unwrap_or_default();
            let mut related = BTreeMap::new();
            for id in &ids {
                lock(&mut tx, tenant, mutation.related_kind, *id).await?;
                related.insert(*id, read(&mut tx, tenant, mutation.related_kind, *id).await?);
            }
            let BatchDecision::Write { related, audit } = apply(guard, &mut main, &related)? else {
                tx.commit().await?;
                return Ok((original.map(serde_json::from_value).transpose()?.unwrap_or_default(), None));
            };
            let payload = prepare(tenant, &mutation, &main, &related, audit.as_deref())?;
            write(&mut tx, tenant, mutation.kind, mutation.id, payload).await?;
            for (id, payload) in related {
                write(&mut tx, tenant, mutation.related_kind, id, payload).await?;
            }
            let audit = match audit {
                Some(audit) => Some(crate::AuditRepo::append_log(&mut tx, *audit).await?),
                None => None,
            };
            tx.commit().await?;
            return Ok((main, audit));
        }
        let mut records = self.memory.lock().map_err(lock_error)?;
        let key = (tenant, mutation.kind.into(), mutation.id);
        let original = records.get(&key).cloned();
        let mut main = original.clone().map(serde_json::from_value).transpose()?.unwrap_or_default();
        let guard =
            mutation.guard.as_ref().and_then(|guard| records.get(&(tenant, guard.kind.into(), guard.id)).cloned());
        let related =
            ids.iter().map(|id| (*id, records.get(&(tenant, mutation.related_kind.into(), *id)).cloned())).collect();
        let BatchDecision::Write { related, audit } = apply(guard, &mut main, &related)? else {
            return Ok((original.map(serde_json::from_value).transpose()?.unwrap_or_default(), None));
        };
        let payload = prepare(tenant, &mutation, &main, &related, audit.as_deref())?;
        let audit = if let Some(audit) = audit { Some(offline_audit(*audit)?) } else { None };
        // All fallible validation, serialization and audit work has finished.
        records.insert(key, payload);
        for (id, payload) in related {
            records.insert((tenant, mutation.related_kind.into(), id), payload);
        }
        Ok((main, audit))
    }
}

fn validate(mutation: &BatchMutation<'_>) -> DomainResult<Vec<Id>> {
    if mutation.related_ids.len() > 100
        || mutation.max_main_bytes == 0
        || mutation.max_main_bytes > 4 * 1024 * 1024
        || mutation.max_related_bytes == 0
        || mutation.max_related_bytes > 8192
    {
        return Err(DomainError::Validation("Configuration batch limits are invalid".into()));
    }
    let mut ids = mutation.related_ids.to_vec();
    ids.sort();
    ids.dedup();
    if ids.len() != mutation.related_ids.len()
        || ids.iter().any(|id| {
            mutation.related_kind == mutation.kind && *id == mutation.id
                || mutation.guard.as_ref().is_some_and(|guard| mutation.related_kind == guard.kind && *id == guard.id)
        })
        || mutation.guard.as_ref().is_some_and(|guard| guard.kind == mutation.kind && guard.id == mutation.id)
    {
        return Err(DomainError::Validation("Configuration batch keys overlap or repeat".into()));
    }
    Ok(ids)
}

fn prepare<T: Serialize>(
    tenant: TenantId,
    mutation: &BatchMutation<'_>,
    main: &T,
    related: &BTreeMap<Id, Value>,
    audit: Option<&AuditLog>,
) -> DomainResult<Value> {
    if audit.is_some_and(|audit| audit.tenant_id != tenant) {
        return Err(DomainError::TenantViolation { tenant: tenant.to_string(), resource: mutation.kind.into() });
    }
    let payload = serde_json::to_value(main)?;
    if serde_json::to_vec(&payload)?.len() > mutation.max_main_bytes {
        return Err(DomainError::PreconditionFailed("Configuration main candidate exceeds its byte bound".into()));
    }
    for (id, value) in related {
        if !mutation.related_ids.contains(id) || serde_json::to_vec(value)?.len() > mutation.max_related_bytes {
            return Err(DomainError::Validation(
                "Configuration related candidate is undeclared or exceeds its byte bound".into(),
            ));
        }
    }
    Ok(payload)
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
    sqlx::query_scalar("SELECT payload FROM console_configurations WHERE tenant_id=$1 AND kind=$2 AND id=$3 AND deleted_at IS NULL FOR UPDATE")
        .bind(tenant.as_uuid()).bind(kind).bind(id.as_uuid()).fetch_optional(&mut **tx).await.map_err(storage_error)
}
async fn write(
    tx: &mut crate::TenantTransaction<'_>,
    tenant: TenantId,
    kind: &str,
    id: Id,
    payload: Value,
) -> DomainResult<()> {
    sqlx::query(
        "INSERT INTO console_configurations(tenant_id,kind,id,payload) VALUES($1,$2,$3,$4)
        ON CONFLICT(tenant_id,kind,id) DO UPDATE SET payload=excluded.payload,updated_at=now(),deleted_at=NULL",
    )
    .bind(tenant.as_uuid())
    .bind(kind)
    .bind(id.as_uuid())
    .bind(payload)
    .execute(&mut **tx)
    .await
    .map_err(storage_error)?;
    Ok(())
}
