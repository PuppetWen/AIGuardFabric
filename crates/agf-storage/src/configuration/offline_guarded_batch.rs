//! One synchronous offline mutex publishes bounded declared records and a trusted audit.
use super::*;
use std::collections::BTreeSet;

#[cfg(test)]
mod tests;

const DIRECTORY: &str = "tenant-directory";
const PASSWORD_POLICY: &str = "password-policy";
const MFA: &str = "mfa-enrollment";
type Key = (String, Id);
type Candidates = BTreeMap<Key, Option<Value>>;

/// Bounded tenant-local targets; authority records are fixed internally and read-only.
#[derive(Debug)]
pub struct OfflineGuardedBatch<'a> {
    /// Main business kind, excluding reserved authority kinds.
    pub kind: &'a str,
    /// Non-nil main identity in the supplied business tenant.
    pub id: Id,
    /// At most 32 unique read-only business prerequisites.
    pub guards: &'a [ConfigurationGuard<'a>],
    /// Identity from the authenticated principal, never a client-selected record path.
    pub security: Option<OfflineSecurityRecords>,
    /// At most 100 unique possible write targets, disjoint from main and guards.
    pub related: &'a [ConfigurationGuard<'a>],
    /// Positive serialized main payload limit, at most 4 MiB.
    pub max_main_bytes: usize,
    /// Positive serialized related payload limit, at most 1 MiB per record.
    pub max_related_bytes: usize,
    /// Positive total serialized write limit, at most 8 MiB, including keys, deletes and audit.
    pub max_total_write_bytes: usize,
}

/// No-op decisions discard all candidate mutations without serializing or auditing them.
#[derive(Debug)]
pub enum GuardedBatchDecision {
    /// Return the original main record and leave every record unchanged.
    Unchanged,
    /// Publish the candidate main and a subset of declared related records with one audit.
    Write {
        /// Only declared keys may appear. None removes a record; absent keys are untouched.
        related: BTreeMap<(String, Id), Option<Value>>,
        /// Success audit with the same business tenant as all write targets.
        audit: Box<AuditLog>,
    },
}

impl ConfigStore {
    /// Offline-only candidate publication under one ConfigStore mutex. SQL mode is rejected.
    /// Apply reads current guards, fixed authority records and declared related originals.
    /// All serialization, byte bounds and tenant checks finish before the trusted audit sink.
    /// Neither callback may await, poll a future or reenter ConfigStore. The sink must append
    /// exactly once and return that sealed entry, changing only a positive chain sequence and
    /// the two 64-character hexadecimal chain hashes; all supplied body fields stay intact.
    /// The budget reserves their maximum sealed sizes before the callback. Errors must append
    /// nothing. Only infallible map updates follow the sink's successful return.
    /// This does not atomically lock a separate identity store or provide crash durability.
    ///
    /// # Errors
    /// Database mode, invalid keys or bounds, malformed originals, validation, serialization,
    /// an oversized candidate, a foreign-tenant audit, or refusal by the trusted audit sink.
    pub fn mutate_offline_guarded_batch_audited<T, F, A>(
        &self,
        tenant: TenantId,
        options: OfflineGuardedBatch<'_>,
        apply: F,
        offline_audit: A,
    ) -> DomainResult<(T, Option<AuditLog>)>
    where
        T: Serialize + DeserializeOwned + Default,
        F: FnOnce(
            &OfflineGuardedSnapshot,
            &mut T,
            &BTreeMap<(String, Id), Option<Value>>,
        ) -> DomainResult<GuardedBatchDecision>,
        A: FnOnce(AuditLog, &OfflineGuardedSnapshot) -> DomainResult<AuditLog>,
    {
        if self.database.is_some() {
            return Err(DomainError::PreconditionFailed("Offline guarded batch cannot run with a database".into()));
        }
        let (guards, declared) = validate(tenant, &options)?;
        let mut records = self.memory.lock().map_err(lock_error)?;
        let snapshot = snapshot(&records, tenant, guards, options.security);
        let originals = declared
            .iter()
            .map(|(kind, id)| ((kind.clone(), *id), records.get(&(tenant, kind.clone(), *id)).cloned()))
            .collect();
        let key = (tenant, options.kind.to_owned(), options.id);
        let original = records.get(&key).cloned();
        let mut main = original.clone().map(serde_json::from_value).transpose()?.unwrap_or_default();
        let GuardedBatchDecision::Write { related, audit } = apply(&snapshot, &mut main, &originals)? else {
            return Ok((original.map(serde_json::from_value).transpose()?.unwrap_or_default(), None));
        };
        let payload = prepare(tenant, &options, &declared, &main, &related, &audit)?;
        let writes = related.into_iter().map(|((kind, id), value)| ((tenant, kind, id), value)).collect::<Vec<_>>();
        let sealed = offline_audit(*audit, &snapshot)?;
        // No fallible work or independent authority reads after the audit commits.
        records.insert(key, payload);
        for (key, value) in writes {
            match value {
                Some(value) => {
                    records.insert(key, value);
                }
                None => {
                    records.remove(&key);
                }
            }
        }
        Ok((main, Some(sealed)))
    }
}

fn validate(tenant: TenantId, options: &OfflineGuardedBatch<'_>) -> DomainResult<(BTreeSet<Key>, BTreeSet<Key>)> {
    if tenant.as_uuid().is_nil()
        || invalid_key(options.kind, options.id)
        || options.guards.len() > 32
        || options.related.len() > 100
        || options
            .security
            .is_some_and(|security| security.identity_tenant.as_uuid().is_nil() || security.subject_id.is_nil())
        || !(1..=4 * 1024 * 1024).contains(&options.max_main_bytes)
        || !(1..=1024 * 1024).contains(&options.max_related_bytes)
        || !(1..=8 * 1024 * 1024).contains(&options.max_total_write_bytes)
    {
        return Err(DomainError::Validation("Offline guarded batch keys or byte bounds are invalid".into()));
    }
    let guards = keys(options.guards)?;
    let related = keys(options.related)?;
    let main = (options.kind.to_owned(), options.id);
    if guards.contains(&main) || related.contains(&main) || !guards.is_disjoint(&related) {
        return Err(DomainError::Validation("Offline guarded batch targets overlap".into()));
    }
    Ok((guards, related))
}

fn invalid_key(kind: &str, id: Id) -> bool {
    kind.is_empty() || id.is_nil() || matches!(kind, DIRECTORY | PASSWORD_POLICY | MFA)
}

fn keys(guards: &[ConfigurationGuard<'_>]) -> DomainResult<BTreeSet<Key>> {
    let mut result = BTreeSet::new();
    for guard in guards {
        if invalid_key(guard.kind, guard.id) || !result.insert((guard.kind.to_owned(), guard.id)) {
            return Err(DomainError::Validation("Offline guarded batch keys repeat or are invalid".into()));
        }
    }
    Ok(result)
}

fn snapshot(
    records: &Records,
    tenant: TenantId,
    guards: BTreeSet<Key>,
    security: Option<OfflineSecurityRecords>,
) -> OfflineGuardedSnapshot {
    let read = |owner, kind: &str, id| records.get(&(owner, kind.to_owned(), id)).cloned();
    let default = TenantId::default_tenant();
    OfflineGuardedSnapshot {
        guards: guards
            .into_iter()
            .map(|(kind, id)| {
                let value = read(tenant, &kind, id);
                ((kind, id), value)
            })
            .collect(),
        tenant_directory: read(default, DIRECTORY, Id::from_uuid(default.as_uuid())),
        password_policy: security.and_then(|identity| {
            read(identity.identity_tenant, PASSWORD_POLICY, Id::from_uuid(identity.identity_tenant.as_uuid()))
        }),
        mfa_enrollment: security.and_then(|identity| read(identity.identity_tenant, MFA, identity.subject_id)),
    }
}

#[derive(Serialize)]
struct SerializedWrite<'a> {
    tenant: TenantId,
    kind: &'a str,
    id: Id,
    delete: bool,
    // None is an explicit deletion marker, never silently excluded.
    payload: Option<&'a Value>,
}

fn prepare<T: Serialize>(
    tenant: TenantId,
    options: &OfflineGuardedBatch<'_>,
    declared: &BTreeSet<Key>,
    main: &T,
    related: &Candidates,
    audit: &AuditLog,
) -> DomainResult<Value> {
    if audit.tenant_id != tenant {
        return Err(DomainError::TenantViolation { tenant: tenant.to_string(), resource: options.kind.to_owned() });
    }
    if audit.id.is_nil() || related.keys().any(|key| !declared.contains(key)) {
        return Err(DomainError::Validation("Offline guarded batch audit or related targets are invalid".into()));
    }
    let payload = serde_json::to_value(main)?;
    ensure_size(serde_json::to_vec(&payload)?.len(), options.max_main_bytes)?;
    let mut writes =
        vec![SerializedWrite { tenant, kind: options.kind, id: options.id, delete: false, payload: Some(&payload) }];
    for ((kind, id), value) in related {
        if let Some(value) = value {
            ensure_size(serde_json::to_vec(value)?.len(), options.max_related_bytes)?;
        }
        writes.push(SerializedWrite { tenant, kind, id: *id, delete: value.is_none(), payload: value.as_ref() });
    }
    let mut sealed_budget = audit.clone();
    sealed_budget.sequence = i64::MAX;
    sealed_budget.prev_hash = "0".repeat(64);
    sealed_budget.entry_hash = "0".repeat(64);
    let total = serde_json::to_vec(&(writes, sealed_budget))?.len();
    ensure_size(total, options.max_total_write_bytes)?;
    Ok(payload)
}

fn ensure_size(bytes: usize, bound: usize) -> DomainResult<()> {
    if bytes > bound {
        return Err(DomainError::PreconditionFailed("Offline guarded batch exceeds its serialized byte bound".into()));
    }
    Ok(())
}
