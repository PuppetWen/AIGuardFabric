//! A synchronous offline commit reads only declared business keys and fixed authority records.
use super::*;
#[cfg(test)]
mod tests;

const DIRECTORY: &str = "tenant-directory";
const PASSWORD_POLICY: &str = "password-policy";
const MFA: &str = "mfa-enrollment";

/// Authority identity must come from an authenticated principal, never a payload.
///
/// Kinds and record IDs are fixed internally: password-policy uses its canonical tenant UUID;
/// mfa-enrollment uses this authenticated subject. No arbitrary cross-tenant key is accepted.
#[derive(Debug, Clone, Copy)]
pub struct OfflineSecurityRecords {
    /// Tenant that owns the authenticated identity, even when a superadmin manages another tenant.
    pub identity_tenant: TenantId,
    /// Authenticated subject identity, not a policy target supplied by the client.
    pub subject_id: Id,
}

/// One offline target and at most two tenant-local dependency records.
/// The global directory always uses defaultTenant and its canonical UUID, never a caller-selected key.
#[derive(Debug)]
pub struct OfflineGuardedMutation<'a> {
    /// Business target kind. Reserved authority kinds cannot be targets or business guards.
    pub kind: &'a str,
    /// Business target identity.
    pub id: Id,
    /// At most two unique, tenant-local keys, sorted before reading.
    pub guards: &'a [ConfigurationGuard<'a>],
    /// Optional authenticated user/key authority identity for fixed read-only records.
    pub security: Option<OfflineSecurityRecords>,
}

/// Read-only records captured under the same mutex as the candidate publication.
/// Raw authority values are deliberately omitted from Debug and never belong in audit payloads.
pub struct OfflineGuardedSnapshot {
    /// Exactly the declared business keys in this mutation's tenant.
    pub guards: BTreeMap<(String, Id), Option<Value>>,
    /// Fixed defaultTenant directory, or absent for the default-directory fallback.
    pub tenant_directory: Option<Value>,
    /// Fixed password-policy record of the authenticated identity tenant.
    pub password_policy: Option<Value>,
    /// Fixed mfa-enrollment record of the authenticated subject.
    pub mfa_enrollment: Option<Value>,
}
impl std::fmt::Debug for OfflineGuardedSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OfflineGuardedSnapshot")
            .field("guard_count", &self.guards.len())
            .field("directory_present", &self.tenant_directory.is_some())
            .finish_non_exhaustive()
    }
}

impl ConfigStore {
    /// Offline-only synchronous candidate and trusted audit publication. Database mode is rejected.
    /// The caller validates authority against this exact snapshot in the audit callback. Neither
    /// callback may await or reenter ConfigStore. The audit sink commits a correctly sealed entry
    /// or returns an error without committing an audit. Apply, identity checks and serialization
    /// all finish before the sink; after successful sealing only infallible insertion remains.
    /// These facts last for one process and do not provide database/crash durability.
    ///
    /// # Errors
    /// SQL mode, invalid/overlapping keys, serialization, candidate validation or an audit refusal.
    pub fn mutate_offline_guarded_audited<T, R, F, A>(
        &self,
        tenant: TenantId,
        mutation: OfflineGuardedMutation<'_>,
        apply: F,
        offline_audit: A,
    ) -> DomainResult<(T, R, AuditLog)>
    where
        T: Serialize + DeserializeOwned + Default,
        F: FnOnce(&OfflineGuardedSnapshot, &mut T) -> DomainResult<(R, AuditLog)>,
        A: FnOnce(AuditLog, &OfflineGuardedSnapshot) -> DomainResult<AuditLog>,
    {
        if self.database.is_some() {
            return Err(DomainError::PreconditionFailed(
                "Offline guarded publication cannot run with a database".into(),
            ));
        }
        let keys = validate(&mutation)?;
        let mut records = self.memory.lock().map_err(lock_error)?;
        let security = mutation.security;
        let snapshot = OfflineGuardedSnapshot {
            guards: keys
                .into_iter()
                .map(|(kind, id)| {
                    let value = records.get(&(tenant, kind.clone(), id)).cloned();
                    ((kind, id), value)
                })
                .collect(),
            tenant_directory: records
                .get(&(
                    TenantId::default_tenant(),
                    DIRECTORY.into(),
                    Id::from_uuid(TenantId::default_tenant().as_uuid()),
                ))
                .cloned(),
            password_policy: security.and_then(|security| {
                records
                    .get(&(
                        security.identity_tenant,
                        PASSWORD_POLICY.into(),
                        Id::from_uuid(security.identity_tenant.as_uuid()),
                    ))
                    .cloned()
            }),
            mfa_enrollment: security.and_then(|security| {
                records.get(&(security.identity_tenant, MFA.into(), security.subject_id)).cloned()
            }),
        };
        let key = (tenant, mutation.kind.into(), mutation.id);
        let mut candidate: T = records.get(&key).cloned().map(serde_json::from_value).transpose()?.unwrap_or_default();
        let (result, audit) = apply(&snapshot, &mut candidate)?;
        if audit.tenant_id != tenant {
            return Err(DomainError::TenantViolation { tenant: tenant.to_string(), resource: mutation.kind.into() });
        }
        let payload = serde_json::to_value(&candidate)?;
        let sealed = offline_audit(audit, &snapshot)?;
        records.insert(key, payload);
        Ok((candidate, result, sealed))
    }
}

fn validate(mutation: &OfflineGuardedMutation<'_>) -> DomainResult<Vec<(String, Id)>> {
    let reserved = |kind: &str| matches!(kind, DIRECTORY | PASSWORD_POLICY | MFA);
    if mutation.kind.is_empty()
        || mutation.id.is_nil()
        || reserved(mutation.kind)
        || mutation.guards.len() > 2
        || mutation.security.is_some_and(|security| {
            security.subject_id.is_nil() || Id::from_uuid(security.identity_tenant.as_uuid()).is_nil()
        })
    {
        return Err(DomainError::Validation("Offline guarded publication keys are invalid".into()));
    }
    let mut keys = mutation.guards.iter().map(|guard| (guard.kind.to_owned(), guard.id)).collect::<Vec<_>>();
    keys.sort();
    if keys.iter().any(|(kind, id)| {
        kind.is_empty() || id.is_nil() || reserved(kind) || (kind.as_str(), *id) == (mutation.kind, mutation.id)
    }) || keys.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(DomainError::Validation(
            "Offline business guards overlap, repeat or use reserved authority keys".into(),
        ));
    }
    Ok(keys)
}
