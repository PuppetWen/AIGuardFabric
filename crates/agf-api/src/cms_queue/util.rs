use super::{
    STATE,
    model::{Journal, Key},
};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(super) fn key(kind: &str, id: Id) -> Key {
    (kind.into(), id)
}
pub(super) fn state_key(tenant: TenantId) -> Key {
    key(STATE, deterministic_id("agf.cms.queue.state.v1", &tenant.to_string()))
}
pub(super) fn derived(tenant: TenantId, request: Id, index: usize, domain: &str) -> Id {
    deterministic_id(domain, &format!("{tenant}:{request}:{index}"))
}
pub(super) fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(super) fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), canonical(v)))
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}
pub(super) fn fingerprint<T: Serialize>(value: &T) -> DomainResult<String> {
    Ok(hash(&serde_json::to_vec(&canonical(&serde_json::to_value(value)?))?))
}
pub(super) fn bound<T: Serialize>(value: &T, max: usize) -> DomainResult<usize> {
    let bytes = serde_json::to_vec(value)?.len();
    if bytes > max {
        return Err(capacity());
    }
    Ok(bytes)
}
pub(super) fn validate_journal(row: &Journal, tenant: TenantId) -> DomainResult<()> {
    if row.tenant.is_some_and(|t| t != tenant)
        || (row.tenant.is_none()
            && (row.generation != 0 || row.facts != 0 || row.stored_bytes != 0 || !row.items.is_empty()))
        || row.facts > super::MAX_FACTS
        || row.items.len() > super::MAX_ITEMS
        || row.items.iter().any(Id::is_nil)
        || row.items.iter().collect::<BTreeSet<_>>().len() != row.items.len()
        || row.stored_bytes > 2 * 1024 * 1024
    {
        return Err(corrupt());
    }
    bound(row, 64 * 1024)?;
    Ok(())
}
pub(super) fn bump(row: &mut Journal, tenant: TenantId, facts: u64) -> DomainResult<()> {
    row.tenant = Some(tenant);
    row.generation = row.generation.checked_add(1).ok_or_else(capacity)?;
    row.facts = row.facts.checked_add(facts).ok_or_else(capacity)?;
    validate_journal(row, tenant)
}
pub(super) fn invalid() -> DomainError {
    DomainError::Validation("CMS queue input is invalid or exceeds its declared bounds".into())
}
pub(super) fn corrupt() -> DomainError {
    DomainError::Crypto("CMS queue authenticated record is invalid".into())
}
pub(super) fn capacity() -> DomainError {
    DomainError::PreconditionFailed("CMS queue capacity is exhausted; permanent identities are never evicted".into())
}
pub(super) fn conflict() -> DomainError {
    DomainError::Conflict("CMS queue generation, identity or original source changed; retain the original UUID".into())
}
