use super::{
    STATE,
    model::{Intent, Journal, Key},
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
    key(STATE, deterministic_id("agf.privatelink.provisioning.state.v1", &tenant.to_string()))
}
pub(super) fn mock_key(tenant: TenantId) -> Key {
    key(super::MOCK, deterministic_id("agf.privatelink.provisioning.mock.v1", &tenant.to_string()))
}
pub(super) fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(super) fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, v)| (k.clone(), canonical(v)))
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(canonical).collect()),
        v => v.clone(),
    }
}
pub(super) fn fingerprint<T: Serialize>(value: &T) -> DomainResult<String> {
    Ok(hash(&serde_json::to_vec(&canonical(&serde_json::to_value(value)?))?))
}
pub(super) fn bound<T: Serialize>(value: &T, max: usize) -> DomainResult<usize> {
    let n = serde_json::to_vec(value)?.len();
    if n > max {
        return Err(capacity());
    }
    Ok(n)
}
pub(super) fn validate_journal(row: &Journal, tenant: TenantId) -> DomainResult<()> {
    if row.tenant.is_some_and(|t| t != tenant)
        || (row.tenant.is_none()
            && (row.generation != 0
                || row.facts != 0
                || row.stored_bytes != 0
                || !row.items.is_empty()
                || !row.risks.is_empty()))
        || row.facts > super::MAX_FACTS
        || row.items.len() > super::MAX_ITEMS
        || row.items.iter().any(Id::is_nil)
        || row.items.iter().collect::<BTreeSet<_>>().len() != row.items.len()
        || row.stored_bytes > 2 * 1024 * 1024
        || row.risks.len() > super::MAX_FACTS as usize
        || row.risks.iter().any(|(k, id)| k.len() != 64 || !k.bytes().all(|b| b.is_ascii_hexdigit()) || id.is_nil())
    {
        return Err(corrupt());
    }
    bound(row, 1024 * 1024)?;
    Ok(())
}
pub(super) fn bump(row: &mut Journal, tenant: TenantId, facts: u64) -> DomainResult<()> {
    row.tenant = Some(tenant);
    row.generation = row.generation.checked_add(1).ok_or_else(capacity)?;
    row.facts = row.facts.checked_add(facts).ok_or_else(capacity)?;
    validate_journal(row, tenant)
}
pub(super) fn create_resource(
    tenant: TenantId,
    target: &agf_alicloud::privatelink::provisioning::CreateEndpoint,
) -> DomainResult<String> {
    fingerprint(&("create", tenant, &target.service_id, &target.vpc_id))
}
pub(super) fn resource(tenant: TenantId, intent: &Intent) -> DomainResult<String> {
    match intent {
        Intent::Create { target } => create_resource(tenant, target),
        Intent::Accept { target, .. } => fingerprint(&("accept", tenant, &target.service_id, &target.endpoint_id)),
    }
}
pub(super) fn risk(row: &Journal, tenant: TenantId, intent: &Intent) -> DomainResult<()> {
    if row.risks.contains_key(&resource(tenant, intent)?)
        || row.risks.contains_key(&create_resource(tenant, intent.planned())?)
    {
        return Err(DomainError::PreconditionFailed("An original PrivateLink resource write is unresolved; source labels and new UUIDs do not permit another send".into()));
    }
    Ok(())
}
pub(super) fn invalid() -> DomainError {
    DomainError::Validation("PrivateLink provisioning input is invalid or exceeds its typed bounds".into())
}
pub(super) fn corrupt() -> DomainError {
    DomainError::Crypto("PrivateLink provisioning authenticated record is invalid".into())
}
pub(super) fn capacity() -> DomainError {
    DomainError::PreconditionFailed(
        "PrivateLink provisioning capacity is exhausted; permanent request identities and risk are never evicted"
            .into(),
    )
}
pub(super) fn conflict() -> DomainError {
    DomainError::Conflict(
        "PrivateLink generation, preview, source or original request changed; retain the original UUID".into(),
    )
}
