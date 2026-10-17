use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(super) fn record_id(tenant: TenantId) -> Id {
    deterministic_id("agf.semantic-cache.profile.v1", &tenant.to_string())
}
pub(super) fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(fields) => {
            let sorted: std::collections::BTreeMap<_, _> =
                fields.iter().map(|(key, value)| (key.clone(), canonical(value))).collect();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}
pub(super) fn digest(value: &Value) -> DomainResult<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&canonical(value))?)))
}
pub(super) fn bounded<T: serde::Serialize>(value: &T, max: usize) -> DomainResult<()> {
    if serde_json::to_vec(value)?.len() > max {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn invalid() -> DomainError {
    DomainError::Validation("Invalid or oversized semantic profile".into())
}
pub(super) fn stale() -> DomainError {
    DomainError::PreconditionFailed("Semantic preparation authority, source or original deadline changed".into())
}
pub(super) fn corrupt() -> DomainError {
    DomainError::Internal("Stored semantic profile identity or shape is invalid".into())
}
