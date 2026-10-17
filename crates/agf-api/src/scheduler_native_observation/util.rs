use super::records::{BINDING, BODY, FACT, STATE, Values};
use crate::{
    model_gateway::{cipher, encrypt},
    state::AppState,
};
use agf_core::{
    audit::AuditLog,
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
};
use agf_storage::crypto::FieldCipher;
use secrecy::ExposeSecret;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub(super) fn main_id(tenant: TenantId) -> Id {
    crate::integration_store::id(tenant, super::NAME)
}
pub(super) fn runtime_kind(kind: &str) -> &str {
    match kind {
        "report" => "report-generate",
        "archive" => "cold-archive",
        other => other,
    }
}
pub(super) fn key_id(tenant: TenantId, request: Id, kind: &str) -> Id {
    deterministic_id("agf.scheduler.native.record", &format!("{tenant}:{kind}:{request}"))
}
pub(super) fn fact_key(tenant: TenantId, request: Id) -> (String, Id) {
    (FACT.into(), key_id(tenant, request, FACT))
}
pub(super) fn body_key(tenant: TenantId, request: Id) -> (String, Id) {
    (BODY.into(), key_id(tenant, request, BODY))
}
pub(super) fn state_key(tenant: TenantId) -> (String, Id) {
    (STATE.into(), main_id(tenant))
}
pub(super) fn binding_key(tenant: TenantId) -> (String, Id) {
    (BINDING.into(), main_id(tenant))
}
pub(super) fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub(super) fn canonical_hash(value: &Value) -> DomainResult<String> {
    Ok(hash(&serde_json::to_vec(&canonical(value))?))
}
fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            let mut result = Map::new();
            for key in keys {
                result.insert(key.clone(), canonical(&object[key]));
            }
            Value::Object(result)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
        _ => value.clone(),
    }
}
pub(super) fn text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.trim() == value && !value.chars().any(char::is_control)
}
pub(super) fn positive_id(value: &str) -> bool {
    value.len() <= 19 && value.parse::<i64>().is_ok_and(|number| number > 0 && number.to_string() == value)
}
pub(super) fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}
pub(super) fn bound<T: Serialize>(value: &T, max: usize) -> DomainResult<usize> {
    let bytes = serde_json::to_vec(value)?.len();
    if bytes > max {
        return Err(capacity());
    }
    Ok(bytes)
}
pub(super) fn read<T: DeserializeOwned>(values: &Values, key: &(String, Id)) -> DomainResult<Option<T>> {
    values.get(key).and_then(Option::as_ref).cloned().map(serde_json::from_value).transpose().map_err(Into::into)
}
pub(super) fn put<T: Serialize>(values: &mut Values, key: (String, Id), value: &T) -> DomainResult<()> {
    values.insert(key, Some(serde_json::to_value(value)?));
    Ok(())
}
pub(super) fn decrypt_json(
    state: &AppState,
    tenant: TenantId,
    id: Id,
    secret: &SecretMaterial,
    expected: &str,
) -> DomainResult<Value> {
    decode_secret(&cipher(state)?, tenant, id, secret, expected)
}
pub(super) fn decode_secret(
    cipher: &FieldCipher,
    tenant: TenantId,
    id: Id,
    secret: &SecretMaterial,
    expected: &str,
) -> DomainResult<Value> {
    if secret.aad.as_deref() != Some(FieldCipher::make_aad(&tenant, &id).as_str()) {
        return Err(corrupt());
    }
    let clear = cipher.decrypt(secret)?;
    let clear = clear.expose_secret();
    if clear.len() > super::MAX_BODY_BYTES || hash(clear.as_bytes()) != expected {
        return Err(corrupt());
    }
    serde_json::from_str(clear).map_err(|_| corrupt())
}
pub(super) fn encrypt_json(
    state: &AppState,
    tenant: TenantId,
    id: Id,
    value: &Value,
) -> DomainResult<(SecretMaterial, String)> {
    let clear = serde_json::to_string(value)?;
    if clear.len() > super::MAX_BODY_BYTES {
        return Err(capacity());
    }
    let hash = hash(clear.as_bytes());
    Ok((encrypt(state, tenant, id, clear)?, hash))
}
pub(super) fn batch_bound(tenant: TenantId, values: &Values, audit: &AuditLog) -> DomainResult<()> {
    let writes = values
        .iter()
        .map(|((kind, id), payload)| {
            serde_json::json!({
                "tenant":tenant,"kind":kind,"id":id,"delete":payload.is_none(),"payload":payload
            })
        })
        .collect::<Vec<_>>();
    let mut sealed = audit.clone();
    sealed.sequence = i64::MAX;
    sealed.prev_hash = "0".repeat(64);
    sealed.entry_hash = "0".repeat(64);
    bound(&(writes, sealed), 8 * 1024 * 1024)?;
    Ok(())
}
pub(super) fn corrupt() -> DomainError {
    DomainError::Crypto("Scheduler 持久记录的身份、密文或完整证据不一致".into())
}
pub(super) fn stale() -> DomainError {
    DomainError::Conflict("Scheduler 来源、观察或绑定版本已改变；请重新读取后明确提交".into())
}
pub(super) fn capacity() -> DomainError {
    DomainError::PreconditionFailed("Scheduler 观察达到容量限制；请显式归档已结束的记录".into())
}
pub(super) fn missing(id: Id) -> DomainError {
    DomainError::NotFound { entity: "Scheduler observation", id: id.to_string() }
}
