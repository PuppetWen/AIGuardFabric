//! HMAC identities never store a raw caller key or a public unkeyed input digest.
use super::{Binding, OPERATION};
use crate::{Principal, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
    rbac::SubjectKind,
};
use axum::http::HeaderMap;
use base64::Engine as _;
use sha2::{Digest, Sha256};

pub(super) fn header(headers: &HeaderMap) -> DomainResult<&str> {
    let mut keys = headers.get_all("idempotency-key").iter();
    let key = keys.next().and_then(|value| value.to_str().ok()).ok_or_else(invalid)?;
    if keys.next().is_some() || key.is_empty() || key.len() > 200 || !key.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(invalid());
    }
    Ok(key)
}

pub(super) fn namespace(state: &AppState, principal: &Principal, key: &str) -> DomainResult<(Id, String)> {
    let body = namespace_bytes(principal, key)?;
    let namespace = tag(state, b"namespace\0", &body)?;
    Ok((id(&namespace)?, namespace))
}
pub(super) fn namespace_bytes(principal: &Principal, key: &str) -> DomainResult<Vec<u8>> {
    let subject = principal.subject_id.filter(|id| !id.is_nil()).ok_or_else(invalid)?;
    if principal.tenant.as_uuid().is_nil()
        || principal.identity_tenant.as_uuid().is_nil()
        || !matches!(principal.subject_kind, SubjectKind::User | SubjectKind::ApiKey)
    {
        return Err(invalid());
    }
    serde_json::to_vec(&(principal.tenant, principal.identity_tenant, principal.subject_kind, subject, OPERATION, key))
        .map_err(Into::into)
}

pub(super) fn id(namespace: &str) -> DomainResult<Id> {
    if !digest(namespace) {
        return Err(corrupt());
    }
    Ok(agf_core::ids::deterministic_id("agf.gateway-admission-key.v1", namespace))
}

pub(super) fn input(state: &AppState, namespace: &str, fingerprint: &str) -> DomainResult<String> {
    if !digest(namespace) || !digest(fingerprint) {
        return Err(corrupt());
    }
    tag(state, b"input\0", &serde_json::to_vec(&(namespace, fingerprint))?)
}

pub(super) fn binding(state: &AppState, principal: &Principal, key: &str, fingerprint: &str) -> DomainResult<Binding> {
    let (id, namespace) = namespace(state, principal, key)?;
    Ok(Binding { id, input: input(state, &namespace, fingerprint)?, namespace })
}

fn tag(state: &AppState, purpose: &[u8], body: &[u8]) -> DomainResult<String> {
    let master = base64::engine::general_purpose::STANDARD
        .decode(&state.config.security.master_key_b64)
        .map_err(|_| corrupt())?;
    if master.len() != 32 {
        return Err(corrupt());
    }
    let mut key = Sha256::new();
    key.update(b"agf.gateway-admission-key.service.v1\0");
    key.update(&master);
    let key: [u8; 32] = key.finalize().into();
    let mut bytes = purpose.to_vec();
    bytes.extend_from_slice(body);
    Ok(hex::encode(mac(&key, &bytes)))
}

pub(super) fn mac(key: &[u8], body: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|byte| byte ^ 0x36));
    inner.update(body);
    let mut outer = Sha256::new();
    outer.update(block.map(|byte| byte ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}
pub(super) fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
pub(super) fn invalid() -> DomainError {
    DomainError::Validation(
        "A single Idempotency-Key requires 1–200 printable ASCII bytes and an authenticated identity".into(),
    )
}
pub(super) fn corrupt() -> DomainError {
    DomainError::Crypto("Durable gateway admission identity is invalid".into())
}
