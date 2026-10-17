//! Authenticated fact and pending bodies have disjoint kind/tenant/attempt AAD.
use crate::{model_gateway, state::AppState};
use agf_core::{
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use agf_storage::crypto::FieldCipher;
use secrecy::{ExposeSecret, SecretString};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

const MAX_BODY: usize = 64 * 1024;

fn aad(tenant: TenantId, id: Id, kind: &str) -> String {
    format!("agf.gateway-settlement.preview.v1:{kind}:{tenant}:{id}")
}

pub(super) fn encode<T: Serialize>(
    state: &AppState,
    tenant: TenantId,
    id: Id,
    kind: &str,
    body: &T,
) -> DomainResult<SecretMaterial> {
    encode_with(&model_gateway::cipher(state)?, tenant, id, kind, body)
}

pub(super) fn encode_with<T: Serialize>(
    cipher: &FieldCipher,
    tenant: TenantId,
    id: Id,
    kind: &str,
    body: &T,
) -> DomainResult<SecretMaterial> {
    let text = serde_json::to_string(body)?;
    if text.len() > MAX_BODY {
        return Err(DomainError::PreconditionFailed("Gateway settlement evidence exceeds 64 KiB".into()));
    }
    cipher.encrypt(&SecretString::from(text), &aad(tenant, id, kind))
}

pub(super) fn decode<T: DeserializeOwned>(
    state: &AppState,
    tenant: TenantId,
    id: Id,
    kind: &str,
    body: &SecretMaterial,
) -> DomainResult<T> {
    decode_with(&model_gateway::cipher(state)?, tenant, id, kind, body)
}

pub(super) fn decode_with<T: DeserializeOwned>(
    cipher: &FieldCipher,
    tenant: TenantId,
    id: Id,
    kind: &str,
    body: &SecretMaterial,
) -> DomainResult<T> {
    if body.aad.as_deref() != Some(aad(tenant, id, kind).as_str()) {
        return Err(DomainError::Crypto("Gateway settlement evidence has another AAD".into()));
    }
    let text = cipher.decrypt(body)?;
    if text.expose_secret().len() > MAX_BODY {
        return Err(DomainError::Crypto("Gateway settlement evidence is oversized".into()));
    }
    // Do not return serde source text or deserializer errors containing provider data.
    serde_json::from_str(text.expose_secret())
        .map_err(|_| DomainError::Crypto("Gateway settlement evidence has an invalid typed body".into()))
}

pub(super) fn hash<T: Serialize>(body: &T) -> DomainResult<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(body)?)))
}
