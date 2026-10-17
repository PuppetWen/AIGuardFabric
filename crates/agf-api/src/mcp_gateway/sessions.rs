//! Legacy Streamable HTTP sessions use opaque proxy IDs bound to tenant, caller and endpoint version.
use super::{config::Endpoint, invalid};
use crate::{
    Principal,
    model_gateway::{cipher, encrypt},
    state::AppState,
};
use agf_core::{
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::Id,
    time::Timestamp,
};
use agf_storage::crypto::FieldCipher;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const KIND: &str = "mcp-http-sessions";
#[derive(Clone, Serialize, Deserialize)]
struct Session {
    owner: String,
    version: u64,
    expires: i64,
    upstream: SecretMaterial,
}
#[derive(Default, Serialize, Deserialize)]
struct Sessions {
    entries: BTreeMap<Id, Session>,
}

pub(super) async fn open(
    state: &AppState,
    principal: &Principal,
    endpoint: &Endpoint,
    upstream: &str,
) -> DomainResult<Id> {
    if upstream.is_empty() || upstream.len() > 2048 || !upstream.bytes().all(|b| (33..=126).contains(&b)) {
        return Err(invalid("Upstream returned an invalid MCP session ID"));
    }
    let id = Id::new();
    let now = Timestamp::now().unix_secs();
    let record = Session {
        owner: principal.display(),
        version: endpoint.version,
        expires: now + 3600,
        upstream: encrypt(state, principal.tenant, id, upstream.into())?,
    };
    state
        .configurations
        .mutate::<Sessions, _>(principal.tenant, KIND, endpoint.id, |sessions| {
            sessions.entries.retain(|_, session| session.expires > now && session.version == endpoint.version);
            if sessions.entries.len() >= 1024 {
                return Err(invalid("MCP session capacity reached; close unused sessions"));
            }
            sessions.entries.insert(id, record.clone());
            Ok(())
        })
        .await?;
    Ok(id)
}

pub(super) async fn resolve(
    state: &AppState,
    principal: &Principal,
    endpoint: &Endpoint,
    id: Id,
) -> DomainResult<String> {
    let now = Timestamp::now().unix_secs();
    let mut upstream = None;
    state
        .configurations
        .mutate::<Sessions, _>(principal.tenant, KIND, endpoint.id, |sessions| {
            let row = sessions
                .entries
                .get_mut(&id)
                .filter(|row| row.owner == principal.display() && row.version == endpoint.version && row.expires > now)
                .ok_or_else(|| DomainError::NotFound { entity: "mcp-session", id: id.to_string() })?;
            if row.upstream.aad.as_deref() != Some(&FieldCipher::make_aad(&principal.tenant, &id)) {
                return Err(DomainError::Crypto("MCP session binding mismatch".into()));
            }
            upstream = Some(cipher(state)?.decrypt(&row.upstream)?.expose_secret().to_string());
            row.expires = now + 3600;
            Ok(())
        })
        .await?;
    upstream.ok_or_else(|| invalid("MCP session unavailable"))
}

pub(super) async fn remove(state: &AppState, principal: &Principal, endpoint: &Endpoint, id: Id) -> DomainResult<()> {
    state
        .configurations
        .mutate::<Sessions, _>(principal.tenant, KIND, endpoint.id, |sessions| {
            if sessions.entries.get(&id).is_some_and(|row| row.owner != principal.display()) {
                return Err(DomainError::Forbidden("MCP session belongs to another caller".into()));
            }
            sessions.entries.remove(&id);
            Ok(())
        })
        .await?;
    Ok(())
}

/// Keep an active legacy stream's session alive even if it carries no event IDs for an hour.
pub(super) async fn renew(
    state: &AppState,
    principal: &Principal,
    endpoint_id: Id,
    endpoint_version: u64,
    session_id: Id,
) -> DomainResult<()> {
    let now = Timestamp::now().unix_secs();
    state
        .configurations
        .mutate::<Sessions, _>(principal.tenant, KIND, endpoint_id, |sessions| {
            let row = sessions
                .entries
                .get_mut(&session_id)
                .filter(|row| row.owner == principal.display() && row.version == endpoint_version && row.expires > now)
                .ok_or_else(|| DomainError::NotFound { entity: "mcp-session", id: session_id.to_string() })?;
            row.expires = now + 3600;
            Ok(())
        })
        .await?;
    Ok(())
}
