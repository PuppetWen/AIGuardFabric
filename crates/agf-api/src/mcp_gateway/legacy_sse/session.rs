//! Durable binding between a 2024 SSE connection and its advertised upstream POST URL.
use super::super::{config::Endpoint, invalid};
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
use serde_json::Value;
use std::collections::BTreeMap;

const KIND: &str = "mcp-legacy-sse-sessions";
const MAX_SESSIONS: i64 = 256;
const MAX_PENDING: usize = 64;
const SESSION_SECS: i64 = 60;

#[derive(Clone, Default, Serialize, Deserialize)]
struct Session {
    id: Option<Id>,
    endpoint_id: Option<Id>,
    version: u64,
    owner: String,
    expires: i64,
    post_url: Option<SecretMaterial>,
    pending: BTreeMap<String, Id>,
    #[serde(default)]
    usage_pending: BTreeMap<String, Id>,
}

fn missing(id: Id) -> DomainError {
    DomainError::NotFound { entity: "mcp-sse-session", id: id.to_string() }
}

fn check(row: &Session, principal: &Principal, endpoint: &Endpoint, id: Id) -> DomainResult<()> {
    if row.id != Some(id)
        || row.endpoint_id != Some(endpoint.id)
        || row.version != endpoint.version
        || row.owner != principal.display()
        || row.expires <= Timestamp::now().unix_secs()
    {
        return Err(missing(id));
    }
    Ok(())
}

pub(super) async fn open(
    state: &AppState,
    principal: &Principal,
    endpoint: &Endpoint,
    post_url: &str,
) -> DomainResult<Id> {
    let now = Timestamp::now().unix_secs();
    for stale in state
        .configurations
        .list::<Session>(principal.tenant, KIND)
        .await?
        .into_iter()
        .filter(|row| row.expires <= now)
        .take(MAX_SESSIONS as usize)
    {
        if let Some(id) = stale.id {
            state.configurations.delete(principal.tenant, KIND, id).await?;
        }
    }
    let id = Id::new();
    let record = Session {
        id: Some(id),
        endpoint_id: Some(endpoint.id),
        version: endpoint.version,
        owner: principal.display(),
        expires: now + SESSION_SECS,
        post_url: Some(encrypt(state, principal.tenant, id, post_url.into())?),
        pending: BTreeMap::new(),
        usage_pending: BTreeMap::new(),
    };
    state
        .configurations
        .mutate_bounded::<Session, _>(principal.tenant, KIND, id, Some(MAX_SESSIONS), |row| {
            if row.id.is_some() {
                return Err(DomainError::Conflict("MCP SSE session ID already exists".into()));
            }
            *row = record.clone();
            Ok(())
        })
        .await?;
    Ok(id)
}

async fn load(state: &AppState, principal: &Principal, endpoint: &Endpoint, id: Id) -> DomainResult<Session> {
    let row = state.configurations.get::<Session>(principal.tenant, KIND, id).await?.ok_or_else(|| missing(id))?;
    check(&row, principal, endpoint, id)?;
    Ok(row)
}

pub(super) async fn post_url(
    state: &AppState,
    principal: &Principal,
    endpoint: &Endpoint,
    id: Id,
) -> DomainResult<String> {
    let row = load(state, principal, endpoint, id).await?;
    let sealed = row.post_url.ok_or_else(|| DomainError::Crypto("MCP SSE POST URL missing".into()))?;
    if sealed.aad.as_deref() != Some(&FieldCipher::make_aad(&principal.tenant, &id)) {
        return Err(DomainError::Crypto("MCP SSE POST URL binding mismatch".into()));
    }
    let value = cipher(state)?.decrypt(&sealed)?.expose_secret().to_string();
    super::validate_post_url(&endpoint.url, &value)?;
    Ok(value)
}

pub(super) async fn close(state: &AppState, principal: &Principal, endpoint: &Endpoint, id: Id) -> DomainResult<()> {
    load(state, principal, endpoint, id).await?;
    state.configurations.delete(principal.tenant, KIND, id).await
}

pub(super) async fn heartbeat(
    state: &AppState,
    principal: &Principal,
    endpoint: &Endpoint,
    id: Id,
) -> DomainResult<Vec<(Id, Option<Id>)>> {
    let row = state
        .configurations
        .mutate::<Session, _>(principal.tenant, KIND, id, |row| {
            check(row, principal, endpoint, id)?;
            row.expires = Timestamp::now().unix_secs() + SESSION_SECS;
            Ok(())
        })
        .await?;
    Ok(row.pending.iter().map(|(key, id)| (*id, row.usage_pending.get(key).copied())).collect())
}

fn request_key(request_id: &Value) -> DomainResult<String> {
    if request_id.is_null() || !(request_id.is_string() || request_id.is_i64() || request_id.is_u64()) {
        return Err(invalid("MCP SSE request ID must be a string or integer"));
    }
    serde_json::to_string(request_id).map_err(Into::into)
}

pub(super) async fn remember_pending(
    state: &AppState,
    principal: &Principal,
    endpoint: &Endpoint,
    id: Id,
    request_id: &Value,
    lease_id: Id,
    usage_id: Id,
) -> DomainResult<()> {
    let key = request_key(request_id)?;
    state
        .configurations
        .mutate::<Session, _>(principal.tenant, KIND, id, |row| {
            check(row, principal, endpoint, id)?;
            if row.pending.len() >= MAX_PENDING {
                return Err(invalid("MCP SSE session has too many unfinished tool calls"));
            }
            if row.pending.contains_key(&key) {
                return Err(DomainError::Conflict("MCP SSE request ID is already in flight".into()));
            }
            row.pending.insert(key.clone(), lease_id);
            row.usage_pending.insert(key, usage_id);
            Ok(())
        })
        .await?;
    Ok(())
}

pub(super) async fn pending_for(
    state: &AppState,
    principal: &Principal,
    endpoint: &Endpoint,
    id: Id,
    request_id: &Value,
) -> DomainResult<Option<(Id, Option<Id>)>> {
    let key = request_key(request_id)?;
    let row = load(state, principal, endpoint, id).await?;
    Ok(row.pending.get(&key).map(|lease| (*lease, row.usage_pending.get(&key).copied())))
}

pub(super) async fn forget_pending(
    state: &AppState,
    principal: &Principal,
    endpoint: &Endpoint,
    id: Id,
    request_id: &Value,
) -> DomainResult<()> {
    let key = request_key(request_id)?;
    state
        .configurations
        .mutate::<Session, _>(principal.tenant, KIND, id, |row| {
            check(row, principal, endpoint, id)?;
            row.pending.remove(&key);
            row.usage_pending.remove(&key);
            Ok(())
        })
        .await?;
    Ok(())
}
