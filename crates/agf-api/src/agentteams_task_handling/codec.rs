//! Kind, tenant and canonical key are authenticated together. Reads never initialize records.
use super::{Handling, Journal, RequestFact, util};
use crate::state::AppState;
use agf_core::{
    credential::SecretMaterial,
    error::DomainResult,
    ids::{Id, TenantId, deterministic_id},
};
use agf_storage::crypto::FieldCipher;
use secrecy::{ExposeSecret, SecretString};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

pub(super) const STATE: &str = "agentteams-task-handling-state";
pub(super) const RECORD: &str = "agentteams-task-handling-record";
pub(super) const REQUEST: &str = "agentteams-task-handling-request";
pub(super) type Key = (String, Id);
pub(super) type Values = std::collections::BTreeMap<Key, Option<Value>>;

pub(super) fn state_key(tenant: TenantId) -> Key {
    key(STATE, tenant, &tenant.to_string())
}
pub(super) fn record_key(tenant: TenantId, id: Id) -> Key {
    key(RECORD, tenant, &id.to_string())
}
pub(super) fn request_key(tenant: TenantId, id: Id) -> Key {
    key(REQUEST, tenant, &id.to_string())
}
fn key(kind: &str, tenant: TenantId, identity: &str) -> Key {
    (kind.into(), deterministic_id("agf.agentteams.task-handling.key.v1", &format!("{tenant}:{kind}:{identity}")))
}
fn aad(tenant: TenantId, key: &Key) -> String {
    format!("agf.agentteams.task-handling.record.v1:{}:{}:{}", tenant, key.0, key.1)
}
pub(super) fn encode<T: Serialize>(state: &AppState, tenant: TenantId, key: &Key, body: &T) -> DomainResult<Value> {
    let text = serde_json::to_string(body)?;
    if text.len() > 512 * 1024 {
        return Err(util::invalid());
    }
    let cipher = crate::model_gateway::cipher(state)?;
    let material = cipher.encrypt(&SecretString::from(text), &aad(tenant, key))?;
    let value = serde_json::to_value(material)?;
    util::bounded(&value, 1024 * 1024)?;
    Ok(value)
}
pub(super) fn decode<T: DeserializeOwned>(
    state: &AppState,
    tenant: TenantId,
    key: &Key,
    value: &Value,
) -> DomainResult<T> {
    util::bounded(value, 1024 * 1024)?;
    let material: SecretMaterial = serde_json::from_value(value.clone()).map_err(|_| util::corrupt())?;
    if material.aad.as_deref() != Some(aad(tenant, key).as_str()) || material.plaintext_len > 512 * 1024 {
        return Err(util::corrupt());
    }
    let cipher: FieldCipher = crate::model_gateway::cipher(state)?;
    let text = cipher.decrypt(&material).map_err(|_| util::corrupt())?;
    if text.expose_secret().len() > 512 * 1024 {
        return Err(util::corrupt());
    }
    serde_json::from_str(text.expose_secret()).map_err(|_| util::corrupt())
}
pub(super) fn journal(state: &AppState, tenant: TenantId, values: &Values) -> DomainResult<Journal> {
    let key = state_key(tenant);
    let journal = values
        .get(&key)
        .and_then(Option::as_ref)
        .map(|value| decode(state, tenant, &key, value))
        .transpose()?
        .unwrap_or_else(|| Journal::new(tenant));
    journal.validate(tenant)?;
    Ok(journal)
}
pub(super) fn handling(state: &AppState, tenant: TenantId, id: Id, values: &Values) -> DomainResult<Option<Handling>> {
    let key = record_key(tenant, id);
    let row: Option<Handling> =
        values.get(&key).and_then(Option::as_ref).map(|value| decode(state, tenant, &key, value)).transpose()?;
    if let Some(row) = &row {
        row.validate(&row.evidence)?;
        if row.evidence.tenant != tenant || row.evidence.event_id != id {
            return Err(util::corrupt());
        }
    }
    Ok(row)
}
pub(super) fn request(
    state: &AppState,
    tenant: TenantId,
    id: Id,
    values: &Values,
) -> DomainResult<Option<RequestFact>> {
    let key = request_key(tenant, id);
    let row: Option<RequestFact> =
        values.get(&key).and_then(Option::as_ref).map(|value| decode(state, tenant, &key, value)).transpose()?;
    if let Some(row) = &row {
        row.validate(tenant, id)?;
    }
    Ok(row)
}
