use super::{
    model::{Envelope, Key, Values},
    util,
};
use crate::{
    model_gateway::{cipher, encrypt},
    state::AppState,
};
use agf_core::{error::DomainResult, ids::TenantId};
use agf_storage::crypto::FieldCipher;
use secrecy::ExposeSecret;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

pub(super) fn encode<T: Serialize>(state: &AppState, tenant: TenantId, key: &Key, row: &T) -> DomainResult<Value> {
    let clear =
        serde_json::to_string(&serde_json::json!({"schema":1,"tenant":tenant,"kind":key.0,"id":key.1,"value":row}))?;
    if clear.len() > 256 * 1024 {
        return Err(util::capacity());
    }
    let envelope = Envelope {
        tenant,
        id: key.1,
        kind: key.0.clone(),
        hash: util::hash(clear.as_bytes()),
        secret: encrypt(state, tenant, key.1, clear)?,
    };
    util::bound(&envelope, 1024 * 1024)?;
    Ok(serde_json::to_value(envelope)?)
}
pub(super) fn decode<T: DeserializeOwned>(
    state: &AppState,
    tenant: TenantId,
    key: &Key,
    value: &Value,
) -> DomainResult<T> {
    util::bound(value, 1024 * 1024).map_err(|_| util::corrupt())?;
    let envelope: Envelope = serde_json::from_value(value.clone()).map_err(|_| util::corrupt())?;
    if envelope.tenant != tenant
        || envelope.id != key.1
        || envelope.kind != key.0
        || envelope.secret.aad.as_deref() != Some(&FieldCipher::make_aad(&tenant, &key.1))
    {
        return Err(util::corrupt());
    }
    util::bound(&envelope, 1024 * 1024)?;
    let clear = cipher(state)?.decrypt(&envelope.secret)?;
    if clear.expose_secret().len() > 256 * 1024 || util::hash(clear.expose_secret().as_bytes()) != envelope.hash {
        return Err(util::corrupt());
    }
    let payload: Value = serde_json::from_str(clear.expose_secret()).map_err(|_| util::corrupt())?;
    if payload["schema"] != 1
        || payload["tenant"] != serde_json::to_value(tenant)?
        || payload["id"] != serde_json::to_value(key.1)?
        || payload["kind"] != key.0
    {
        return Err(util::corrupt());
    }
    serde_json::from_value(payload["value"].clone()).map_err(|_| util::corrupt())
}
pub(super) fn read<T: DeserializeOwned>(
    state: &AppState,
    tenant: TenantId,
    values: &Values,
    key: &Key,
) -> DomainResult<Option<T>> {
    values.get(key).and_then(Option::as_ref).map(|value| decode(state, tenant, key, value)).transpose()
}
pub(super) fn put<T: Serialize>(
    state: &AppState,
    tenant: TenantId,
    values: &mut Values,
    key: Key,
    row: &T,
) -> DomainResult<()> {
    values.insert(key.clone(), Some(encode(state, tenant, &key, row)?));
    Ok(())
}
