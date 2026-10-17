use super::*;
use agf_storage::crypto::FieldCipher;
use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;

fn aad(tenant: TenantId, kind: &str, id: Id) -> String {
    format!("{}:{kind}:v1", FieldCipher::make_aad(&tenant, &id))
}
pub(super) fn seal<T: Serialize>(
    state: &AppState,
    tenant: TenantId,
    kind: &str,
    id: Id,
    value: &T,
) -> DomainResult<model::Sealed> {
    let raw = serde_json::to_string(value)?;
    if id.is_nil() || raw.len() > MAX_BYTES {
        return Err(DomainError::Validation("角色约束记录超过安全上限".into()));
    }
    let secret = crate::model_gateway::cipher(state)?.encrypt(&SecretString::from(raw), &aad(tenant, kind, id))?;
    Ok(model::Sealed { secret })
}
pub(super) fn open<T: DeserializeOwned>(
    state: &AppState,
    tenant: TenantId,
    kind: &str,
    id: Id,
    row: &model::Sealed,
) -> DomainResult<T> {
    if id.is_nil() || row.secret.aad.as_deref() != Some(aad(tenant, kind, id).as_str()) {
        return Err(DomainError::Crypto("角色约束租户/用途绑定不匹配".into()));
    }
    let raw = crate::model_gateway::cipher(state)?.decrypt(&row.secret)?;
    if raw.expose_secret().len() > MAX_BYTES {
        return Err(DomainError::Crypto("角色约束记录超过安全上限".into()));
    }
    serde_json::from_str(raw.expose_secret()).map_err(|_| DomainError::Crypto("角色约束正文无效".into()))
}
pub(super) fn record(
    state: &AppState,
    tenant: TenantId,
    id: Id,
    sealed: &model::Sealed,
) -> DomainResult<model::Record> {
    let row: model::Record = open(state, tenant, KIND, id, sealed)?;
    if row.tenant != tenant
        || row.asset_id != id
        || row.proof.agent.tenant_id != tenant
        || row.proof.agent.id != id
        || !row.governed
        || row.version == 0
    {
        return Err(DomainError::Crypto("角色约束身份无效".into()));
    }
    Ok(row)
}
pub(super) fn replay(
    state: &AppState,
    tenant: TenantId,
    actor_id: Id,
    asset: Id,
    input: &model::Input,
    sealed: &model::Sealed,
) -> DomainResult<model::Intent> {
    let fact: model::Intent = open(state, tenant, INTENTS, input.request_id, sealed)?;
    if fact.tenant != tenant
        || fact.request_id != input.request_id
        || fact.actor_id != actor_id
        || fact.asset_id != asset
        || fact.body_hash != hash(&(asset, input))?
    {
        return Err(DomainError::Conflict("请求编号已用于另一主体、Worker 或角色变更；请核查原回执".into()));
    }
    // No original or current permission decision is granted by decrypting an intent.
    Ok(fact)
}
