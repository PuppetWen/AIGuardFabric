//! Configuration identity stays distinct from verified RAM ownership.
use super::{NAME, contract::Scope};
use crate::{
    cloud_store,
    integration_store::{Stored, decrypt, id},
    state::AppState,
};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{TenantId, deterministic_id},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(super) async fn load(state: &AppState, tenant: TenantId) -> DomainResult<(Stored, Scope)> {
    let row = cloud_store::load(state, tenant, NAME)
        .await?
        .filter(|row| row.enabled)
        .ok_or_else(|| DomainError::PreconditionFailed("请先启用PrivateLink连接并明确配置现有endpoint_id".into()))?;
    let scope = from_row(state, tenant, &row)?;
    Ok((row, scope))
}

pub(super) fn from_row(state: &AppState, tenant: TenantId, row: &Stored) -> DomainResult<Scope> {
    if row.id != id(tenant, NAME) || row.name != NAME {
        return Err(stale());
    }
    let private = decrypt(state, tenant, row)?;
    let region = private
        .settings
        .get("region_id")
        .ok_or_else(|| DomainError::Validation("PrivateLink盘点必须明确配置端点region_id".into()))
        .and_then(|value| identifier(value, "region_id"))?;
    let endpoint_id = private
        .settings
        .get("endpoint_id")
        .ok_or_else(|| DomainError::Validation("PrivateLink盘点必须明确配置现有endpoint_id".into()))
        .and_then(|value| identifier(value, "endpoint_id"))?;
    let source_identity = hash(&json!([
        cloud_store::setting(&private, "endpoint", ""),
        cloud_store::setting(&private, "account_id", ""),
        cloud_store::setting(&private, "credential_source", "access-key"),
        cloud_store::setting(&private, "role_arn", ""),
        private.secrets.get("access_key_id")
    ]))?;
    let mocked = state.config.mock_mode || row.mock;
    let scope_id = deterministic_id(
        "agf.privatelink.inventory.scope",
        &hash(&json!([tenant, row.id, row.version, source_identity, region, endpoint_id, mocked]))?,
    );
    Ok(Scope {
        id: scope_id,
        cloud_id: row.id,
        configuration_version: row.version,
        source_identity,
        region,
        endpoint_id,
        mocked,
    })
}

fn identifier(value: &Value, field: &str) -> DomainResult<String> {
    value
        .as_str()
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 256
                && !value.chars().any(|character| character.is_control() || character.is_whitespace())
        })
        .map(str::to_owned)
        .ok_or_else(|| DomainError::Validation(format!("PrivateLink {field}须为非空安全标识")))
}

pub(super) fn hash(value: &Value) -> DomainResult<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

pub(super) fn stale() -> DomainError {
    DomainError::Conflict("PrivateLink配置、范围、租约或请求状态已变化；请重新读取".into())
}
