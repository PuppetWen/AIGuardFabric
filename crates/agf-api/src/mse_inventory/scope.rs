//! Scope identity is derived from the frozen configured source; it is not a claim of verified RAM account identity.
use super::{NAME, contract::Scope};
use crate::{
    cloud_store,
    integration_store::{Stored, decrypt},
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
        .ok_or_else(|| DomainError::PreconditionFailed("请先启用 MSE 连接并配置实例、命名空间".into()))?;
    let scope = from_row(state, tenant, &row)?;
    Ok((row, scope))
}

pub(super) fn from_row(state: &AppState, tenant: TenantId, row: &Stored) -> DomainResult<Scope> {
    if row.id != crate::integration_store::id(tenant, NAME) || row.name != NAME {
        return Err(DomainError::Validation("MSE 配置记录身份不匹配".into()));
    }
    let private = decrypt(state, tenant, row)?;
    let region = match private.settings.get("region_id") {
        None => "cn-hangzhou",
        Some(value) => value
            .as_str()
            .filter(|value| valid_text(value, 128) && !value.is_empty())
            .ok_or_else(|| DomainError::Validation("MSE region_id 必须为有效字符串".into()))?,
    };
    let instance = private
        .settings
        .get("instance_id")
        .and_then(Value::as_str)
        .filter(|value| valid_text(value, 256) && !value.is_empty())
        .ok_or_else(|| DomainError::Validation("MSE 盘点必须明确配置 instance_id".into()))?;
    let namespace = private
        .settings
        .get("namespace_id")
        .and_then(Value::as_str)
        .filter(|value| valid_text(value, 256))
        .ok_or_else(|| {
            DomainError::Validation("MSE 盘点必须明确配置 namespace_id；空字符串明确选择默认命名空间".into())
        })?;
    let source_identity = hash(&json!([
        cloud_store::setting(&private, "endpoint", ""),
        cloud_store::setting(&private, "account_id", ""),
        cloud_store::setting(&private, "credential_source", "access-key"),
        cloud_store::setting(&private, "role_arn", ""),
        private.secrets.get("access_key_id").map_or("", String::as_str)
    ]))?;
    let mocked = state.config.mock_mode || row.mock;
    let key = hash(&json!([tenant, row.id, row.version, source_identity, region, instance, namespace, mocked]))?;
    Ok(Scope {
        id: deterministic_id("agf.mse.inventory.scope", &key),
        cloud_id: row.id,
        configuration_version: row.version,
        source_identity,
        region: region.into(),
        instance_id: instance.into(),
        namespace_id: namespace.into(),
        mocked,
    })
}

pub(super) fn valid_text(value: &str, max: usize) -> bool {
    value.len() <= max && !value.chars().any(char::is_control)
}

pub(super) fn hash(value: &Value) -> DomainResult<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

pub(super) fn stale() -> DomainError {
    DomainError::Conflict("MSE 配置、范围或操作租约已改变，旧盘点没有发布；请重新读取".into())
}
