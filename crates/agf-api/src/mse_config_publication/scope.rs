//! The Nacos engine origin is separate from the Alibaba OpenAPI endpoint.
use super::{
    DIALECT, NAME, Registry,
    contract::{ManagedBinding, Scope, TransportMode},
};
use crate::{integration_store, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{TenantId, deterministic_id},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(super) fn from_row(
    state: &AppState,
    tenant: TenantId,
    row: &integration_store::Stored,
    registry: &Registry,
) -> DomainResult<Scope> {
    if row.id != integration_store::id(tenant, NAME) || row.name != NAME || row.version == 0 {
        return Err(DomainError::Conflict("MSE配置身份或版本不匹配，请重新读取".into()));
    }
    let private = integration_store::decrypt(state, tenant, row)?;
    let configured_origin = setting(&private, "engine_origin", false, 2048)?;
    let (_, actual_transport) = registry.endpoint(tenant, &configured_origin)?;
    let engine_origin = url::Url::parse(&configured_origin)
        .map_err(|_| invalid("engine_origin", "origin格式不正确"))?
        .origin()
        .ascii_serialization();
    let region = setting(&private, "region_id", false, 256)?;
    let instance_id = setting(&private, "instance_id", false, 256)?;
    let namespace_id = setting(&private, "namespace_id", true, 256)?;
    if namespace_id == "public" {
        return Err(invalid("namespace_id", "默认namespace须明确使用空字符串"));
    }
    let group = setting(&private, "config_group", false, 256)?;
    let data_id = setting(&private, "config_data_id", false, 256)?;
    if setting(&private, "config_dialect", false, 256)? != DIALECT {
        return Err(invalid("config_dialect", "只支持nacos-http-v2-cas"));
    }
    if private.settings.get("managed_upsert_confirmed") != Some(&Value::Bool(true)) {
        return Err(DomainError::PreconditionFailed("请明确授权平台管理专用JSON Data ID及内容MD5 upsert语义".into()));
    }
    let mocked = state.config.mock_mode || row.mock;
    let transport_mode = if mocked { TransportMode::Mock } else { actual_transport };
    let credential_source = optional_setting(&private, "credential_source")?.unwrap_or("access-key");
    if !matches!(credential_source, "access-key" | "sts" | "assume-role" | "ecs-role" | "oidc-role") {
        return Err(invalid("credential_source", "凭据来源不受支持"));
    }
    let source_identity = source_identity(&private, credential_source)?;
    let scope_hash = hash(&json!([
        tenant,
        row.id,
        source_identity,
        engine_origin,
        region,
        instance_id,
        namespace_id,
        group,
        data_id,
        DIALECT,
        transport_mode
    ]))?;
    let target_scope_id = deterministic_id("agf.mse.config-publication.scope", &scope_hash);
    Ok(Scope {
        tenant,
        source_identity,
        target: ManagedBinding {
            target_scope_id,
            configuration_id: row.id,
            configuration_version: row.version,
            source_label: format!("Configured MSE source ({credential_source})"),
            region,
            instance_id,
            engine_origin,
            namespace_id,
            group,
            data_id,
            dialect: DIALECT.into(),
            mocked,
            transport_mode,
        },
    })
}

fn source_identity(private: &integration_store::Private, credential_source: &str) -> DomainResult<String> {
    hash(&json!([
        optional_setting(private, "account_id")?,
        credential_source,
        optional_setting(private, "role_arn")?,
        optional_setting(private, "ecs_role_name")?,
        optional_setting(private, "oidc_provider_arn")?,
        optional_setting(private, "sts_endpoint")?,
        private.secrets.get("access_key_id")
    ]))
}

fn optional_setting<'a>(private: &'a integration_store::Private, key: &str) -> DomainResult<Option<&'a str>> {
    private
        .settings
        .get(key)
        .map(|value| {
            value
                .as_str()
                .filter(|text| text.len() <= 4096 && !text.chars().any(char::is_control))
                .ok_or_else(|| invalid(key, "来源身份须为有界安全字符串"))
        })
        .transpose()
}

fn setting(private: &integration_store::Private, key: &str, empty: bool, max: usize) -> DomainResult<String> {
    private
        .settings
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| {
            (empty || !value.is_empty())
                && value.len() <= max
                && value.trim() == *value
                && !value.chars().any(char::is_control)
        })
        .map(str::to_owned)
        .ok_or_else(|| invalid(key, "必须提供类型正确且有界的明确值"))
}

fn invalid(field: &str, detail: &str) -> DomainError {
    DomainError::PreconditionFailed(format!("MSE专用发布目标{field}：{detail}"))
}
fn hash(value: &Value) -> DomainResult<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}
