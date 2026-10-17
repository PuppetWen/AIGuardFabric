//! Complete source identity fences dispatch; conservative resource identity carries Unknown risk.
use super::{
    contract::{Binding, ManagedBinding, Scope, TransportMode},
    util,
};
use crate::{cloud_store, integration_store, state::AppState};
use agf_alicloud::apig::{
    config_driver::{ContentBinding, ModelBinding},
    policy_driver::MockBridge,
};
use agf_core::{
    enums::AliCloudService,
    error::{DomainError, DomainResult},
    ids::{TenantId, deterministic_id},
};
use serde_json::{Value, json};

pub(super) fn from_row(state: &AppState, tenant: TenantId, row: &integration_store::Stored) -> DomainResult<Scope> {
    if tenant.as_uuid().is_nil()
        || row.id != integration_store::id(tenant, super::NAME)
        || row.name != super::NAME
        || row.version == 0
    {
        return Err(util::stale());
    }
    let private = integration_store::decrypt(state, tenant, row)?;
    let model = ModelBinding {
        http_api_id: required(&private, "configuration_http_api_id")?,
        gateway_id: required(&private, "configuration_gateway_id")?,
        environment_id: required(&private, "configuration_environment_id")?,
    };
    let binding = match required(&private, "configuration_kind")?.as_str() {
        "content" => Binding::Content(ContentBinding {
            model,
            attachment_id: required(&private, "configuration_attachment_id")?,
            plugin_id: required(&private, "configuration_plugin_id")?,
            class_id: required(&private, "configuration_class_id")?,
            class_version: required(&private, "configuration_class_version")?,
        }),
        "models" => Binding::Models(model),
        _ => return Err(DomainError::PreconditionFailed("请选择明确的content或models受管配置类型".into())),
    };
    binding.validate()?;
    if private.settings.get("managed_configuration_confirmed") != Some(&Value::Bool(true)) {
        return Err(DomainError::PreconditionFailed(
            "请明确确认只修改公开开关/已观察模型权重，原私密配置保持且共享影响未知".into(),
        ));
    }
    let resolved = cloud_store::endpoint(AliCloudService::Apig, &private)?;
    let endpoint = url::Url::parse(&resolved.url("/")).map_err(|_| util::corrupt())?.origin().ascii_serialization();
    let mocked = state.config.mock_mode || row.mock;
    let transport_mode = if mocked {
        TransportMode::Mock
    } else {
        state.apig_configuration_publication.mode(tenant, &format!("{endpoint}/"))?
    };
    let source = optional(&private, "credential_source")?.unwrap_or("access-key");
    if !matches!(source, "access-key" | "sts" | "assume-role" | "ecs-role" | "oidc-role") {
        return Err(DomainError::PreconditionFailed("APIG凭据来源不受支持".into()));
    }
    let source_identity = util::request_hash(&json!([
        source,
        optional(&private, "account_id")?,
        optional(&private, "role_arn")?,
        optional(&private, "ecs_role_name")?,
        optional(&private, "oidc_provider_arn")?,
        optional(&private, "sts_endpoint")?,
        private.secrets.get("access_key_id")
    ]))?;
    let scope_hash = util::request_hash(&json!([
        tenant,
        row.id,
        source_identity,
        endpoint,
        resolved.region,
        binding,
        transport_mode
    ]))?;
    // Attachment updates can affect any attached resource. Models share the HTTP API across environments.
    // Account text, credentials, source version and endpoint cannot partition an unverified previous write.
    let resource = match &binding {
        Binding::Content(value) => json!(["attachment", value.attachment_id]),
        Binding::Models(value) => json!(["http_api", value.http_api_id]),
    };
    Ok(Scope {
        tenant,
        source_identity,
        payload_fingerprint: MockBridge::source_fingerprint(&serde_json::to_value(row)?),
        target: ManagedBinding {
            target_scope_id: deterministic_id("agf.apig.configuration-publication.scope", &scope_hash),
            write_resource_id: deterministic_id(
                "agf.apig.configuration-publication.resource",
                &util::request_hash(&json!([tenant, resource]))?,
            ),
            configuration_id: row.id,
            configuration_version: row.version,
            source_label: format!("Configured APIG source ({source})"),
            region: resolved.region,
            endpoint,
            binding,
            mocked,
            transport_mode,
        },
    })
}
fn required(private: &integration_store::Private, key: &str) -> DomainResult<String> {
    optional(private, key)?
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| DomainError::PreconditionFailed(format!("APIG配置绑定须明确填写{key}")))
}
fn optional<'a>(private: &'a integration_store::Private, key: &str) -> DomainResult<Option<&'a str>> {
    private
        .settings
        .get(key)
        .map(|value| {
            value
                .as_str()
                .filter(|text| text.len() <= 4096 && text.trim() == *text && !text.chars().any(char::is_control))
                .ok_or_else(|| DomainError::PreconditionFailed(format!("APIG来源{key}须为有界安全字符串")))
        })
        .transpose()
}
