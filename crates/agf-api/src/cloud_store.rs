//! Tenant cloud settings reuse the encrypted integration envelope, with no network access on save.
use crate::{
    integration_store::{Private, Stored, Update, decrypt, id},
    model_gateway::encrypt,
    state::AppState,
};
use agf_alicloud::{
    credential::{
        CloudCredential,
        sts_async::{AssumeRoleRequest, from_secret_json},
    },
    endpoint::{EndpointStyle, ResolvedEndpoint, resolve, service_key},
    openapi::contracts,
};
use agf_core::{
    audit::AuditLog,
    enums::AliCloudService,
    error::{DomainError, DomainResult},
    ids::TenantId,
    time::Timestamp,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const KIND: &str = "cloud-integration";
pub const SECRET_KEYS: [&str; 3] = ["access_key_id", "access_key_secret", "security_token"];
pub fn service(name: &str) -> DomainResult<AliCloudService> {
    AliCloudService::all()
        .into_iter()
        .find(|service| service.as_str() == name)
        .ok_or_else(|| DomainError::NotFound { entity: "cloud-service", id: name.into() })
}
pub fn setting<'a>(private: &'a Private, key: &str, default: &'a str) -> &'a str {
    private.settings.get(key).and_then(Value::as_str).filter(|value| !value.is_empty()).unwrap_or(default)
}
pub fn endpoint(service: AliCloudService, private: &Private) -> DomainResult<ResolvedEndpoint> {
    let style = match setting(private, "endpoint_style", "public") {
        "public" => EndpointStyle::Public,
        "private" => EndpointStyle::Private,
        _ => return Err(DomainError::Validation("endpoint_style 必须是 public 或 private".into())),
    };
    let overrides = BTreeMap::from([(service_key(service).into(), setting(private, "endpoint", "").into())]);
    resolve(service, setting(private, "region_id", "cn-hangzhou"), style, &overrides)
}
pub fn source(private: &Private) -> DomainResult<CloudCredential> {
    let mut fields = serde_json::to_value(&private.secrets)?;
    fields["expires_at"] = private.settings.get("expires_at").cloned().unwrap_or(Value::Null);
    let credential = from_secret_json(&fields.to_string())?;
    if setting(private, "credential_source", "access-key") == "sts" && credential.security_token.is_none() {
        return Err(DomainError::Validation("STS 模式必须提供 security_token 和 expires_at".into()));
    }
    Ok(credential)
}
pub fn role(private: &Private) -> DomainResult<Option<AssumeRoleRequest>> {
    match setting(private, "credential_source", "access-key") {
        "access-key" | "sts" | "ecs-role" => Ok(None),
        "assume-role" | "oidc-role" => {
            let duration = private
                .settings
                .get("duration_seconds")
                .map(|value| value.as_u64().ok_or_else(|| DomainError::Validation("STS 有效期必须是整数秒".into())))
                .transpose()?
                .unwrap_or(3600);
            let request = AssumeRoleRequest {
                role_arn: setting(private, "role_arn", "").into(),
                session_name: setting(private, "role_session_name", "aiguardfabric").into(),
                duration_seconds: u32::try_from(duration)
                    .map_err(|_| DomainError::Validation("STS 有效期过长".into()))?,
                external_id: private
                    .settings
                    .get("external_id")
                    .and_then(Value::as_str)
                    .filter(|v| !v.is_empty())
                    .map(str::to_string),
                policy: private
                    .settings
                    .get("session_policy")
                    .and_then(Value::as_str)
                    .filter(|v| !v.is_empty())
                    .map(str::to_string),
            };
            request.validate()?;
            Ok(Some(request))
        }
        _ => Err(DomainError::Validation("不支持的凭据来源".into())),
    }
}
pub async fn load(state: &AppState, tenant: TenantId, name: &str) -> DomainResult<Option<Stored>> {
    service(name)?;
    state.configurations.get(tenant, KIND, id(tenant, name)).await
}
pub async fn view(state: &AppState, tenant: TenantId, name: &str) -> DomainResult<Value> {
    let service = service(name)?;
    let row = load(state, tenant, name).await?;
    let private = row.as_ref().map(|row| decrypt(state, tenant, row)).transpose()?.unwrap_or_default();
    let endpoint = endpoint(service, &private)?.url("/");
    let probe = state.configurations.get::<Value>(tenant, "cloud-probe", id(tenant, name)).await?.filter(|probe| {
        row.as_ref().is_some_and(|row| {
            row.enabled
                && probe["version"].as_u64() == Some(row.version)
                && probe["mocked"].as_bool() == Some(state.config.mock_mode || row.mock)
        })
    });
    let operations: Vec<_> = contracts(service)?
        .into_iter()
        .filter(|operation| {
            crate::cloud_runtime::generic_operation_visible(service, &operation.action, operation.read_only)
        })
        .collect();
    Ok(json!({"name":name,"display_name":agf_alicloud::mock::display_name_of(service),
        "enabled":row.as_ref().is_some_and(|row|row.enabled),"mock":row.as_ref().is_none_or(|row|row.mock),
        "environment_mock":state.config.mock_mode,"version":row.as_ref().map_or(0,|row|row.version),
        "updated_at":row.as_ref().map(|row|row.updated_at),"settings":private.settings,"secret_keys":private.secrets.keys().collect::<Vec<_>>(),
        "endpoint":endpoint,"operations":operations,"probe":probe}))
}
pub async fn save(state: &AppState, tenant: TenantId, name: &str, body: Update) -> DomainResult<Value> {
    save_inner(state, tenant, name, body, None).await
}

pub async fn save_audited(
    state: &AppState,
    tenant: TenantId,
    name: &str,
    body: Update,
    audit: AuditLog,
) -> DomainResult<Value> {
    save_inner(state, tenant, name, body, Some(audit)).await
}

async fn save_inner(
    state: &AppState,
    tenant: TenantId,
    name: &str,
    body: Update,
    audit: Option<AuditLog>,
) -> DomainResult<Value> {
    let selected = service(name)?;
    let previous = load(state, tenant, name).await?;
    let mut private = previous.as_ref().map(|row| decrypt(state, tenant, row)).transpose()?.unwrap_or_default();
    if previous.as_ref().map_or(0, |row| row.version) != body.expected_version {
        return Err(DomainError::Conflict("云配置已被其他用户修改，请重新加载".into()));
    }
    let mut settings = body.settings;
    let mut supplied = body.secrets;
    for key in SECRET_KEYS {
        if let Some(value) = settings.remove(key).and_then(|value| value.as_str().map(str::to_owned)) {
            if !value.is_empty() {
                supplied.insert(key.into(), value);
            }
        }
    }
    if supplied.keys().chain(&body.clear_secrets).any(|key| !SECRET_KEYS.contains(&key.as_str())) {
        return Err(DomainError::Validation("存在未登记的云凭据字段".into()));
    }
    let next = Private { settings, secrets: BTreeMap::new() };
    let changed = endpoint(selected, &next)?.url("/") != endpoint(selected, &private)?.url("/")
        // The Nacos engine receives credentials separately from the Console RPC endpoint.
        || (selected == AliCloudService::Mse
            && setting(&next, "engine_origin", "") != setting(&private, "engine_origin", ""))
        || [
            ("sts_endpoint", "https://sts.aliyuncs.com"),
            ("account_id", ""),
            ("role_arn", ""),
            ("credential_source", "access-key"),
        ]
        .iter()
        .any(|(key, default)| setting(&next, key, default) != setting(&private, key, default));
    if changed {
        private.secrets.clear();
    }
    private.settings = next.settings;
    for key in &body.clear_secrets {
        private.secrets.remove(key);
    }
    for (key, value) in supplied {
        if !value.is_empty() {
            private.secrets.insert(key, value);
        }
    }
    endpoint(selected, &private)?;
    if setting(&private, "credential_source", "") == "oidc-role" {
        private.settings.remove("external_id");
    }
    // The same strict endpoint parser validates an STS override without contacting it.
    let mut sts = Private::default();
    sts.settings.insert("endpoint".into(), json!(setting(&private, "sts_endpoint", "https://sts.aliyuncs.com")));
    endpoint(AliCloudService::Cms, &sts)?;
    if body.enabled && !body.mock && !state.config.mock_mode {
        crate::cloud_credentials::validate(tenant, &private)?;
    }
    if crate::cloud_credentials::is_workload(&private) {
        private.secrets.clear();
    }
    let encoded = serde_json::to_string(&private)?;
    if encoded.len() > 32768 {
        return Err(DomainError::Validation("云配置最多 32 KiB".into()));
    }
    let row = Stored {
        id: id(tenant, name),
        name: name.into(),
        enabled: body.enabled,
        mock: body.mock,
        version: body.expected_version.checked_add(1).ok_or_else(|| DomainError::Conflict("版本已达上限".into()))?,
        updated_at: Timestamp::now(),
        private: encrypt(state, tenant, id(tenant, name), encoded)?,
    };
    let apply = |current: &mut Option<Stored>| {
        if current.as_ref().map_or(0, |row| row.version) != body.expected_version {
            return Err(DomainError::Conflict("云配置已改变，请重新加载".into()));
        }
        *current = Some(row);
        Ok(())
    };
    let sealed = if let Some(entry) = audit.as_ref() {
        state
            .configurations
            .mutate_audited::<Option<Stored>, _>(tenant, KIND, id(tenant, name), entry.clone(), apply)
            .await?
            .1
    } else {
        state.configurations.mutate(tenant, KIND, id(tenant, name), apply).await?;
        None
    };
    if let Some(sealed) = sealed {
        if let Err(error) = state.store.hydrate_audit(&sealed) {
            tracing::warn!(%error, "已提交的云配置审计内存投影刷新失败");
        }
    } else if let Some(entry) = audit {
        state.store.audit_append_durable(entry).await?;
    }
    view(state, tenant, name).await
}
