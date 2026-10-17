//! 租户通知配置。Webhook URL、SMTP 密码与签名凭据均加密落库。
use crate::{
    model_gateway::{cipher, encrypt},
    state::AppState,
};
use agf_adapters::{contract::VendorAdapter, settings::StaticSecrets};
use agf_core::{
    adapter::AdapterConfig,
    audit::AuditLog,
    credential::SecretMaterial,
    enums::Severity,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
    notify::ChannelKind,
    time::Timestamp,
};
use agf_storage::crypto::FieldCipher;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const KIND: &str = "notification-channel";

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredChannel {
    pub id: Id,
    #[serde(default)]
    pub version: u64,
    pub channel: ChannelKind,
    pub enabled: bool,
    pub min_severity: Severity,
    pub private: SecretMaterial,
}
#[derive(Default, Serialize, Deserialize)]
pub struct PrivateConfig {
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub settings: BTreeMap<String, Value>,
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Update {
    pub expected_version: Option<u64>,
    pub enabled: bool,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub settings: BTreeMap<String, Value>,
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
    pub min_severity: Option<Severity>,
}
pub fn parse(value: &str) -> DomainResult<ChannelKind> {
    let value = match value {
        "ding-talk" => "dingtalk",
        "we-com" => "wecom",
        "pager-duty" => "pagerduty",
        other => other,
    };
    ChannelKind::all()
        .into_iter()
        .find(|kind| kind.as_str() == value)
        .ok_or_else(|| DomainError::Validation("未知通知渠道".into()))
}
pub fn id(tenant: TenantId, kind: ChannelKind) -> Id {
    deterministic_id("aiguardfabric.api.notify_channel", &format!("{tenant}:{}", kind.as_str()))
}
pub fn decrypt(state: &AppState, tenant: TenantId, row: &StoredChannel) -> DomainResult<PrivateConfig> {
    if row.private.aad.as_deref() != Some(&FieldCipher::make_aad(&tenant, &row.id)) {
        return Err(DomainError::Crypto("通知凭据租户绑定不匹配".into()));
    }
    let raw = cipher(state)?.decrypt(&row.private)?;
    serde_json::from_str(raw.expose_secret()).map_err(|_| DomainError::Config("通知配置解密后格式无效".into()))
}
pub fn view(row: &StoredChannel, private: &PrivateConfig, mocked: bool) -> Value {
    // 设置只通过字符串提供给 JSON 编辑器，避免全局 camelizer 改写厂商键名。
    json!({"channel":row.channel,"version":row.version,"enabled":row.enabled,"minSeverity":row.min_severity,
        "target": if matches!(row.channel, ChannelKind::Email | ChannelKind::Sms) { &private.target } else { "" },
        "configured":true,"settingsJson":serde_json::to_string_pretty(&private.settings).unwrap_or_default(),
        "secretKeys":private.secrets.keys().collect::<Vec<_>>(),"mocked":mocked && row.channel != ChannelKind::InApp})
}
pub async fn save(state: &AppState, tenant: TenantId, kind: ChannelKind, body: Update) -> DomainResult<Value> {
    save_inner(state, tenant, kind, body, None).await
}

pub async fn save_audited(
    state: &AppState,
    tenant: TenantId,
    kind: ChannelKind,
    body: Update,
    audit: AuditLog,
) -> DomainResult<Value> {
    save_inner(state, tenant, kind, body, Some(audit)).await
}

async fn save_inner(
    state: &AppState,
    tenant: TenantId,
    kind: ChannelKind,
    body: Update,
    audit: Option<AuditLog>,
) -> DomainResult<Value> {
    let key = id(tenant, kind);
    let apply = |slot: &mut Option<StoredChannel>| {
        let previous = slot.as_ref();
        let version = previous.map_or(0, |row| row.version);
        let expected = match (previous, body.expected_version) {
            (Some(_), None) => {
                return Err(DomainError::Validation("编辑通知配置须提供 expectedVersion，请重新加载".into()));
            }
            (None, None) => 0,
            (_, Some(version)) => version,
        };
        if expected != version {
            return Err(DomainError::Conflict("通知渠道已被其他人修改，请重新加载后合并变更".into()));
        }
        let next_version = version.checked_add(1).ok_or_else(|| DomainError::Conflict("版本已达上限".into()))?;
        let mut private = previous.map(|row| decrypt(state, tenant, row)).transpose()?.unwrap_or_default();
        let old_destination = destination(kind, &private);
        if !body.target.trim().is_empty() {
            private.target = body.target.trim().into();
        }
        private.settings = body.settings;
        let mut supplied = body.secrets.into_iter().filter(|(_, value)| !value.is_empty()).collect::<BTreeMap<_, _>>();
        for key in [
            "password",
            "smtp_password",
            "secret",
            "sign_secret",
            "signing_secret",
            "routing_key",
            "auth_header",
            "token",
            "api_key",
            "webhook_url",
        ] {
            if let Some(value) = private.settings.remove(key).and_then(|value| value.as_str().map(str::to_owned)) {
                if !value.is_empty() {
                    supplied.insert(key.into(), value);
                }
            }
        }
        if previous.is_some() && old_destination != destination(kind, &private) {
            if private.secrets.keys().any(|key| !supplied.contains_key(key)) {
                return Err(DomainError::Validation("更换通知投递地址时，请重新填写已保存的渠道凭据".into()));
            }
            private.secrets.clear();
        }
        private.secrets.extend(supplied);
        if private.target.len() > 4096 || serde_json::to_vec(&private)?.len() > 32768 {
            return Err(DomainError::Validation("通知配置过大".into()));
        }
        if body.enabled {
            validate(state, tenant, kind, &private)?;
        }
        *slot = Some(StoredChannel {
            id: key,
            version: next_version,
            channel: kind,
            enabled: body.enabled,
            min_severity: body.min_severity.unwrap_or_else(|| previous.map_or(Severity::Low, |row| row.min_severity)),
            private: encrypt(state, tenant, key, serde_json::to_string(&private)?)?,
        });
        Ok(())
    };
    let (saved, sealed) = if let Some(entry) = audit.as_ref() {
        state.configurations.mutate_audited(tenant, KIND, key, entry.clone(), apply).await?
    } else {
        (state.configurations.mutate(tenant, KIND, key, apply).await?, None)
    };
    if let Some(sealed) = sealed {
        if let Err(error) = state.store.hydrate_audit(&sealed) {
            tracing::warn!(%error, "已提交的通知配置审计内存投影刷新失败");
        }
    } else if let Some(entry) = audit {
        state.store.audit_append_durable(entry).await?;
    }
    let row = saved.ok_or_else(|| DomainError::Internal("通知配置未保存".into()))?;
    let private = decrypt(state, tenant, &row)?;
    Ok(view(&row, &private, state.config.mock_mode))
}

fn destination(kind: ChannelKind, private: &PrivateConfig) -> Vec<String> {
    match kind {
        ChannelKind::Email => ["smtp_host", "smtp_port", "smtp_security", "smtp_user"]
            .into_iter()
            .map(|key| private.settings.get(key).map(Value::to_string).unwrap_or_default())
            .collect(),
        ChannelKind::Sms | ChannelKind::PagerDuty => {
            vec![private.settings.get("endpoint").map(Value::to_string).unwrap_or_default()]
        }
        ChannelKind::InApp => Vec::new(),
        _ => vec![private.target.clone()],
    }
}
pub fn adapter(
    state: &AppState,
    tenant: TenantId,
    kind: ChannelKind,
    private: &PrivateConfig,
) -> DomainResult<Box<dyn VendorAdapter>> {
    let mut adapter = agf_adapters::vendors::builtin()
        .into_iter()
        .find(|a| a.name() == kind.as_str())
        .ok_or_else(|| DomainError::Config("通知适配器不存在".into()))?;
    let mut settings = private.settings.clone();
    let mut secrets = StaticSecrets::new();
    for (key, value) in &private.secrets {
        secrets = secrets.with(key, value);
    }
    if kind.uses_webhook_url() {
        secrets = secrets.with("webhook_url", &private.target);
    }
    if kind == ChannelKind::Email {
        settings.insert("to".into(), json!(private.target));
    }
    let config = AdapterConfig {
        id: id(tenant, kind),
        tenant_id: tenant,
        adapter: kind.as_str().into(),
        display_name: kind.as_str().into(),
        enabled: true,
        settings,
        secret_refs: BTreeMap::new(),
        circuit_breaker: agf_core::adapter::CircuitBreakerConfig::default(),
        // The durable outbox owns retries; each claimed attempt sends once.
        retry: agf_core::adapter::RetryConfig { max_attempts: 1, ..Default::default() },
        timeout_secs: 10,
        mock: state.config.mock_mode,
        is_default: true,
        created_at: Timestamp::now(),
        updated_at: Timestamp::now(),
    };
    let prepared = adapter.prepare(&config, &secrets)?;
    if !prepared.is_configured() {
        return Err(DomainError::Validation("通知渠道缺少必填配置或凭据".into()));
    }
    adapter.commit(prepared);
    Ok(adapter)
}
fn validate(state: &AppState, tenant: TenantId, kind: ChannelKind, private: &PrivateConfig) -> DomainResult<()> {
    match kind {
        ChannelKind::InApp => Ok(()),
        ChannelKind::Sms | ChannelKind::PagerDuty => {
            let endpoint = private
                .settings
                .get("endpoint")
                .and_then(Value::as_str)
                .unwrap_or(if kind == ChannelKind::PagerDuty { "https://events.pagerduty.com/v2/enqueue" } else { "" });
            let url = url::Url::parse(endpoint)
                .map_err(|_| DomainError::Validation("请配置有效的通知服务 endpoint".into()))?;
            if !["https", "http"].contains(&url.scheme())
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err(DomainError::Validation("通知 endpoint 只接受不含用户名口令的 HTTP(S) URL".into()));
            }
            if kind == ChannelKind::PagerDuty && private.secrets.get("routing_key").is_none_or(|v| v.trim().is_empty())
            {
                return Err(DomainError::Validation("缺少 PagerDuty routing_key".into()));
            }
            if kind == ChannelKind::Sms && private.target.is_empty() {
                return Err(DomainError::Validation("请填写短信接收号码".into()));
            }
            Ok(())
        }
        _ => adapter(state, tenant, kind, private).map(|_| ()),
    }
}

impl std::fmt::Debug for StoredChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredChannel").field("credentials", &"<redacted>").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for PrivateConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateConfig").field("credentials", &"<redacted>").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Update {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Update").field("credentials", &"<redacted>").finish_non_exhaustive()
    }
}
