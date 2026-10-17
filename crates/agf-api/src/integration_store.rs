//! Encrypted vendor configuration, optimistic updates and explicit TCP reachability checks.
use crate::{
    model_gateway::{cipher, encrypt},
    state::AppState,
};
use agf_adapters::{
    contract::{AdapterMetadata, VendorAdapter},
    health::AdapterHealthRecord,
    settings::StaticSecrets,
};
use agf_core::{
    adapter::{AdapterConfig, CircuitBreakerConfig, RetryConfig},
    audit::AuditLog,
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
    time::Timestamp,
};
use agf_storage::crypto::FieldCipher;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
mod probe;
pub use probe::{probe, probe_audited};

pub const KIND: &str = "vendor-integration";
#[derive(Clone, Serialize, Deserialize)]
pub struct Stored {
    pub id: Id,
    pub name: String,
    pub enabled: bool,
    pub mock: bool,
    pub version: u64,
    pub updated_at: Timestamp,
    pub private: SecretMaterial,
}
#[derive(Default, Serialize, Deserialize)]
pub struct Private {
    pub settings: BTreeMap<String, Value>,
    pub secrets: BTreeMap<String, String>,
}
#[derive(Deserialize)]
pub struct Update {
    pub enabled: bool,
    #[serde(default)]
    pub mock: bool,
    #[serde(default)]
    pub settings: BTreeMap<String, Value>,
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
    #[serde(default)]
    pub clear_secrets: Vec<String>,
    pub expected_version: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Probe {
    pub version: u64,
    pub checked_at: Timestamp,
    pub mocked: bool,
    pub tcp_reachable: Option<bool>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub note: String,
}
impl std::fmt::Debug for Stored {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredIntegration")
            .field("name", &self.name)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for Private {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntegrationPrivate")
            .field("secret_keys", &self.secrets.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for Update {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntegrationUpdate").field("version", &self.expected_version).finish_non_exhaustive()
    }
}
pub fn id(tenant: TenantId, name: &str) -> Id {
    deterministic_id("aiguardfabric.integration", &format!("{tenant}:{name}"))
}
pub fn vendor(name: &str) -> DomainResult<Box<dyn VendorAdapter>> {
    agf_adapters::vendors::builtin()
        .into_iter()
        .find(|vendor| vendor.name() == name)
        .ok_or_else(|| DomainError::NotFound { entity: "adapter", id: name.into() })
}
pub async fn load(state: &AppState, tenant: TenantId, name: &str) -> DomainResult<Option<Stored>> {
    vendor(name)?;
    state.configurations.get(tenant, KIND, id(tenant, name)).await
}
pub fn decrypt(state: &AppState, tenant: TenantId, row: &Stored) -> DomainResult<Private> {
    if row.id != id(tenant, &row.name) || row.private.aad.as_deref() != Some(&FieldCipher::make_aad(&tenant, &row.id)) {
        return Err(DomainError::Crypto("集成凭据租户绑定不匹配".into()));
    }
    let text = cipher(state)?.decrypt(&row.private)?;
    serde_json::from_str(text.expose_secret()).map_err(|_| DomainError::Config("集成配置解密后格式无效".into()))
}
pub fn adapter(
    state: &AppState,
    tenant: TenantId,
    row: &Stored,
    private: &Private,
) -> DomainResult<Box<dyn VendorAdapter>> {
    let mut adapter = vendor(&row.name)?;
    let mut secrets = StaticSecrets::new();
    for (key, value) in &private.secrets {
        secrets = secrets.with(key, value);
    }
    let config = AdapterConfig {
        id: row.id,
        tenant_id: tenant,
        adapter: row.name.clone(),
        display_name: row.name.clone(),
        enabled: row.enabled,
        settings: private.settings.clone(),
        secret_refs: BTreeMap::new(),
        circuit_breaker: CircuitBreakerConfig::default(),
        retry: RetryConfig::default(),
        timeout_secs: 10,
        mock: state.config.mock_mode || row.mock,
        is_default: true,
        created_at: row.updated_at,
        updated_at: row.updated_at,
    };
    let prepared = adapter.prepare(&config, &secrets)?;
    if row.enabled && !config.mock && !prepared.is_configured() {
        return Err(DomainError::Validation("请填写适配器所需设置和凭据后启用；也可保存为停用草稿".into()));
    }
    adapter.commit(prepared);
    Ok(adapter)
}
pub async fn view(state: &AppState, tenant: TenantId, name: &str) -> DomainResult<Value> {
    let metadata = vendor(name)?.metadata();
    let row = load(state, tenant, name).await?;
    let private = row.as_ref().map(|row| decrypt(state, tenant, row)).transpose()?.unwrap_or_default();
    let probe =
        state.configurations.get::<Probe>(tenant, "integration-probe", id(tenant, name)).await?.filter(|probe| {
            row.as_ref().is_some_and(|row| {
                row.enabled && row.version == probe.version && probe.mocked == (state.config.mock_mode || row.mock)
            })
        });
    Ok(json!({"name":name,"metadata":metadata,"enabled":row.as_ref().is_some_and(|row|row.enabled),
        "mock":row.as_ref().is_none_or(|row|row.mock),"environment_mock":state.config.mock_mode,
        "version":row.as_ref().map_or(0,|row|row.version),"updated_at":row.as_ref().map(|row|row.updated_at),
        "settings_json":serde_json::to_string_pretty(&private.settings)?,"secret_keys":private.secrets.keys().collect::<Vec<_>>(),"probe":probe}))
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
    let meta = vendor(name)?.metadata();
    let previous = load(state, tenant, name).await?;
    let mut private = previous.as_ref().map(|row| decrypt(state, tenant, row)).transpose()?.unwrap_or_default();
    let mut settings = body.settings;
    let mut supplied = body.secrets;
    let keys: Vec<_> = meta.required_secrets.iter().chain(&meta.optional_secrets).collect();
    for key in &keys {
        if let Some(value) = settings.remove(*key).and_then(|value| value.as_str().map(str::to_owned)) {
            if !value.is_empty() {
                supplied.insert((*key).clone(), value);
            }
        }
    }
    if supplied.keys().chain(&body.clear_secrets).any(|key| !keys.contains(&key)) {
        return Err(DomainError::Validation("存在未登记的凭据字段，请核对适配器字段名".into()));
    }
    let endpoint_changed = meta.endpoint_key.as_ref().is_some_and(|key| settings.get(key) != private.settings.get(key))
        || ["smtp_host", "smtp_port", "smtp_security", "api_base"]
            .iter()
            .any(|key| settings.get(*key) != private.settings.get(*key));
    let webhook_changed = supplied
        .get("webhook_url")
        .is_some_and(|value| !value.is_empty() && private.secrets.get("webhook_url") != Some(value));
    if endpoint_changed || webhook_changed {
        private.secrets.clear();
    }
    private.settings = settings;
    for key in &body.clear_secrets {
        private.secrets.remove(key);
    }
    for (key, value) in supplied {
        if !value.is_empty() {
            private.secrets.insert(key, value);
        }
    }
    let serialized = serde_json::to_string(&private)?;
    if serialized.len() > 32768 {
        return Err(DomainError::Validation("集成配置最多 32 KiB".into()));
    }
    let row = Stored {
        id: id(tenant, name),
        name: name.into(),
        enabled: body.enabled,
        mock: body.mock,
        version: body.expected_version.checked_add(1).ok_or_else(|| DomainError::Conflict("版本已达上限".into()))?,
        updated_at: Timestamp::now(),
        private: encrypt(state, tenant, id(tenant, name), serialized)?,
    };
    let _ = adapter(state, tenant, &row, &private)?;
    let apply = |current: &mut Option<Stored>| {
        if current.as_ref().map_or(0, |row| row.version) != body.expected_version {
            return Err(DomainError::Conflict("配置已被其他用户修改，请重新加载".into()));
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
            tracing::warn!(%error, "已提交的集成配置审计内存投影刷新失败");
        }
    } else if let Some(entry) = audit {
        state.store.audit_append_durable(entry).await?;
    }
    view(state, tenant, name).await
}

pub async fn snapshot(
    state: &AppState,
    tenant: TenantId,
) -> DomainResult<(Vec<AdapterMetadata>, BTreeMap<String, AdapterHealthRecord>)> {
    let metadata = agf_adapters::vendors::builtin().into_iter().map(|adapter| adapter.metadata()).collect::<Vec<_>>();
    let mut health = BTreeMap::new();
    for meta in &metadata {
        let mut adapter = vendor(&meta.name)?;
        let row = load(state, tenant, &meta.name).await?;
        if let Some(row) = &row {
            adapter = self::adapter(state, tenant, row, &decrypt(state, tenant, row)?)?;
        } else if state.config.mock_mode {
            adapter.force_mock();
        }
        let cached = if let Some(row) = &row {
            state.integration_runtime.health(tenant, &meta.name, row.version).await?
        } else {
            None
        };
        let mut record = if let Some(cached) = cached { cached } else { adapter.health_check().await? };
        if record.status == agf_adapters::health::HealthStatus::Available && record.total_success == 0 {
            record.status = agf_adapters::health::HealthStatus::Degraded;
            record.message = Some("配置已校验；列表不会主动调用外部服务，实际业务状态须根据调用回执确认".into());
        }
        health.insert(meta.name.clone(), record);
    }
    Ok((metadata, health))
}
