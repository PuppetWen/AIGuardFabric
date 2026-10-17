//! Versioned endpoint configuration; secrets never appear in management responses.
use super::invalid;
use crate::store::asset_transaction::AssetTransaction;
use crate::{
    model_gateway::{cipher, encrypt},
    model_routes::tenant_record_id,
    state::AppState,
};
use agf_asset::service::AssetBackend;
use agf_core::{
    audit::{AuditAction, AuditActor, AuditLog, AuditOutcome, AuditTarget},
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use agf_storage::crypto::FieldCipher;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(super) const KIND: &str = "mcp-http-endpoints";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    #[default]
    StreamableHttp,
    LegacySse,
}

impl Transport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StreamableHttp => "streamable-http",
            Self::LegacySse => "legacy-sse",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub id: Id,
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub transport: Transport,
    pub enabled: bool,
    pub version: u64,
    pub idle_timeout_secs: u64,
    pub allowed_origins: Vec<String>,
    pub updated_at: Timestamp,
    pub secret: Option<SecretMaterial>,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("id", &self.id)
            .field("version", &self.version)
            .field("credential_configured", &self.secret.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Default, Serialize, Deserialize)]
pub(super) struct Registry {
    pub(super) entries: BTreeMap<Id, Endpoint>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub id: Option<Id>,
    pub expected_version: u64,
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub transport: Transport,
    pub enabled: bool,
    pub idle_timeout_secs: u64,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// None preserves a credential only while the URL is unchanged; an empty string removes it.
    pub bearer_token: Option<String>,
}

impl std::fmt::Debug for Input {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Input")
            .field("id", &self.id)
            .field("expected_version", &self.expected_version)
            .field("credential_supplied", &self.bearer_token.is_some())
            .finish_non_exhaustive()
    }
}

pub async fn list(state: &AppState, tenant: TenantId) -> DomainResult<Vec<Endpoint>> {
    let registry: Registry =
        state.configurations.get(tenant, KIND, tenant_record_id(tenant)).await?.unwrap_or_default();
    Ok(registry.entries.into_values().collect())
}

pub async fn get(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Endpoint> {
    list(state, tenant)
        .await?
        .into_iter()
        .find(|row| row.id == id)
        .ok_or_else(|| DomainError::NotFound { entity: "mcp-endpoint", id: id.to_string() })
}

pub fn public(row: &Endpoint) -> serde_json::Value {
    serde_json::json!({"id":row.id,"name":row.name,"url":row.url,"transport":row.transport.as_str(),"enabled":row.enabled,
        "version":row.version,"idle_timeout_secs":row.idle_timeout_secs,"allowed_origins":row.allowed_origins,
        "updated_at":row.updated_at,"credential_configured":row.secret.is_some()})
}

pub async fn save(state: &AppState, tenant: TenantId, input: Input, actor: AuditActor) -> DomainResult<Endpoint> {
    let url = url::Url::parse(&input.url).map_err(|_| invalid("请输入完整的 MCP HTTP(S) 端点 URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || input.url.len() > 2048
    {
        return Err(invalid("MCP 地址仅允许 HTTP(S)，不能携带凭据、查询参数或片段；凭据请单独填写"));
    }
    if input.name.trim().is_empty() || input.name.len() > 160 || !(5..=600).contains(&input.idle_timeout_secs) {
        return Err(invalid("请输入名称（最长 160 字节）及 5..600 秒空闲超时"));
    }
    if input.allowed_origins.len() > 16
        || input.allowed_origins.iter().any(|value| {
            !url::Url::parse(value).is_ok_and(|origin| {
                matches!(origin.scheme(), "http" | "https") && origin.origin().ascii_serialization() == *value
            })
        })
    {
        return Err(invalid("来源须为完整且精确的 HTTP(S) Origin，不含路径、通配符或末尾斜线"));
    }
    let id = input.id.unwrap_or_default();
    if id == tenant_record_id(tenant) {
        return Err(invalid("端点 ID 不能使用当前租户的保留标识，请省略 id 创建新端点"));
    }
    let secret = match &input.bearer_token {
        Some(token) if token.is_empty() => Some(None),
        Some(token) => {
            if token.len() > 8192 || !token.bytes().all(|b| (33..=126).contains(&b)) {
                return Err(invalid("Bearer token 不能包含空格、换行或非 ASCII 字符，最长 8192 字节"));
            }
            Some(Some(encrypt(state, tenant, id, token.clone())?))
        }
        None => None,
    };
    let apply = |registry: &mut Registry| {
        let old = registry.entries.get(&id);
        if old.map_or(0, |row| row.version) != input.expected_version {
            return Err(DomainError::Conflict("配置已被更新，请刷新后比较并重新保存".into()));
        }
        if old.is_none() && registry.entries.len() >= 128 {
            return Err(invalid("每个租户最多 128 个 MCP HTTP 端点"));
        }
        if old.is_some_and(|row| row.url != url.as_str() && row.secret.is_some()) && input.bearer_token.is_none() {
            return Err(invalid("更换 MCP 目标地址时，请重新填写 Bearer token，或显式清空旧凭据"));
        }
        let row = Endpoint {
            id,
            name: input.name.trim().into(),
            url: url.to_string(),
            transport: input.transport,
            enabled: input.enabled,
            version: input.expected_version + 1,
            idle_timeout_secs: input.idle_timeout_secs,
            allowed_origins: input.allowed_origins.clone(),
            updated_at: Timestamp::now(),
            secret: secret.clone().unwrap_or_else(|| old.and_then(|row| row.secret.clone())),
        };
        registry.entries.insert(id, row);
        Ok(())
    };
    let saved = if let Some(db) = state.store.database() {
        let backend = AssetTransaction::begin(db, tenant).await?;
        let mut registry: Registry = backend.configuration(KIND, tenant_record_id(tenant)).await?.unwrap_or_default();
        apply(&mut registry)?;
        let row =
            registry.entries.get(&id).ok_or_else(|| DomainError::Internal("Saved MCP endpoint missing".into()))?;
        let snapshot: Option<super::discovery::Snapshot> = backend.configuration(super::discovery::KIND, id).await?;
        let asset = super::discovery::project(backend.find(tenant, id).await?, tenant, row, snapshot.as_ref())?;
        backend.upsert(tenant, &asset).await?;
        backend.configure(KIND, tenant_record_id(tenant), Some(serde_json::to_value(&registry)?)).await?;
        backend.audit(success_audit(tenant, actor, row)).await?;
        backend.commit(&state.store).await?;
        registry
    } else {
        let registry =
            state.configurations.mutate::<Registry, _>(tenant, KIND, tenant_record_id(tenant), apply).await?;
        if let Some(row) = registry.entries.get(&id) {
            super::discovery::register(state, tenant, row).await?;
            state.store.audit_append_durable(success_audit(tenant, actor, row)).await?;
        }
        registry
    };
    saved
        .entries
        .into_values()
        .find(|row| row.id == id)
        .ok_or_else(|| DomainError::Internal("Saved MCP endpoint missing from transaction result".into()))
}

fn success_audit(tenant: TenantId, actor: AuditActor, row: &Endpoint) -> AuditLog {
    AuditLog {
        id: Id::new(),
        tenant_id: tenant,
        sequence: 0,
        action: AuditAction::Configure,
        outcome: AuditOutcome::Success,
        actor,
        target: AuditTarget::new("mcp-http-endpoint", Some(row.id.to_string()), Some(row.name.clone())),
        before: None,
        after: None,
        changed_fields: Vec::new(),
        request_id: crate::error::current_request_id(),
        error: None,
        note: format!(
            "Saved MCP HTTP endpoint version {}; enabled={}; credentials encrypted",
            row.version, row.enabled
        ),
        prev_hash: String::new(),
        entry_hash: String::new(),
        at: Timestamp::now(),
    }
}

pub fn credential(state: &AppState, tenant: TenantId, row: &Endpoint) -> DomainResult<Option<String>> {
    row.secret
        .as_ref()
        .map(|secret| {
            if secret.aad.as_deref() != Some(&FieldCipher::make_aad(&tenant, &row.id)) {
                return Err(DomainError::Crypto("MCP 凭据绑定不匹配".into()));
            }
            Ok(cipher(state)?.decrypt(secret)?.expose_secret().to_string())
        })
        .transpose()
}
