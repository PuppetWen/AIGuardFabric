//! Versioned MCP OAuth client registration, pinned to an endpoint URL and tenant.
use super::{CONFIG_KIND, client_metadata, discovery, dynamic_registration, invalid};
use crate::{Principal, model_gateway, state::AppState};
use agf_auth::oidc::{self, ClientAuth};
use agf_core::{
    audit::{AuditAction, AuditOutcome, AuditTarget},
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Registration {
    #[default]
    PreRegistered,
    ClientIdMetadata,
    Dynamic,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Configuration {
    pub revision: Id,
    #[serde(default)]
    pub registration: Registration,
    pub endpoint_url: String,
    pub metadata: discovery::Metadata,
    pub client_id: String,
    pub client_auth: ClientAuth,
    pub client_secret: Option<SecretMaterial>,
    #[serde(default)]
    pub client_secret_expires_at: Option<i64>,
    #[serde(default)]
    pub requested_client_auth: Option<ClientAuth>,
    pub scope: String,
    pub redirect_uri: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    pub expected_revision: Option<Id>,
    #[serde(default)]
    pub registration: Registration,
    pub issuer: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_auth: ClientAuth,
    pub client_secret: Option<String>,
    #[serde(default)]
    pub registration_access_token: Option<String>,
    #[serde(default)]
    pub scope: String,
    pub redirect_uri: String,
}

pub(super) fn auth_method(value: ClientAuth) -> &'static str {
    match value {
        ClientAuth::ClientSecretBasic => "client_secret_basic",
        ClientAuth::ClientSecretPost => "client_secret_post",
        ClientAuth::None => "none",
    }
}

pub(crate) async fn get(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Option<Configuration>> {
    state.configurations.get(tenant, CONFIG_KIND, id).await
}

pub(crate) fn public(value: &Configuration) -> Value {
    json!({"revision":value.revision,"registration":value.registration,"endpoint_url":value.endpoint_url,
        "issuer":value.metadata.issuer,"resource":value.metadata.resource,
        "client_id":value.client_id,"client_auth":value.client_auth,
        "requested_client_auth":value.requested_client_auth,
        "scope":value.scope,"redirect_uri":value.redirect_uri,
        "client_secret_configured":value.client_secret.is_some(),
        "client_secret_expires_at":value.client_secret_expires_at})
}

pub(crate) async fn save(state: &AppState, principal: &Principal, id: Id, body: Input) -> DomainResult<Configuration> {
    let endpoint = super::super::config::get(state, principal.tenant, id).await?;
    if endpoint.secret.is_some() {
        return Err(invalid("先在端点配置中清除固定 Bearer token，再启用交互式 OAuth"));
    }
    if body.scope.len() > 1024
        || body.scope.chars().any(char::is_control)
        || body.client_secret.as_ref().is_some_and(|value| value.len() > 8192)
        || body
            .registration_access_token
            .as_ref()
            .is_some_and(|value| value.len() > 8192 || value.bytes().any(|byte| !(33..=126).contains(&byte)))
    {
        return Err(invalid("scope 最长 1024 字节，Client Secret 最长 8192 字节"));
    }
    let callback = oidc::endpoint(&body.redirect_uri)?;
    if callback.path() != "/mcp/oauth/callback" || callback.query().is_some() {
        return Err(invalid("MCP OAuth 回调地址须为控制台 HTTPS 地址加 /mcp/oauth/callback，不带查询参数"));
    }
    if body.registration == Registration::ClientIdMetadata && callback.scheme() != "https" {
        return Err(invalid("托管 Client ID 元数据需要公开可访问的 HTTPS 控制台回调地址"));
    }
    match body.registration {
        Registration::PreRegistered if body.client_id.is_empty() || body.client_id.len() > 512 => {
            return Err(invalid("预注册 OAuth 客户端必须填写不超过 512 字节的 Client ID"));
        }
        Registration::ClientIdMetadata | Registration::Dynamic
            if !body.client_id.is_empty()
                || (body.registration == Registration::ClientIdMetadata && body.client_auth != ClientAuth::None)
                || body.client_secret.as_ref().is_some_and(|secret| !secret.is_empty()) =>
        {
            return Err(invalid("自动注册方式由平台获取 Client ID 和密钥，不能手工填写"));
        }
        _ => {}
    }
    if body.registration != Registration::Dynamic
        && body.registration_access_token.as_ref().is_some_and(|value| !value.is_empty())
    {
        return Err(invalid("初始注册令牌只用于动态客户端注册"));
    }
    let old = get(state, principal.tenant, id).await?;
    if old.as_ref().map(|row| row.revision) != body.expected_revision {
        return Err(DomainError::Conflict("MCP OAuth 配置已变更，请刷新后比较".into()));
    }
    let scope = body.scope.split_whitespace().collect::<Vec<_>>().join(" ");
    if let Some(previous) = old.as_ref().filter(|row| {
        body.registration == Registration::Dynamic
            && row.registration == Registration::Dynamic
            && row.endpoint_url == endpoint.url
            && row.metadata.issuer == body.issuer
            && row.redirect_uri == body.redirect_uri
            && row.scope == scope
            && row.requested_client_auth == Some(body.client_auth)
            && body.registration_access_token.as_ref().is_none_or(String::is_empty)
            && row
                .client_secret_expires_at
                .is_none_or(|expiry| expiry > agf_core::time::Timestamp::now().unix_secs() + 60)
    }) {
        return Ok(previous.clone());
    }
    let retained_secret = if body.registration != Registration::PreRegistered || body.client_auth == ClientAuth::None {
        None
    } else if let Some(value) = body.client_secret.filter(|value| !value.is_empty()) {
        Some(model_gateway::encrypt(state, principal.tenant, id, value)?)
    } else {
        old.as_ref()
            .filter(|row| {
                row.registration == Registration::PreRegistered
                    && row.metadata.issuer == body.issuer
                    && row.client_id == body.client_id
                    && row.client_auth == body.client_auth
                    && row.endpoint_url == endpoint.url
            })
            .and_then(|row| row.client_secret.clone())
    };
    if body.registration == Registration::PreRegistered
        && body.client_auth != ClientAuth::None
        && retained_secret.is_none()
    {
        return Err(invalid("机密 OAuth 客户端必须填写 Client Secret"));
    }
    let metadata = discovery::discover(
        &endpoint.url,
        &body.issuer,
        auth_method(body.client_auth),
        body.registration == Registration::ClientIdMetadata,
        body.registration == Registration::Dynamic,
    )
    .await?;
    let revision = Id::new();
    let (client_id, client_auth, client_secret, client_secret_expires_at, requested_client_auth) = match body
        .registration
    {
        Registration::PreRegistered => (body.client_id, body.client_auth, retained_secret, None, None),
        Registration::ClientIdMetadata => (
            client_metadata::client_id(state, principal.tenant, id, revision, &callback)?,
            ClientAuth::None,
            None,
            None,
            None,
        ),
        Registration::Dynamic => {
            let registered = dynamic_registration::register(
                &metadata,
                &body.redirect_uri,
                &scope,
                body.client_auth,
                body.registration_access_token.as_deref().filter(|value| !value.is_empty()),
            )
            .await?;
            let secret = registered
                .client_secret
                .map(|value| model_gateway::encrypt(state, principal.tenant, id, value))
                .transpose()?;
            (registered.client_id, registered.client_auth, secret, registered.secret_expires_at, Some(body.client_auth))
        }
    };
    let stored = Configuration {
        revision,
        registration: body.registration,
        endpoint_url: endpoint.url,
        metadata,
        client_id,
        client_auth,
        client_secret,
        client_secret_expires_at,
        requested_client_auth,
        scope,
        redirect_uri: body.redirect_uri,
    };
    let entry = AppState::audit_entry(
        principal.tenant,
        AuditAction::Configure,
        AuditOutcome::Success,
        AppState::audit_actor(principal, "mcp-oauth"),
        AuditTarget::new("mcp-oauth-client", Some(id.to_string()), None),
        "更新 MCP OAuth 客户端配置；旧令牌不再适用于新版本",
    );
    let (_, sealed) = state
        .configurations
        .mutate_audited::<Option<Configuration>, _>(principal.tenant, CONFIG_KIND, id, entry.clone(), |current| {
            if current.as_ref().map(|row| row.revision) != body.expected_revision {
                return Err(DomainError::Conflict("MCP OAuth 配置已变更，请刷新后比较".into()));
            }
            *current = Some(stored.clone());
            Ok(())
        })
        .await?;
    if let Some(sealed) = sealed {
        if let Err(error) = state.store.hydrate_audit(&sealed) {
            tracing::warn!(%error, "已提交的 MCP OAuth 配置审计内存投影刷新失败");
        }
    } else {
        state.store.audit_append_durable(entry).await?;
    }
    Ok(stored)
}
