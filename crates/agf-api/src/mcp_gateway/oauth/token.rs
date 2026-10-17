//! Encrypted access/refresh tokens; refresh is scoped to the saved client and resource.
use super::{Configuration, TOKEN_KIND, denied, discovery, unavailable, unseal};
use crate::{Principal, model_gateway, state::AppState};
use agf_auth::oidc::ClientAuth;
use agf_core::{
    audit::{AuditAction, AuditOutcome, AuditTarget},
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Serialize, Deserialize)]
struct Stored {
    nonce: Id,
    config_revision: Id,
    expires_at: i64,
    sealed: SecretMaterial,
}

#[derive(Serialize, Deserialize)]
struct Secrets {
    access_token: String,
    refresh_token: Option<String>,
}

pub(super) struct Response {
    secrets: Secrets,
    expires_at: i64,
}

async fn request(
    state: &AppState,
    tenant: TenantId,
    id: Id,
    config: &Configuration,
    grant: &str,
    value: &str,
    verifier: Option<&str>,
) -> DomainResult<Response> {
    if config.client_secret_expires_at.is_some_and(|expiry| expiry <= Timestamp::now().unix_secs()) {
        return Err(DomainError::PreconditionFailed(
            "MCP 动态注册的 Client Secret 已到期；请重新保存 OAuth 配置后授权".into(),
        ));
    }
    let mut form = vec![
        ("grant_type", grant),
        (if verifier.is_some() { "code" } else { "refresh_token" }, value),
        ("resource", config.metadata.resource.as_str()),
    ];
    if let Some(verifier) = verifier {
        form.push(("redirect_uri", &config.redirect_uri));
        form.push(("code_verifier", verifier));
    }
    let client = discovery::client()?;
    let mut post = client.post(&config.metadata.token_endpoint);
    match config.client_auth {
        ClientAuth::ClientSecretBasic => {
            let secret = config.client_secret.as_ref().ok_or_else(denied)?;
            let secret = unseal(state, tenant, id, secret)?;
            let encode = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
            post = post.basic_auth(encode(&config.client_id), Some(encode(&secret)));
        }
        ClientAuth::ClientSecretPost => {
            let secret = config.client_secret.as_ref().ok_or_else(denied)?;
            let secret = unseal(state, tenant, id, secret)?;
            // Keep the owned secret alive until reqwest has serialized the form.
            let mut fields: Vec<(String, String)> =
                form.iter().map(|(key, value)| ((*key).into(), (*value).into())).collect();
            fields.push(("client_id".into(), config.client_id.clone()));
            fields.push(("client_secret".into(), secret));
            return parse(discovery::json(post.form(&fields).send().await.map_err(|_| unavailable())?).await?);
        }
        ClientAuth::None => form.push(("client_id", &config.client_id)),
    }
    parse(discovery::json(post.form(&form).send().await.map_err(|_| unavailable())?).await?)
}

fn parse(value: Value) -> DomainResult<Response> {
    let token = value["access_token"].as_str().filter(|token| valid_token(token)).ok_or_else(unavailable)?;
    if !value["token_type"].as_str().is_some_and(|kind| kind.eq_ignore_ascii_case("Bearer")) {
        return Err(unavailable());
    }
    let seconds =
        value["expires_in"].as_i64().filter(|seconds| (1..=86_400).contains(seconds)).ok_or_else(unavailable)?;
    let refresh_token = value["refresh_token"].as_str().map(str::to_owned);
    if refresh_token.as_deref().is_some_and(|token| !valid_token(token)) {
        return Err(unavailable());
    }
    Ok(Response {
        secrets: Secrets { access_token: token.into(), refresh_token },
        expires_at: Timestamp::now().unix_secs() + seconds,
    })
}

fn valid_token(value: &str) -> bool {
    !value.is_empty() && value.len() <= 8192 && value.bytes().all(|b| (33..=126).contains(&b))
}

pub(super) async fn exchange_code(
    state: &AppState,
    tenant: TenantId,
    id: Id,
    config: &Configuration,
    code: &str,
    verifier: &str,
) -> DomainResult<Response> {
    request(state, tenant, id, config, "authorization_code", code, Some(verifier)).await
}

pub(super) async fn save(
    state: &AppState,
    principal: &Principal,
    id: Id,
    revision: Id,
    response: Response,
) -> DomainResult<()> {
    let tenant = principal.tenant;
    let row = Stored {
        nonce: Id::new(),
        config_revision: revision,
        expires_at: response.expires_at,
        sealed: model_gateway::encrypt(state, tenant, id, serde_json::to_string(&response.secrets)?)?,
    };
    let entry = AppState::audit_entry(
        tenant,
        AuditAction::Configure,
        AuditOutcome::Success,
        AppState::audit_actor(principal, "mcp-oauth"),
        AuditTarget::new("mcp-oauth-connection", Some(id.to_string()), None),
        "MCP OAuth 授权成功；令牌已加密保存",
    );
    let (_, sealed) = state
        .configurations
        .mutate_audited::<Option<Stored>, _>(tenant, TOKEN_KIND, id, entry.clone(), |current| {
            *current = Some(row.clone());
            Ok(())
        })
        .await?;
    append_audit(state, entry, sealed).await
}

async fn append_audit(
    state: &AppState,
    entry: agf_core::audit::AuditLog,
    sealed: Option<agf_core::audit::AuditLog>,
) -> DomainResult<()> {
    if let Some(sealed) = sealed {
        if let Err(error) = state.store.hydrate_audit(&sealed) {
            tracing::warn!(%error, "已提交的 MCP OAuth 审计内存投影刷新失败");
        }
        Ok(())
    } else {
        state.store.audit_append_durable(entry).await.map(|_| ())
    }
}

pub(crate) async fn connected(
    state: &AppState,
    tenant: TenantId,
    id: Id,
    config: &Configuration,
) -> DomainResult<Value> {
    let row: Option<Stored> = state.configurations.get::<Option<Stored>>(tenant, TOKEN_KIND, id).await?.flatten();
    let valid = row.as_ref().filter(|row| row.config_revision == config.revision);
    let refreshable = valid
        .map(|row| unseal(state, tenant, id, &row.sealed))
        .transpose()?
        .and_then(|value| serde_json::from_str::<Secrets>(&value).ok())
        .is_some_and(|secrets| secrets.refresh_token.is_some());
    Ok(json!({"connected":valid.is_some_and(|row| row.expires_at > Timestamp::now().unix_secs() || refreshable),
        "expires_at":valid.map(|row| row.expires_at),"refreshable":refreshable}))
}

pub(crate) async fn credential(
    state: &AppState,
    tenant: TenantId,
    endpoint: &super::super::config::Endpoint,
) -> DomainResult<Option<String>> {
    let Some(config) = super::get(state, tenant, endpoint.id).await? else {
        return super::super::config::credential(state, tenant, endpoint);
    };
    if config.endpoint_url != endpoint.url || endpoint.secret.is_some() {
        return Err(DomainError::PreconditionFailed(
            "MCP OAuth 与端点 URL 或固定 Bearer 配置不匹配，请重新连接".into(),
        ));
    }
    let row: Stored = state
        .configurations
        .get::<Option<Stored>>(tenant, TOKEN_KIND, endpoint.id)
        .await?
        .flatten()
        .filter(|row: &Stored| row.config_revision == config.revision)
        .ok_or_else(|| {
            DomainError::PreconditionFailed("MCP OAuth 尚未连接；请管理员在 HTTP 接入配置中完成授权".into())
        })?;
    let secrets: Secrets = serde_json::from_str(&unseal(state, tenant, endpoint.id, &row.sealed)?)?;
    if row.expires_at > Timestamp::now().unix_secs() + 30 {
        return Ok(Some(secrets.access_token));
    }
    let refresh = secrets
        .refresh_token
        .as_deref()
        .ok_or_else(|| DomainError::PreconditionFailed("MCP OAuth 访问令牌已过期且无刷新令牌，请重新授权".into()))?;
    let mut response = request(state, tenant, endpoint.id, &config, "refresh_token", refresh, None).await?;
    if response.secrets.refresh_token.is_none() {
        response.secrets.refresh_token = Some(refresh.into());
    }
    let access = response.secrets.access_token.clone();
    let current = super::get(state, tenant, endpoint.id).await?;
    if current.as_ref().map(|row| row.revision) != Some(config.revision) {
        return Err(denied());
    }
    let updated = Stored {
        nonce: Id::new(),
        config_revision: config.revision,
        expires_at: response.expires_at,
        sealed: model_gateway::encrypt(state, tenant, endpoint.id, serde_json::to_string(&response.secrets)?)?,
    };
    let changed = state
        .configurations
        .mutate::<Option<Stored>, _>(tenant, TOKEN_KIND, endpoint.id, |current| {
            if current.as_ref().map(|token| token.nonce) != Some(row.nonce) {
                return Err(DomainError::Conflict("MCP OAuth 令牌已由另一请求刷新".into()));
            }
            *current = Some(updated.clone());
            Ok(())
        })
        .await;
    match changed {
        Ok(_) => Ok(Some(access)),
        Err(DomainError::Conflict(_)) => {
            let latest: Option<Stored> =
                state.configurations.get::<Option<Stored>>(tenant, TOKEN_KIND, endpoint.id).await?.flatten();
            let latest = latest
                .filter(|next| {
                    next.config_revision == config.revision && next.expires_at > Timestamp::now().unix_secs() + 5
                })
                .ok_or_else(denied)?;
            let payload: Secrets = serde_json::from_str(&unseal(state, tenant, endpoint.id, &latest.sealed)?)?;
            Ok(Some(payload.access_token))
        }
        Err(error) => Err(error),
    }
}

pub(crate) async fn disconnect(state: &AppState, principal: &Principal, id: Id) -> DomainResult<Value> {
    super::super::config::get(state, principal.tenant, id).await?;
    let entry = AppState::audit_entry(
        principal.tenant,
        AuditAction::Configure,
        AuditOutcome::Success,
        AppState::audit_actor(principal, "mcp-oauth"),
        AuditTarget::new("mcp-oauth-connection", Some(id.to_string()), None),
        "断开 MCP OAuth；已移除平台保存的令牌",
    );
    let (_, sealed) = state
        .configurations
        .mutate_audited::<Option<Stored>, _>(principal.tenant, TOKEN_KIND, id, entry.clone(), |current| {
            *current = None;
            Ok(())
        })
        .await?;
    append_audit(state, entry, sealed).await?;
    Ok(json!({"connected":false}))
}
