//! Browser-bound, single-use S256 authorization transaction.
use super::{Configuration, FLOW_KIND, denied, invalid, token, unseal};
use crate::{Principal, model_gateway, state::AppState};
use agf_auth::oidc;
use agf_core::{
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::Id,
    secret::generate_token,
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Serialize, Deserialize)]
struct Flow {
    endpoint_id: Id,
    config_revision: Id,
    started_by: Id,
    session_id: String,
    expires_at: i64,
    phase: String,
    sealed: SecretMaterial,
}

#[derive(Serialize, Deserialize)]
struct Secrets {
    binding_hash: String,
    verifier: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Complete {
    pub state: Id,
    pub binding: String,
    pub code: String,
    pub iss: Option<String>,
}

fn ready<'a>(
    principal: &Principal,
    endpoint: &super::super::config::Endpoint,
    config: &'a Configuration,
) -> DomainResult<&'a Configuration> {
    if !endpoint.enabled || endpoint.url != config.endpoint_url {
        return Err(DomainError::PreconditionFailed("MCP 端点已停用或 URL 已变化，请重新配置 OAuth".into()));
    }
    if principal.subject_id.is_none() || principal.session_id.is_none() {
        return Err(DomainError::PreconditionFailed("请使用管理员的网页登录会话完成 MCP OAuth 授权".into()));
    }
    Ok(config)
}

pub(crate) async fn start(state: &AppState, principal: &Principal, id: Id) -> DomainResult<Value> {
    let endpoint = super::super::config::get(state, principal.tenant, id).await?;
    let config = super::get(state, principal.tenant, id)
        .await?
        .ok_or_else(|| DomainError::PreconditionFailed("请先保存此 MCP 端点的 OAuth 客户端配置".into()))?;
    let config = ready(principal, &endpoint, &config)?;
    state.configurations.purge_expired(principal.tenant, FLOW_KIND, Timestamp::now().unix_secs()).await?;
    let flow_id = Id::new();
    let binding = generate_token();
    let verifier = generate_token();
    let mut url = oidc::endpoint(&config.metadata.authorization_endpoint)?;
    let reserved = [
        "response_type",
        "client_id",
        "redirect_uri",
        "state",
        "scope",
        "resource",
        "code_challenge",
        "code_challenge_method",
    ];
    if url.query_pairs().any(|(key, _)| reserved.contains(&key.as_ref())) {
        return Err(invalid("MCP OAuth 授权地址含重复协议参数"));
    }
    url.query_pairs_mut().extend_pairs([
        ("response_type", "code"),
        ("client_id", config.client_id.as_str()),
        ("redirect_uri", config.redirect_uri.as_str()),
        ("state", &flow_id.to_string()),
        ("resource", config.metadata.resource.as_str()),
        ("code_challenge", &oidc::challenge(&verifier)),
        ("code_challenge_method", "S256"),
    ]);
    if !config.scope.is_empty() {
        url.query_pairs_mut().append_pair("scope", &config.scope);
    }
    let secrets = Secrets { binding_hash: oidc::challenge(&binding), verifier };
    let flow = Flow {
        endpoint_id: id,
        config_revision: config.revision,
        started_by: principal.subject_id.ok_or_else(denied)?,
        session_id: principal.session_id.clone().ok_or_else(denied)?,
        expires_at: Timestamp::now().unix_secs() + 600,
        phase: "pending".into(),
        sealed: model_gateway::encrypt(state, principal.tenant, flow_id, serde_json::to_string(&secrets)?)?,
    };
    state.configurations.put(principal.tenant, FLOW_KIND, flow_id, &flow).await?;
    Ok(json!({"authorization_url":url.as_str(),"state":flow_id,"binding":binding,"redirect_uri":config.redirect_uri}))
}

pub(crate) async fn complete(state: &AppState, principal: &Principal, id: Id, body: Complete) -> DomainResult<Value> {
    if !(32..=256).contains(&body.binding.len()) || body.code.is_empty() || body.code.len() > 8192 {
        return Err(denied());
    }
    let endpoint = super::super::config::get(state, principal.tenant, id).await?;
    let config = super::get(state, principal.tenant, id).await?.ok_or_else(denied)?;
    let config = ready(principal, &endpoint, &config)?;
    if body.iss.as_deref().is_some_and(|issuer| issuer != config.metadata.issuer)
        || (config.metadata.response_iss_supported && body.iss.as_deref() != Some(&config.metadata.issuer))
    {
        return Err(denied());
    }
    let flow: Option<Flow> = state
        .configurations
        .mutate(principal.tenant, FLOW_KIND, body.state, |flow: &mut Option<Flow>| {
            let flow = flow.as_mut().ok_or_else(denied)?;
            if flow.endpoint_id != id
                || flow.config_revision != config.revision
                || principal.subject_id != Some(flow.started_by)
                || principal.session_id.as_deref() != Some(&flow.session_id)
                || flow.expires_at <= Timestamp::now().unix_secs()
                || flow.phase != "pending"
            {
                return Err(denied());
            }
            let secrets: Secrets = serde_json::from_str(&unseal(state, principal.tenant, body.state, &flow.sealed)?)?;
            if secrets.binding_hash != oidc::challenge(&body.binding) {
                return Err(denied());
            }
            flow.phase = "exchanging".into();
            Ok(())
        })
        .await?;
    let flow = flow.ok_or_else(denied)?;
    let secrets: Secrets = serde_json::from_str(&unseal(state, principal.tenant, body.state, &flow.sealed)?)?;
    let response = token::exchange_code(state, principal.tenant, id, config, &body.code, &secrets.verifier).await?;
    if super::get(state, principal.tenant, id).await?.as_ref().map(|row| row.revision) != Some(config.revision) {
        return Err(denied());
    }
    token::save(state, principal, id, config.revision, response).await?;
    state.configurations.delete(principal.tenant, FLOW_KIND, body.state).await?;
    Ok(json!({"connected":true}))
}
