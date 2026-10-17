//! Backwards-compatible RFC 7591 registration for servers without Client ID metadata support.
use super::{discovery, invalid, unavailable};
use agf_auth::oidc::ClientAuth;
use agf_core::error::DomainResult;
use agf_core::time::Timestamp;
use serde_json::{Value, json};

pub(super) struct Registered {
    pub client_id: String,
    pub client_auth: ClientAuth,
    pub client_secret: Option<String>,
    pub secret_expires_at: Option<i64>,
}

fn printable(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && value.bytes().all(|byte| (32..=126).contains(&byte))
}

fn method(value: &str) -> DomainResult<ClientAuth> {
    match value {
        "none" => Ok(ClientAuth::None),
        "client_secret_basic" => Ok(ClientAuth::ClientSecretBasic),
        "client_secret_post" => Ok(ClientAuth::ClientSecretPost),
        _ => Err(unavailable()),
    }
}

fn has(value: &Value, key: &str, wanted: &str) -> bool {
    value[key].as_array().is_some_and(|values| values.iter().any(|item| item == wanted))
}

pub(super) async fn register(
    metadata: &discovery::Metadata,
    redirect_uri: &str,
    scope: &str,
    requested_auth: ClientAuth,
    initial_access_token: Option<&str>,
) -> DomainResult<Registered> {
    let endpoint = metadata.registration_endpoint.as_ref().ok_or_else(unavailable)?;
    let requested_method = super::store::auth_method(requested_auth);
    let mut payload = json!({
        "client_name":"AIGuardFabric MCP Gateway",
        "redirect_uris":[redirect_uri],
        "grant_types":["authorization_code","refresh_token"],
        "response_types":["code"],
        "token_endpoint_auth_method":requested_method,
        "application_type":"web"
    });
    if !scope.is_empty() {
        payload["scope"] = json!(scope);
    }
    let client = discovery::client()?;
    let mut request = client.post(endpoint).json(&payload);
    if let Some(token) = initial_access_token {
        request = request.bearer_auth(token);
    }
    let response = discovery::json(request.send().await.map_err(|_| unavailable())?).await?;
    let client_id = response["client_id"].as_str().filter(|id| printable(id, 512)).ok_or_else(unavailable)?;
    if !has(&response, "redirect_uris", redirect_uri)
        || response["grant_types"].as_array().is_some_and(|_| !has(&response, "grant_types", "authorization_code"))
        || response["response_types"].as_array().is_some_and(|_| !has(&response, "response_types", "code"))
    {
        return Err(invalid("MCP 动态注册响应未确认所需的回调 URI 或授权码流程"));
    }
    let auth = method(response["token_endpoint_auth_method"].as_str().unwrap_or("client_secret_basic"))?;
    let secret = response["client_secret"].as_str();
    if auth != ClientAuth::None && !secret.is_some_and(|secret| printable(secret, 8192)) {
        return Err(invalid("MCP 动态注册返回的机密客户端缺少有效 Client Secret"));
    }
    let expires = if auth == ClientAuth::None {
        None
    } else {
        match response["client_secret_expires_at"].as_i64() {
            Some(0) | None => None,
            Some(expires) if expires > Timestamp::now().unix_secs() + 30 => Some(expires),
            _ => return Err(invalid("MCP 动态注册返回的 Client Secret 已到期")),
        }
    };
    Ok(Registered {
        client_id: client_id.into(),
        client_auth: auth,
        client_secret: if auth == ClientAuth::None { None } else { secret.map(str::to_owned) },
        secret_expires_at: expires,
    })
}
