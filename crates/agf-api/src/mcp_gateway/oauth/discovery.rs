//! RFC 9728 protected resource and RFC 8414 / OIDC authorization-server discovery.
use super::{invalid, unavailable};
use agf_auth::oidc;
use agf_core::error::DomainResult;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use url::Url;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Metadata {
    pub resource: String,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub response_iss_supported: bool,
    #[serde(default)]
    pub client_id_metadata_document_supported: bool,
    #[serde(default)]
    pub registration_endpoint: Option<String>,
}

pub(super) fn client() -> DomainResult<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(12))
        .build()
        .map_err(|_| unavailable())
}

pub(super) async fn json(mut response: reqwest::Response) -> DomainResult<Value> {
    if !response.status().is_success() {
        return Err(unavailable());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| unavailable())? {
        if bytes.len() + chunk.len() > 65_536 {
            return Err(unavailable());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| unavailable())
}

fn well_known(resource: &Url, suffix: &str, at_origin: bool) -> String {
    let mut url = resource.clone();
    url.set_query(None);
    url.set_fragment(None);
    let path = if at_origin { String::new() } else { resource.path().trim_end_matches('/').to_owned() };
    url.set_path(&format!("/.well-known/{suffix}{path}"));
    url.into()
}

async fn challenged_resource(http: &reqwest::Client, endpoint: &Url) -> DomainResult<Option<Value>> {
    let response = http.head(endpoint.as_str()).send().await.map_err(|_| unavailable())?;
    if response.status() != reqwest::StatusCode::UNAUTHORIZED {
        return Ok(None);
    }
    let header = response.headers().get("www-authenticate").and_then(|value| value.to_str().ok()).unwrap_or_default();
    let lower = header.to_ascii_lowercase();
    let marker = "resource_metadata=\"";
    let Some(start) = lower.find(marker).filter(|_| lower.starts_with("bearer ")) else {
        return Ok(None);
    };
    let url = header[start + marker.len()..].split('"').next().unwrap_or_default();
    let metadata_url = oidc::endpoint(url)?;
    if metadata_url.origin() != endpoint.origin() {
        return Err(invalid("MCP OAuth 401 挑战中的资源元数据地址必须与上游端点同源"));
    }
    let value = json(http.get(metadata_url).send().await.map_err(|_| unavailable())?).await?;
    Ok(Some(value))
}

pub(crate) async fn discover(
    upstream: &str,
    issuer: &str,
    client_auth: &str,
    require_client_metadata: bool,
    require_dynamic_registration: bool,
) -> DomainResult<Metadata> {
    let endpoint = oidc::endpoint(upstream)?;
    if endpoint.query().is_some() {
        return Err(invalid("MCP OAuth 资源地址不能包含查询参数"));
    }
    let issuer_url = oidc::endpoint(issuer)?;
    if issuer_url.query().is_some() || issuer_url.fragment().is_some() {
        return Err(invalid("MCP OAuth issuer 不能包含查询参数或片段"));
    }
    let http = client()?;
    let mut protected = None;
    for at_origin in [false, true] {
        let url = well_known(&endpoint, "oauth-protected-resource", at_origin);
        let response = http.get(url).send().await.map_err(|_| unavailable())?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            continue;
        }
        protected = Some(json(response).await?);
        break;
    }
    let protected = match protected {
        Some(value) => value,
        None => challenged_resource(&http, &endpoint).await?.ok_or_else(unavailable)?,
    };
    let resource = protected["resource"].as_str().ok_or_else(unavailable)?;
    let resource_url = oidc::endpoint(resource)?;
    if resource_url.query().is_some() || resource_url.origin() != endpoint.origin() {
        return Err(invalid("MCP 资源发现文档的 resource 必须与上游端点同源且无查询参数"));
    }
    if !protected["authorization_servers"]
        .as_array()
        .is_some_and(|servers| servers.iter().any(|server| server.as_str() == Some(issuer)))
    {
        return Err(invalid("MCP 资源发现文档未授权所选 issuer"));
    }
    let mut candidates = vec![well_known(&issuer_url, "oauth-authorization-server", false)];
    let mut oidc_url = issuer_url.clone();
    oidc_url.set_path(&format!("{}/.well-known/openid-configuration", issuer_url.path().trim_end_matches('/')));
    candidates.push(oidc_url.into());
    for url in candidates {
        let response = http.get(url).send().await.map_err(|_| unavailable())?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            continue;
        }
        let document = json(response).await?;
        if document["issuer"] != issuer {
            return Err(invalid("MCP 授权服务发现文档的 issuer 不匹配"));
        }
        let authorization_endpoint = document["authorization_endpoint"].as_str().ok_or_else(unavailable)?;
        let token_endpoint = document["token_endpoint"].as_str().ok_or_else(unavailable)?;
        oidc::endpoint(authorization_endpoint)?;
        oidc::endpoint(token_endpoint)?;
        if !document["code_challenge_methods_supported"]
            .as_array()
            .is_some_and(|methods| methods.iter().any(|method| method == "S256"))
            || document["response_types_supported"]
                .as_array()
                .is_some_and(|types| !types.iter().any(|kind| kind == "code"))
            || document["token_endpoint_auth_methods_supported"]
                .as_array()
                .is_some_and(|methods| !methods.iter().any(|method| method == client_auth))
        {
            return Err(invalid("MCP 授权服务不支持 code + S256 PKCE 或已配置的客户端认证方式"));
        }
        let client_id_metadata_document_supported = document["client_id_metadata_document_supported"] == true;
        if require_client_metadata && !client_id_metadata_document_supported {
            return Err(invalid("MCP 授权服务未声明支持 Client ID 元数据文档；请改用预注册客户端"));
        }
        let registration_endpoint = document["registration_endpoint"].as_str();
        if require_dynamic_registration && registration_endpoint.is_none() {
            return Err(invalid("MCP 授权服务未声明动态客户端注册地址；请改用托管元数据或预注册客户端"));
        }
        let registration_endpoint = match registration_endpoint {
            Some(value) if require_dynamic_registration => Some(oidc::endpoint(value)?.to_string()),
            Some(value) => oidc::endpoint(value).ok().map(|url| url.to_string()),
            None => None,
        };
        return Ok(Metadata {
            resource: resource.into(),
            issuer: issuer.into(),
            authorization_endpoint: authorization_endpoint.into(),
            token_endpoint: token_endpoint.into(),
            response_iss_supported: document["authorization_response_iss_parameter_supported"] == true,
            client_id_metadata_document_supported,
            registration_endpoint,
        });
    }
    Err(unavailable())
}
