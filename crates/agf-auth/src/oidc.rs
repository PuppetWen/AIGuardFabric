//! OpenID Connect code flow with S256 PKCE and strict ID-token validation.
use agf_core::error::{DomainError, DomainResult};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::Jwk};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;

/// Client authentication at the token endpoint, as registered at the identity provider.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuth {
    /// Confidential client using HTTP Basic.
    #[default]
    ClientSecretBasic,
    /// Confidential client sending its secret in the form body.
    ClientSecretPost,
    /// Public client; S256 PKCE remains mandatory.
    None,
}

/// Discovery data pinned to a tenant administrator's configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    /// Exact issuer identifier, including any path and trailing slash.
    pub issuer: String,
    /// Browser authorization endpoint.
    pub authorization_endpoint: String,
    /// Backend authorization-code exchange endpoint.
    pub token_endpoint: String,
    /// Signing-key set endpoint pinned by discovery.
    pub jwks_uri: String,
}

/// Only signed identity attributes are returned; access and refresh tokens are not retained.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Verified issuer; part of the immutable account identity.
    pub issuer: String,
    /// Verified subject; email is never used to link existing accounts.
    pub subject: String,
    /// Optional display name from the signed ID token.
    pub name: Option<String>,
    /// Email is returned only when the signed token marks it verified.
    pub email: Option<String>,
}

/// Configured endpoints must use TLS, except explicit loopback development endpoints.
pub fn endpoint(value: &str) -> DomainResult<Url> {
    let url = Url::parse(value).map_err(|_| invalid("身份服务 URL 无效"))?;
    let loopback = url
        .host_str()
        .is_some_and(|h| h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()));
    if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid("身份服务和回调地址必须使用 HTTPS（仅回环地址允许 HTTP），不能包含凭据或片段"));
    }
    Ok(url)
}

/// S256 challenge, also used to store only a digest of the browser binding secret.
pub fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn client() -> DomainResult<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(12))
        .build()
        .map_err(|_| unavailable())
}

async fn json_response(mut response: reqwest::Response) -> DomainResult<Value> {
    if !response.status().is_success() {
        return Err(unavailable());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| unavailable())? {
        if bytes.len() + chunk.len() > 1_048_576 {
            return Err(unavailable());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| unavailable())
}

/// Fetch and validate discovery without following redirects to an unconfigured destination.
pub async fn discover(issuer: &str) -> DomainResult<Metadata> {
    if endpoint(issuer)?.query().is_some() {
        return Err(invalid("Issuer 不能包含查询参数"));
    }
    let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    let data = json_response(client()?.get(url).send().await.map_err(|_| unavailable())?).await?;
    let metadata: Metadata = serde_json::from_value(data.clone()).map_err(|_| unavailable())?;
    if metadata.issuer != issuer {
        return Err(invalid("发现文档的 issuer 与配置不一致"));
    }
    for url in [&metadata.authorization_endpoint, &metadata.token_endpoint, &metadata.jwks_uri] {
        endpoint(url)?;
    }
    if data
        .get("code_challenge_methods_supported")
        .is_some_and(|v| !v.as_array().is_some_and(|items| items.iter().any(|s| s == "S256")))
    {
        return Err(invalid("身份服务必须支持 S256 PKCE"));
    }
    Ok(metadata)
}

/// Build a code-flow URL with state, nonce and S256 PKCE; reject duplicate parameters.
pub fn authorize_url(
    metadata: &Metadata,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    nonce: &str,
    verifier: &str,
) -> DomainResult<String> {
    let mut url = endpoint(&metadata.authorization_endpoint)?;
    // Configured endpoints may have a tenant/routing query, but not duplicate protocol parameters.
    let reserved = [
        "client_id",
        "redirect_uri",
        "response_type",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
        "response_mode",
    ];
    if url.query_pairs().any(|(key, _)| reserved.contains(&key.as_ref())) {
        return Err(invalid("授权端点包含重复的 OIDC 参数"));
    }
    url.query_pairs_mut().extend_pairs([
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("scope", "openid profile email"),
        ("state", state),
        ("nonce", nonce),
        ("code_challenge", &challenge(verifier)),
        ("code_challenge_method", "S256"),
        ("response_mode", "query"),
    ]);
    Ok(url.into())
}

/// Exchange arguments belong to a one-use, browser-bound transaction stored by the caller.
pub struct Exchange<'a> {
    /// Administrator-approved discovery data.
    pub metadata: &'a Metadata,
    /// Registered relying-party identifier.
    pub client_id: &'a str,
    /// Decrypted confidential-client secret; never sent to the browser.
    pub client_secret: Option<&'a str>,
    /// Registered token endpoint authentication method.
    pub client_auth: ClientAuth,
    /// Exact redirect URI used in the authorization request.
    pub redirect_uri: &'a str,
    /// Single-use authorization code received by the browser.
    pub code: &'a str,
    /// Server-retained PKCE verifier.
    pub verifier: &'a str,
    /// Expected nonce in the signed ID token.
    pub nonce: &'a str,
    /// Start of this login transaction, in Unix seconds.
    pub started_at: i64,
}

impl std::fmt::Debug for Exchange<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Exchange")
            .field("issuer", &self.metadata.issuer)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// Redeem the code and validate signature, issuer, audience, timestamps and nonce.
pub async fn exchange(request: &Exchange<'_>) -> DomainResult<Identity> {
    let http = client()?;
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", request.code),
        ("redirect_uri", request.redirect_uri),
        ("code_verifier", request.verifier),
    ];
    let mut post = http.post(endpoint(&request.metadata.token_endpoint)?);
    match request.client_auth {
        ClientAuth::ClientSecretBasic => {
            let encode = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
            post = post.basic_auth(encode(request.client_id), Some(encode(request.client_secret.unwrap_or(""))));
        }
        ClientAuth::ClientSecretPost => {
            form.push(("client_id", request.client_id));
            form.push(("client_secret", request.client_secret.unwrap_or("")));
        }
        ClientAuth::None => form.push(("client_id", request.client_id)),
    }
    let body = json_response(post.form(&form).send().await.map_err(|_| unavailable())?).await?;
    let token = body["id_token"].as_str().ok_or_else(rejected)?;
    let jwks =
        json_response(http.get(endpoint(&request.metadata.jwks_uri)?).send().await.map_err(|_| unavailable())?).await?;
    validate(token, &jwks, request)
}

fn validate(token: &str, jwks: &Value, request: &Exchange<'_>) -> DomainResult<Identity> {
    let header = decode_header(token).map_err(|_| rejected())?;
    if !matches!(
        header.alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::EdDSA
    ) {
        return Err(rejected());
    }
    let alg = format!("{:?}", header.alg);
    let keys: Vec<_> = jwks["keys"]
        .as_array()
        .ok_or_else(rejected)?
        .iter()
        .filter(|jwk| {
            header.kid.as_ref().is_none_or(|kid| jwk["kid"].as_str() == Some(kid))
                && jwk.get("use").is_none_or(|v| v == "sig")
                && jwk.get("alg").is_none_or(|v| v == &alg)
                && jwk.get("key_ops").is_none_or(|v| v.as_array().is_some_and(|ops| ops.iter().any(|s| s == "verify")))
        })
        .collect();
    if keys.len() != 1 {
        return Err(rejected());
    }
    let key: Jwk = serde_json::from_value(keys[0].clone()).map_err(|_| rejected())?;
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[&request.metadata.issuer]);
    validation.set_audience(&[request.client_id]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub", "iat"]);
    validation.validate_nbf = true;
    validation.leeway = 30;
    let claims: Value = decode(token, &DecodingKey::from_jwk(&key).map_err(|_| rejected())?, &validation)
        .map_err(|_| rejected())?
        .claims;
    let now = agf_core::time::Timestamp::now().unix_secs();
    let iat = claims["iat"].as_i64().ok_or_else(rejected)?;
    let subject = claims["sub"].as_str().filter(|s| !s.is_empty() && s.len() <= 255).ok_or_else(rejected)?;
    if claims["nonce"].as_str() != Some(request.nonce)
        || iat > now + 30
        || iat < request.started_at - 120
        || claims.get("azp").is_some_and(|azp| azp != request.client_id)
        || (claims["aud"].as_array().is_some_and(|a| a.len() > 1) && claims["azp"] != request.client_id)
    {
        return Err(rejected());
    }
    Ok(Identity {
        issuer: request.metadata.issuer.clone(),
        subject: subject.into(),
        name: claims["name"].as_str().filter(|s| s.len() <= 256).map(str::to_owned),
        email: if claims["email_verified"] == true {
            claims["email"].as_str().filter(|s| s.len() <= 254).map(str::to_owned)
        } else {
            None
        },
    })
}

fn invalid(message: &str) -> DomainError {
    DomainError::Validation(message.into())
}
fn rejected() -> DomainError {
    DomainError::Unauthenticated("身份令牌验证失败，请重新发起企业登录".into())
}
fn unavailable() -> DomainError {
    DomainError::DependencyUnavailable {
        dependency: "oidc".into(),
        cause: "身份服务请求失败，请检查端点、客户端注册和服务端日志".into(),
    }
}
