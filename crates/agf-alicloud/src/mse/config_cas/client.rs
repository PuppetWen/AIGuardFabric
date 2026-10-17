use super::*;
use futures::StreamExt;
use reqwest::{Method, header::HeaderMap};
use tokio::time::Instant;
use url::{Host, Url};

/// Trusted engine origin. The only request path is `/nacos/v2/cs/config`.
#[derive(Debug, Clone)]
pub struct EngineEndpoint(Url);
impl EngineEndpoint {
    /// Construct a Live HTTPS origin with no credentials, path, query or fragment.
    /// # Errors
    /// Invalid or non-HTTPS origins are rejected.
    pub fn https(origin: &str) -> DomainResult<Self> {
        Self::parse(origin, false)
    }
    /// Explicit test-only HTTP origin; its host must be a literal loopback IP.
    /// # Errors
    /// Domain names, non-loopback addresses or non-HTTP origins are rejected.
    pub fn literal_loopback_for_test(origin: &str) -> DomainResult<Self> {
        Self::parse(origin, true)
    }
    fn parse(origin: &str, loopback: bool) -> DomainResult<Self> {
        if origin.len() > 2048
            || origin.trim() != origin
            || origin.contains('\\')
            || origin.chars().any(char::is_control)
        {
            return Err(invalid_origin());
        }
        let mut url = Url::parse(origin).map_err(|_| invalid_origin())?;
        let valid_host = match url.host() {
            Some(Host::Ipv4(ip)) => !loopback || ip.is_loopback(),
            Some(Host::Ipv6(ip)) => !loopback || ip.is_loopback(),
            Some(Host::Domain(_)) => !loopback,
            None => false,
        };
        if !valid_host
            || url.scheme() != if loopback { "http" } else { "https" }
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid_origin());
        }
        url.set_path("/nacos/v2/cs/config");
        Ok(Self(url))
    }
}
fn invalid_origin() -> DomainError {
    DomainError::Validation("Nacos engine origin is not an allowed origin".into())
}

/// Fixed-origin client. It never follows redirects or retries writes.
pub struct NacosConfigClient {
    pub(super) endpoint: EngineEndpoint,
    pub(super) provider: Arc<dyn NacosCredentialProvider>,
    pub(super) limits: Limits,
    http: reqwest::Client,
}
impl fmt::Debug for NacosConfigClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NacosConfigClient")
            .field("endpoint", &self.endpoint)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}
impl NacosConfigClient {
    /// Build a client using platform-approved credentials and a trusted engine origin.
    /// # Errors
    /// Invalid limits or HTTP client initialization errors are returned without sending requests.
    pub fn new(
        endpoint: EngineEndpoint,
        provider: Arc<dyn NacosCredentialProvider>,
        limits: Limits,
    ) -> DomainResult<Self> {
        limits.validate()?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .retry(reqwest::retry::never())
            .connect_timeout(limits.timeout)
            .timeout(limits.timeout)
            .build()
            .map_err(|_| DomainError::Config("Cannot initialize Nacos HTTPS client".into()))?;
        Ok(Self { endpoint, provider, limits, http })
    }
    pub(super) async fn prepare(
        &self,
        key: &ConfigKey,
        guard: &dyn NacosSendGuard,
        deadline: Instant,
    ) -> DomainResult<HeaderMap> {
        let credential = self.provider.credentials().await?;
        check_deadline(deadline)?;
        signing::validate_credential(&credential)?;
        guard.validate().await?;
        check_deadline(deadline)?;
        // A long guard wait must not send credentials which expired during that wait.
        signing::validate_credential(&credential)?;
        signing::headers(key, &credential, Timestamp::now().unix_millis())
    }
    pub(super) fn request(&self, method: Method, headers: HeaderMap) -> reqwest::RequestBuilder {
        self.http.request(method, self.endpoint.0.clone()).headers(headers)
    }
    pub(super) async fn read(&self, mut response: reqwest::Response) -> Result<WireResponse, UncertainReason> {
        if response.content_length().is_some_and(|size| size > self.limits.max_response_bytes as u64) {
            return Err(UncertainReason::ResponseLimit);
        }
        let status = response.status().as_u16();
        let headers = std::mem::take(response.headers_mut());
        let mut stream = response.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| UncertainReason::Transport)?;
            if chunk.len() > self.limits.max_response_bytes.saturating_sub(body.len()) {
                return Err(UncertainReason::ResponseLimit);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(WireResponse { status, headers, body })
    }
}
pub(super) fn check_deadline(deadline: Instant) -> DomainResult<()> {
    if Instant::now() >= deadline {
        return Err(DomainError::Timeout("Nacos call budget expired".into()));
    }
    Ok(())
}
pub(super) struct WireResponse {
    pub(super) status: u16,
    pub(super) headers: HeaderMap,
    pub(super) body: Vec<u8>,
}
impl fmt::Debug for WireResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireResponse")
            .field("status", &self.status)
            .field("body", &"<redacted>")
            .finish_non_exhaustive()
    }
}
pub(super) fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> DomainResult<Option<&'a str>> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .map(reqwest::header::HeaderValue::to_str)
        .transpose()
        .map_err(|_| DomainError::Parse("Nacos response contains an invalid header".into()))?;
    if values.next().is_some() {
        return Err(DomainError::Parse("Nacos response contains duplicate security headers".into()));
    }
    Ok(value)
}
pub(super) fn normal_response(headers: &HeaderMap) -> DomainResult<()> {
    for name in ["encrypted-data-key", "vipserver-tag", "betaips", "tag"] {
        if single_header(headers, name)?.is_some_and(|value| !value.is_empty()) {
            return Err(DomainError::PreconditionFailed(
                "Encrypted, beta or tagged Nacos configuration is unsupported".into(),
            ));
        }
    }
    if single_header(headers, "isbeta")?.is_some_and(|value| value != "false") {
        return Err(DomainError::PreconditionFailed("Beta or unverified Nacos configuration is unsupported".into()));
    }
    let kind = single_header(headers, "content-type")?.and_then(|value| value.split(';').next()).map(str::trim);
    if kind != Some("application/json") {
        return Err(DomainError::Parse("Expected the Nacos v2 JSON response protocol".into()));
    }
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Envelope {
    pub(super) code: u32,
    #[serde(rename = "message")]
    _message: String,
    #[serde(default)]
    pub(super) data: serde_json::Value,
}
