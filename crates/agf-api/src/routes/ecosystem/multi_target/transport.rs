use crate::AppState;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use reqwest::{Client, Url};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
#[cfg(feature = "test-loopback-transport")]
use std::net::{Ipv4Addr, SocketAddr};

#[cfg(feature = "test-loopback-transport")]
#[derive(Debug, Clone)]
pub(crate) struct TestCapability {
    tenant: TenantId,
    targets: Vec<(Id, SocketAddr)>,
}
#[cfg(feature = "test-loopback-transport")]
impl TestCapability {
    fn permits(&self, tenant: TenantId, id: Id, url: &Url) -> bool {
        tenant == self.tenant
            && self.targets.iter().any(|(profile, address)| {
                *profile == id
                    && url.scheme() == "http"
                    && url.host_str() == Some("127.0.0.1")
                    && url.port_or_known_default() == Some(address.port())
            })
    }
}
#[cfg(feature = "test-loopback-transport")]
impl AppState {
    /// Default-off owned transport capability; never activated by a URL, header or environment variable.
    /// # Errors
    /// Nil/duplicate profiles, more than three targets or a nonliteral loopback address.
    pub fn with_multi_target_loopback_targets(
        mut self,
        tenant: TenantId,
        targets: Vec<(Id, SocketAddr)>,
    ) -> DomainResult<Self> {
        if tenant.as_id().is_nil()
            || targets.len() != 3
            || targets.iter().any(|(id, address)| {
                id.is_nil() || address.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) || address.port() == 0
            })
            || targets.iter().map(|(id, _)| *id).collect::<std::collections::BTreeSet<_>>().len() != 3
        {
            return Err(invalid());
        }
        self.redteam_multi_test_transport = Some(std::sync::Arc::new(TestCapability { tenant, targets }));
        Ok(self)
    }
}
pub(super) fn parse(raw: &str) -> DomainResult<Url> {
    let url = Url::parse(raw).map_err(|_| invalid())?;
    if raw.len() > 2048
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
    {
        return Err(invalid());
    }
    Ok(url)
}
pub(super) fn literal_ip(url: &Url) -> Option<IpAddr> {
    match url.host()? {
        url::Host::Ipv4(ip) => Some(IpAddr::V4(ip)),
        url::Host::Ipv6(ip) => Some(IpAddr::V6(ip)),
        url::Host::Domain(_) => None,
    }
}
pub(super) fn mode(state: &AppState, tenant: TenantId, id: Id, raw: &str) -> DomainResult<String> {
    let url = parse(raw)?;
    #[cfg(feature = "test-loopback-transport")]
    if state.redteam_multi_test_transport.as_ref().is_some_and(|cap| cap.permits(tenant, id, &url)) {
        return Ok("test-loopback".into());
    }
    #[cfg(not(feature = "test-loopback-transport"))]
    let _ = (state, tenant, id);
    let host = url.host_str().ok_or_else(invalid)?;
    if url.scheme() != "https"
        || host.eq_ignore_ascii_case("localhost")
        || host.ends_with(".local")
        || literal_ip(&url).is_some_and(|address| !public(address))
    {
        return Err(invalid());
    }
    Ok("https-live".into())
}
fn public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && ip.octets()[0] != 0
                && ip.octets()[0] < 224
                && !(ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
                && !(ip.octets()[0] == 198 && [18, 19].contains(&ip.octets()[1]))
        }
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return public(IpAddr::V4(mapped));
            }
            let segments = ip.segments();
            // Global unicast only; reject the reserved documentation prefix as well.
            (segments[0] & 0xe000) == 0x2000 && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}
pub(super) fn mode_approved(
    state: &AppState,
    tenant: TenantId,
    id: Id,
    raw: &str,
    private: Option<&super::managed_model::PrivateNetwork>,
) -> DomainResult<String> {
    let url = parse(raw)?;
    if let Some(private) = private {
        private.validate(&url)?;
        return Ok(format!("approved-private-{}", url.scheme()));
    }
    mode(state, tenant, id, raw)
}
pub(super) async fn client(
    state: &AppState,
    tenant: TenantId,
    id: Id,
    raw: &str,
    private: Option<&super::managed_model::PrivateNetwork>,
) -> DomainResult<(Client, Url, String)> {
    let mode = mode_approved(state, tenant, id, raw, private)?;
    let url = parse(raw)?;
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(std::time::Duration::from_secs(8));
    let mut resolved = Vec::new();
    if mode == "https-live" || private.is_some() {
        let host = url.host_str().ok_or_else(invalid)?;
        let port = url.port_or_known_default().ok_or_else(invalid)?;
        let addresses: Vec<_> = if let Some(ip) = literal_ip(&url) {
            vec![std::net::SocketAddr::new(ip, port)]
        } else {
            tokio::net::lookup_host((host, port)).await.map_err(|_| unavailable())?.collect()
        };
        let addresses = pin(addresses, private)?;
        let address = *addresses.first().ok_or_else(invalid)?;
        resolved = addresses.iter().map(ToString::to_string).collect();
        if literal_ip(&url).is_none() {
            builder = builder.resolve(host, address);
        }
    } else {
        resolved.push(format!("127.0.0.1:{}", url.port_or_known_default().ok_or_else(invalid)?));
    }
    let proof = super::types::hash(
        &serde_json::json!({"tenant":tenant,"profile":id,"url":raw,"mode":mode,"resolvedAddresses":resolved,
        "selectedAddress":resolved.first(),"redirects":false,"proxy":false}),
    )?;
    Ok((builder.build().map_err(|_| unavailable())?, url, proof))
}
fn pin(
    mut addresses: Vec<std::net::SocketAddr>,
    private: Option<&super::managed_model::PrivateNetwork>,
) -> DomainResult<Vec<std::net::SocketAddr>> {
    if addresses.is_empty()
        || addresses.len() > 16
        || addresses.iter().any(|address| match private {
            Some(private) => address.port() != private.port || !private.addresses.contains(&address.ip()),
            None => !public(address.ip()),
        })
        || private.is_some_and(|private| {
            private.addresses.iter().any(|ip| !addresses.iter().any(|address| address.ip() == *ip))
        })
    {
        return Err(invalid());
    }
    addresses.sort();
    addresses.dedup();
    Ok(addresses)
}
pub(super) struct Wire {
    pub content: Value,
    pub response_sha256: String,
    pub response_bytes: usize,
    pub session: Option<String>,
}
pub(super) async fn exchange(
    client: &Client,
    url: &Url,
    bearer: Option<&str>,
    body: &Value,
    method: Option<(&str, Option<&str>)>,
) -> DomainResult<Wire> {
    let mut request = client.post(url.clone()).json(body);
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    if let Some((method, name)) = method {
        request = request
            .header("mcp-method", method)
            .header("mcp-protocol-version", "2026-07-28")
            .header("accept", "application/json");
        if let Some(name) = name {
            request = request.header("mcp-name", name);
        }
    }
    let mut response = request.send().await.map_err(|_| unavailable())?;
    if !response.status().is_success() {
        return Err(unavailable());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| unavailable())? {
        if bytes.len().saturating_add(chunk.len()) > 64 * 1024 {
            return Err(unavailable());
        }
        bytes.extend_from_slice(&chunk);
    }
    let content = serde_json::from_slice(&bytes).map_err(|_| unavailable())?;
    Ok(Wire {
        content,
        response_sha256: format!("{:x}", Sha256::digest(&bytes)),
        response_bytes: bytes.len(),
        session: None,
    })
}
pub(super) async fn mcp_exchange(
    client: &Client,
    url: &Url,
    bearer: Option<&str>,
    body: &Value,
    headers: &reqwest::header::HeaderMap,
    expected: Option<u64>,
) -> DomainResult<Wire> {
    use super::mcp_frames::{self, Frames, LIMIT};
    let mut request = client
        .post(url.clone())
        .headers(headers.clone())
        .header("accept", "application/json, text/event-stream")
        .json(body);
    if let Some(bearer) = bearer {
        request = request.bearer_auth(bearer);
    }
    let mut response = request.send().await.map_err(|_| mcp_frames::invalid())?;
    let session = response
        .headers()
        .get("mcp-session-id")
        .map(|id| {
            let value = id.to_str().map_err(|_| mcp_frames::invalid())?;
            if value.is_empty() || value.len() > 256 || !value.bytes().all(|b| (33..=126).contains(&b)) {
                return Err(mcp_frames::invalid());
            }
            Ok(value.to_owned())
        })
        .transpose()?;
    if expected.is_none() {
        if response.status() != reqwest::StatusCode::ACCEPTED {
            return Err(mcp_frames::invalid());
        }
        if response.chunk().await.map_err(|_| mcp_frames::invalid())?.is_some() {
            return Err(mcp_frames::invalid());
        }
        return Ok(Wire {
            content: Value::Null,
            response_sha256: format!("{:x}", Sha256::digest([])),
            response_bytes: 0,
            session,
        });
    }
    if !response.status().is_success() {
        return Err(mcp_frames::invalid());
    }
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .ok_or_else(mcp_frames::invalid)?;
    let sse = match content_type {
        "application/json" => false,
        "text/event-stream" => true,
        _ => return Err(mcp_frames::invalid()),
    };
    let expected = expected.ok_or_else(mcp_frames::invalid)?;
    let mut bytes = Vec::new();
    let mut frames = Frames::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| mcp_frames::invalid())? {
        if bytes.len().saturating_add(chunk.len()) > LIMIT {
            return Err(mcp_frames::invalid());
        }
        bytes.extend_from_slice(&chunk);
        if sse && let Some(content) = frames.push(&chunk, expected)? {
            // Final result terminates this local response future; no session GET or stream resume.
            return Ok(Wire {
                content,
                response_sha256: format!("{:x}", Sha256::digest(&bytes)),
                response_bytes: bytes.len(),
                session,
            });
        }
    }
    if sse {
        return Err(mcp_frames::invalid());
    }
    let content = mcp_frames::result(serde_json::from_slice(&bytes).map_err(|_| mcp_frames::invalid())?, expected)?;
    Ok(Wire { content, response_sha256: format!("{:x}", Sha256::digest(&bytes)), response_bytes: bytes.len(), session })
}
fn invalid() -> DomainError {
    DomainError::Validation("Use public HTTPS or an administrator-approved exact private HTTP(S) profile/address/port; no redirects/proxy or mixed DNS answers. Literal127 requires an owned test capability".into())
}
fn unavailable() -> DomainError {
    DomainError::DependencyUnavailable {
        dependency: "redteam-target".into(),
        cause: "Read response unavailable or invalid; dispatch is not retried".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_resolution_requires_complete_approved_address_set_and_exact_port() -> DomainResult<()> {
        let network = super::super::managed_model::PrivateNetwork {
            addresses: vec!["10.1.1.1".parse().map_err(|_| invalid())?, "10.1.1.2".parse().map_err(|_| invalid())?],
            port: 8080,
            allow_plain_http: true,
        };
        let parse = |raw: &str| raw.parse().map_err(|_| invalid());
        let expected = vec![parse("10.1.1.1:8080")?, parse("10.1.1.2:8080")?];
        assert_eq!(pin(expected.clone(), Some(&network))?, expected);
        for raw in ["10.1.1.3:8080", "10.1.1.2:8081", "8.8.8.8:8080", "127.0.0.1:8080", "169.254.169.254:8080"] {
            assert!(pin(vec![expected[0], parse(raw)?], Some(&network)).is_err());
        }
        assert!(pin(vec![expected[0]], Some(&network)).is_err());
        assert!(pin(expected, None).is_err());
        Ok(())
    }
}
