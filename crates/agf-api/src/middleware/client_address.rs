//! 只信任实际 TCP 对端；反向代理地址必须显式列入 AGF_TRUSTED_PROXIES。
use axum::{
    extract::{ConnectInfo, Request},
    http::HeaderValue,
    middleware::Next,
    response::Response,
};
use std::net::{IpAddr, SocketAddr};

fn effective_ip(peer: Option<IpAddr>, forwarded: Option<&str>, proxies: &[String]) -> Option<IpAddr> {
    let mut current = peer?;
    for address in forwarded.unwrap_or_default().split(',').rev() {
        if !agf_auth::rbac::cidr_matches_any(proxies, &current.to_string()) {
            break;
        }
        let Ok(parsed) = address.trim().parse::<IpAddr>() else {
            break;
        };
        current = parsed;
    }
    Some(current)
}

pub(crate) async fn normalize(mut request: Request, next: Next) -> Response {
    let peer = request.extensions().get::<ConnectInfo<SocketAddr>>().map(|value| value.0.ip());
    let proxies: Vec<_> = std::env::var("AGF_TRUSTED_PROXIES")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect();
    let address =
        effective_ip(peer, request.headers().get("x-forwarded-for").and_then(|value| value.to_str().ok()), &proxies);
    strip_untrusted_certificate_headers(request.headers_mut(), peer, &proxies);
    request.headers_mut().remove("x-forwarded-for");
    request.headers_mut().remove("x-real-ip");
    if let Some(value) = address.and_then(|address| HeaderValue::from_str(&address.to_string()).ok()) {
        request.headers_mut().insert("x-forwarded-for", value);
    }
    next.run(request).await
}

fn strip_untrusted_certificate_headers(headers: &mut axum::http::HeaderMap, peer: Option<IpAddr>, proxies: &[String]) {
    if !peer.is_some_and(|peer| agf_auth::rbac::cidr_matches_any(proxies, &peer.to_string())) {
        for name in ["x-ssl-client-verify", "x-ssl-client-cert", "x-agf-client-cert-der"] {
            headers.remove(name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn forwarded_certificates_require_a_trusted_tcp_peer() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-ssl-client-verify", HeaderValue::from_static("SUCCESS"));
        let allow = vec!["10.0.0.1/32".into()];
        strip_untrusted_certificate_headers(&mut headers, "10.0.0.1".parse().ok(), &allow);
        assert!(headers.contains_key("x-ssl-client-verify"));
        strip_untrusted_certificate_headers(&mut headers, "192.0.2.1".parse().ok(), &allow);
        assert!(!headers.contains_key("x-ssl-client-verify"));
    }
    #[test]
    fn direct_clients_cannot_forge_an_allowed_address() {
        let peer = "192.0.2.1".parse().ok();
        assert_eq!(effective_ip(peer, Some("10.0.0.1"), &[]), peer);
        assert_eq!(effective_ip(None, Some("10.0.0.1"), &["0.0.0.0/0".into()]), None);
    }
    #[test]
    fn proxy_chain_is_resolved_from_the_trusted_end() {
        let result =
            effective_ip("10.0.0.2".parse().ok(), Some("1.1.1.1, 192.0.2.99, 10.0.0.3"), &["10.0.0.0/24".into()]);
        assert_eq!(result, "192.0.2.99".parse().ok());
    }
}
