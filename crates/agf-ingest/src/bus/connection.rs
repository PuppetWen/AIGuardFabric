//! Authenticated NATS URLs: credentials go into CONNECT options, never server addresses.
use agf_core::error::{DomainError, DomainResult};
use async_nats::{Client, ConnectOptions, ServerAddr};
use percent_encoding::percent_decode_str;
use std::time::Duration;
use url::Url;

#[derive(Clone, PartialEq, Eq)]
enum Credentials {
    Anonymous,
    UserPassword(String, String),
    Token(String),
}

// Deliberately no Debug implementation: this structure contains decoded secrets.
struct Endpoint {
    address: ServerAddr,
    credentials: Credentials,
}

fn invalid() -> DomainError {
    DomainError::Config("Invalid NATS endpoint or credentials".into())
}

fn endpoint(raw: &str) -> DomainResult<Endpoint> {
    let raw = raw.trim();
    let mut url = Url::parse(&if raw.contains("://") { raw.to_string() } else { format!("nats://{raw}") })
        .map_err(|_| invalid())?;
    if !matches!(url.scheme(), "nats" | "tls" | "ws" | "wss") || url.host_str().is_none() {
        return Err(invalid());
    }
    let user = percent_decode_str(url.username()).decode_utf8().map_err(|_| invalid())?.into_owned();
    // URL normalization can omit an explicitly empty password. Read only the
    // presence of the raw userinfo separator to distinguish user: from a token.
    let authority = raw.split_once("://").map_or(raw, |(_, rest)| rest).split(['/', '?', '#']).next().ok_or_else(invalid)?;
    let has_password = authority.rsplit_once('@').is_some_and(|(userinfo, _)| userinfo.contains(':'));
    let credentials = if has_password {
        if user.is_empty() {
            return Err(invalid());
        }
        Credentials::UserPassword(
            user,
            percent_decode_str(url.password().unwrap_or_default()).decode_utf8().map_err(|_| invalid())?.into_owned(),
        )
    } else if user.is_empty() {
        Credentials::Anonymous
    } else {
        Credentials::Token(user)
    };
    url.set_password(None).map_err(|()| invalid())?;
    url.set_username("").map_err(|()| invalid())?;
    let address = ServerAddr::from_url(url).map_err(|_| invalid())?;
    Ok(Endpoint { address, credentials })
}

/// Public diagnostic label, with userinfo, query and fragment removed.
#[must_use]
pub fn nats_endpoint_label(raw: &str) -> String {
    let Ok(endpoint) = endpoint(raw) else { return "[invalid NATS endpoint]".into() };
    let mut url = endpoint.address.into_inner();
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

fn endpoints(urls: &[String]) -> DomainResult<(Vec<ServerAddr>, Credentials)> {
    if urls.is_empty() {
        return Err(invalid());
    }
    let mut addresses = Vec::with_capacity(urls.len());
    let mut credentials = Credentials::Anonymous;
    for raw in urls {
        let parsed = endpoint(raw)?;
        if parsed.credentials != Credentials::Anonymous {
            if credentials != Credentials::Anonymous && credentials != parsed.credentials {
                return Err(DomainError::Config("NATS failover endpoints require the same credentials".into()));
            }
            credentials = parsed.credentials;
        }
        addresses.push(parsed.address);
    }
    Ok((addresses, credentials))
}

/// Connect using anonymous, URL user/password, or URL token authentication.
///
/// A failover group shares one explicit authentication identity. Addresses retain
/// their transport scheme/path, and contain no userinfo when passed to async-nats.
///
/// # Errors
/// Invalid URLs/UTF-8 or conflicting credentials, unreachable brokers, rejected
/// credentials, and connection timeouts return fixed errors without URL secrets.
pub async fn connect_nats(urls: &[String], timeout: Duration) -> DomainResult<Client> {
    let (addresses, credentials) = endpoints(urls)?;
    let options = ConnectOptions::new().connection_timeout(timeout);
    let options = match credentials {
        Credentials::Anonymous => options,
        Credentials::UserPassword(user, password) => options.user_and_password(user, password),
        Credentials::Token(token) => options.token(token),
    };
    match tokio::time::timeout(timeout, options.connect(addresses)).await {
        Ok(Ok(client)) => Ok(client),
        Ok(Err(error)) => Err(DomainError::DependencyUnavailable {
            dependency: "nats".into(),
            cause: match error.kind() {
                async_nats::ConnectErrorKind::AuthorizationViolation | async_nats::ConnectErrorKind::Authentication => {
                    "NATS authentication failed"
                }
                async_nats::ConnectErrorKind::TimedOut => "NATS connection timed out",
                _ => "NATS connection failed",
            }
            .into(),
        }),
        Err(_) => Err(DomainError::DependencyUnavailable {
            dependency: "nats".into(),
            cause: "NATS connection timed out".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn url_user_password_are_decoded_and_removed_from_server_address() {
        let value = endpoint("nats://us%40er:p%3Aa%25ss@nats:4222").unwrap();
        assert!(value.credentials == Credentials::UserPassword("us@er".into(), "p:a%ss".into()));
        assert_eq!(value.address.as_url_str(), "nats://nats:4222");
    }

    #[test]
    fn credentials_are_utf8_and_plus_is_literal() {
        let value = endpoint("tls://%E7%94%A8%E6%88%B7:%E5%AF%86%E7%A0%81%2B+@nats:4443").unwrap();
        assert!(value.credentials == Credentials::UserPassword("用户".into(), "密码++".into()));
        assert!(value.address.tls_required());
        assert!(endpoint("nats://user:%FF@nats:4222").is_err());
    }

    #[test]
    fn token_userinfo_and_explicit_empty_password_are_distinct() {
        assert!(endpoint("nats://t%40ken@nats:4222").unwrap().credentials == Credentials::Token("t@ken".into()));
        assert!(endpoint("nats://user:@nats:4222").unwrap().credentials == Credentials::UserPassword("user".into(), String::new()));
    }

    #[test]
    fn anonymous_ipv6_and_websocket_transport_are_preserved() {
        let value = endpoint("[::1]:4222").unwrap();
        assert!(value.credentials == Credentials::Anonymous);
        assert_eq!(value.address.host(), "::1");
        let value = endpoint("wss://user:secret@nats:443/socket?route=one").unwrap();
        assert_eq!(value.address.as_url_str(), "wss://nats/socket?route=one");
    }

    #[test]
    fn failover_inherits_one_identity_and_rejects_conflicting_credentials() {
        let (addresses, credentials) = endpoints(&["nats://u:p@one:4222".into(), "nats://two:4222".into()]).unwrap();
        assert!(credentials == Credentials::UserPassword("u".into(), "p".into()));
        assert!(addresses.iter().all(|a| a.username().is_none() && a.password().is_none()));
        assert!(endpoints(&["nats://u:p@one:4222".into(), "nats://u:other@two:4222".into()]).is_err());
    }

    #[test]
    fn diagnostic_labels_and_validation_errors_do_not_contain_credentials() {
        assert_eq!(nats_endpoint_label("nats://user:secret@nats:4222?token=hidden#hidden"), "nats://nats:4222");
        let error = endpoint("http://user:secret@nats:4222").err().unwrap().to_string();
        assert!(!error.contains("user") && !error.contains("secret"));
    }
}
