//! Authenticated 2024-11-05 HTTP+SSE transport with a separate message POST endpoint.
mod listen;
mod post;
pub(super) mod probe;
mod session;

pub(crate) use listen::listen;
pub(crate) use post::post;

use super::{
    config::{self, Endpoint, Transport},
    invalid, protocol,
};
use crate::{ApiResult, Principal, state::AppState};
use agf_core::{error::DomainError, ids::Id};
use axum::http::HeaderMap;

pub(super) async fn authorized(
    state: &AppState,
    principal: &Principal,
    id: Id,
    headers: &HeaderMap,
) -> ApiResult<Endpoint> {
    principal.require(state, "mcps", "execute")?;
    principal.require(state, "policies", "read")?;
    let endpoint = config::get(state, principal.tenant, id).await?;
    if !endpoint.enabled {
        return Err(DomainError::PreconditionFailed("此 MCP SSE 端点已停用".into()).into());
    }
    if endpoint.transport != Transport::LegacySse {
        return Err(DomainError::PreconditionFailed("此端点使用 Streamable HTTP，请连接 /mcp/proxy/{id}".into()).into());
    }
    if headers.contains_key("origin")
        && !protocol::text(headers, "origin")
            .is_some_and(|origin| endpoint.allowed_origins.iter().any(|allowed| allowed == origin))
    {
        return Err(DomainError::Forbidden("Origin is not permitted by this MCP endpoint".into()).into());
    }
    Ok(endpoint)
}

pub(super) fn validate_post_url(sse_url: &str, advertised: &str) -> Result<url::Url, DomainError> {
    if advertised.trim() != advertised || advertised.chars().any(char::is_control) {
        return Err(invalid("MCP SSE server advertised a POST URL with invalid whitespace"));
    }
    let base = url::Url::parse(sse_url).map_err(|_| invalid("Invalid configured MCP SSE URL"))?;
    let url = base.join(advertised).map_err(|_| invalid("MCP SSE server advertised an invalid POST URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.origin() != base.origin()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.as_str().len() > 2048
    {
        return Err(invalid("MCP SSE POST URL must use the configured server origin without credentials or fragment"));
    }
    Ok(url)
}

pub(super) struct Event {
    pub kind: String,
    pub data: String,
}

pub(super) fn decode_event(lines: Vec<String>) -> Option<Event> {
    let mut kind = "message".to_string();
    let mut data = Vec::new();
    for line in lines {
        if line.starts_with(':') {
            continue;
        }
        let (field, value) = line.split_once(':').unwrap_or((&line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => kind = value.to_string(),
            "data" => data.push(value.to_string()),
            _ => {}
        }
    }
    (!data.is_empty()).then(|| Event { kind, data: data.join("\n") })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn post_endpoint_is_bound_to_configured_origin() {
        let base = "https://mcp.example.test/sse";
        assert_eq!(
            validate_post_url(base, "/messages?session_id=abc").unwrap().as_str(),
            "https://mcp.example.test/messages?session_id=abc"
        );
        for advertised in [
            "https://other.example/messages",
            "//other.example/messages",
            "http://mcp.example.test/messages",
            "https://mcp.example.test@other.example/messages",
            "/messages#secret",
        ] {
            assert!(validate_post_url(base, advertised).is_err());
        }
    }
}
