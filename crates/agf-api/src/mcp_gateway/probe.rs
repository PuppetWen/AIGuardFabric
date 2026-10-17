//! Read-only MCP discovery from the console; the probe never calls a tool.
use super::{MAX_FRAME, config::Transport, forward, invalid, legacy_sse, protocol};
use crate::{ApiResult, Principal, state::AppState};
use agf_core::ids::Id;
use axum::{
    body::{Bytes, to_bytes},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::Response,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Duration;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    pub protocol: String,
}

#[derive(Serialize)]
pub(crate) struct Result {
    pub protocol: String,
    pub server: Value,
    pub tools: Value,
    pub session_closed: bool,
}

pub(crate) async fn run(state: &AppState, principal: &Principal, id: Id, input: Input) -> ApiResult<Result> {
    if !protocol::VERSIONS.contains(&input.protocol.as_str()) && input.protocol != "2024-11-05" {
        return Err(invalid("Unsupported probe protocol").into());
    }
    let endpoint = super::config::get(state, principal.tenant, id).await?;
    if endpoint.transport == Transport::LegacySse {
        if input.protocol != "2024-11-05" {
            return Err(invalid("Legacy SSE discovery requires protocol 2024-11-05").into());
        }
        let (server, tools, session_closed) = legacy_sse::probe::run(state, principal, &endpoint).await?;
        super::discovery::save(state, principal.tenant, id, endpoint.version, &server, &tools).await?;
        return Ok(Result { protocol: input.protocol, server, tools, session_closed });
    }
    if input.protocol == "2024-11-05" {
        return Err(invalid("Protocol 2024-11-05 requires a Legacy SSE endpoint").into());
    }
    let modern = input.protocol == protocol::MODERN;
    let mut headers = HeaderMap::new();
    headers.insert(
        "mcp-protocol-version",
        HeaderValue::from_str(&input.protocol).map_err(|_| invalid("Invalid MCP version"))?,
    );
    let initial = if modern { "server/discover" } else { "initialize" };
    let params = if modern {
        json!({})
    } else {
        json!({"protocolVersion":input.protocol,"capabilities":{},"clientInfo":{"name":"AIGuardFabric probe","version":crate::VERSION}})
    };
    let (server, response_headers) = request(state, principal, id, &headers, initial, params, Some(1)).await?;
    if let Some(session) = response_headers.get("mcp-session-id") {
        headers.insert("mcp-session-id", session.clone());
    }
    let queried = async {
        if !modern {
            request(state, principal, id, &headers, "notifications/initialized", json!({}), None).await?;
        }
        list_tools(state, principal, id, &headers).await
    }
    .await;
    // Even a failed tool-list query should release the temporary legacy session.
    let closed = if headers.contains_key("mcp-session-id") {
        forward::forward(state.clone(), principal.clone(), id, Method::DELETE, headers, Bytes::new())
            .await
            .is_ok_and(|response| response.status().is_success())
    } else {
        true
    };
    let tools = queried?;
    super::discovery::save(state, principal.tenant, id, endpoint.version, &server, &tools).await?;
    Ok(Result { protocol: input.protocol, server, tools, session_closed: closed })
}

async fn request(
    state: &AppState,
    principal: &Principal,
    id: Id,
    headers: &HeaderMap,
    method: &str,
    mut params: Value,
    request_id: Option<u64>,
) -> ApiResult<(Value, HeaderMap)> {
    let mut headers = headers.clone();
    if protocol::text(&headers, "mcp-protocol-version") == Some(protocol::MODERN) {
        params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":protocol::MODERN,
            "io.modelcontextprotocol/clientInfo":{"name":"AIGuardFabric probe","version":crate::VERSION},
            "io.modelcontextprotocol/clientCapabilities":{}});
        headers.insert("mcp-method", HeaderValue::from_str(method).map_err(|_| invalid("Invalid MCP method"))?);
    }
    let mut frame = json!({"jsonrpc":"2.0","method":method,"params":params});
    if let Some(id) = request_id {
        frame["id"] = json!(id);
    }
    let response = tokio::time::timeout(
        Duration::from_secs(12),
        forward::forward(state.clone(), principal.clone(), id, Method::POST, headers, Bytes::from(frame.to_string())),
    )
    .await
    .map_err(|_| invalid("MCP discovery timed out"))??;
    collect(response, request_id).await
}

async fn collect(response: Response, id: Option<u64>) -> ApiResult<(Value, HeaderMap)> {
    let (parts, body) = response.into_parts();
    if !parts.status.is_success() {
        let hint = if parts.status == StatusCode::BAD_GATEWAY {
            to_bytes(body, MAX_FRAME)
                .await
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .and_then(|frame| frame["error"]["message"].as_str().map(str::to_owned))
                .filter(|message| message == forward::UPSTREAM_UNAUTHORIZED || message == forward::UPSTREAM_FORBIDDEN)
        } else {
            None
        };
        let fallback =
            format!("MCP discovery returned HTTP {}; check protocol, URL and upstream credential", parts.status);
        return Err(invalid(hint.as_deref().unwrap_or(&fallback)).into());
    }
    let bytes = tokio::time::timeout(Duration::from_secs(12), to_bytes(body, MAX_FRAME))
        .await
        .map_err(|_| invalid("MCP discovery response timed out"))?
        .map_err(|_| invalid("MCP discovery response exceeds 1 MiB"))?;
    if bytes.is_empty() && id.is_none() {
        return Ok((Value::Null, parts.headers));
    }
    let frame: Value =
        if protocol::text(&parts.headers, "content-type").is_some_and(|v| v.starts_with("text/event-stream")) {
            std::str::from_utf8(&bytes)
                .map_err(|_| invalid("Invalid MCP SSE encoding"))?
                .lines()
                .filter_map(|line| line.strip_prefix("data: "))
                .filter_map(|data| serde_json::from_str::<Value>(data).ok())
                .find(|frame| frame.get("method").is_none() && frame["id"] == json!(id))
                .ok_or_else(|| invalid("MCP discovery has no final response"))?
        } else {
            serde_json::from_slice(&bytes).map_err(|_| invalid("Invalid MCP discovery JSON"))?
        };
    if let Some(error) = frame.get("error") {
        return Err(super::probe_rejection(error, false).into());
    }
    Ok((frame["result"].clone(), parts.headers))
}

async fn list_tools(state: &AppState, principal: &Principal, id: Id, headers: &HeaderMap) -> ApiResult<Value> {
    let mut collected = Vec::new();
    let mut cursors = std::collections::BTreeSet::new();
    let mut names = std::collections::BTreeSet::new();
    let mut params = json!({});
    for page in 0..32 {
        let (mut result, _) =
            request(state, principal, id, headers, "tools/list", params.clone(), Some(page + 2)).await?;
        let tools = result["tools"].as_array().ok_or_else(|| invalid("MCP tools/list omitted its tools array"))?;
        for tool in tools {
            let name = tool["name"]
                .as_str()
                .filter(|name| !name.is_empty())
                .ok_or_else(|| invalid("MCP returned a tool without a name"))?;
            if !names.insert(name.to_string()) {
                return Err(invalid("MCP returned duplicate tool names across pages").into());
            }
            collected.push(tool.clone());
        }
        if collected.len() > 5000 || serde_json::to_vec(&collected)?.len() > 4 * MAX_FRAME {
            return Err(invalid("MCP discovery exceeds 5000 tools or 4 MiB; narrow the upstream catalog").into());
        }
        match result.get("nextCursor").filter(|cursor| !cursor.is_null()) {
            None => {
                result["tools"] = json!(collected);
                return Ok(result);
            }
            Some(value) => {
                let cursor = value
                    .as_str()
                    .filter(|cursor| !cursor.is_empty())
                    .ok_or_else(|| invalid("Invalid MCP tools cursor"))?;
                if !cursors.insert(cursor.to_string()) {
                    return Err(invalid("MCP tools pagination repeated its cursor").into());
                }
                params["cursor"] = json!(cursor);
            }
        }
    }
    Err(invalid("MCP discovery exceeds 32 pages; narrow the upstream catalog").into())
}
