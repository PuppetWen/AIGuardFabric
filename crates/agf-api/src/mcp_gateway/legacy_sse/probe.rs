//! Read-only 2024 HTTP+SSE discovery through the same authenticated proxy paths clients use.
use super::{Event, decode_event, listen, post, session};
use crate::{ApiResult, Principal, state::AppState};
use agf_core::ids::Id;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
};
use futures::{Stream, StreamExt};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fmt::Display, time::Duration};

const PROBE_TIMEOUT: Duration = Duration::from_secs(12);

pub(crate) async fn run(
    state: &AppState,
    principal: &Principal,
    endpoint: &super::super::config::Endpoint,
) -> ApiResult<(Value, Value, bool)> {
    let response = tokio::time::timeout(
        PROBE_TIMEOUT,
        listen::listen(State(state.clone()), principal.clone(), Path(endpoint.id), HeaderMap::new()),
    )
    .await
    .map_err(|_| super::super::invalid("MCP SSE discovery connection timed out"))??;
    let mut stream = response.into_body().into_data_stream();
    let mut decoder = super::super::stream::Decoder::default();
    let announced = next_event(&mut stream, &mut decoder).await?;
    if announced.kind != "endpoint" {
        return Err(super::super::invalid("MCP SSE discovery did not receive a POST endpoint").into());
    }
    let prefix =
        format!("{}/mcp/legacy/{}/messages/", state.config.server.api_prefix.trim_end_matches('/'), endpoint.id);
    let session_id = announced
        .data
        .strip_prefix(&prefix)
        .and_then(|value| Id::parse(value).ok())
        .ok_or_else(|| super::super::invalid("MCP SSE discovery received an invalid POST endpoint"))?;
    let queried = async {
        let server = request(
            state,
            principal,
            endpoint.id,
            session_id,
            &mut stream,
            &mut decoder,
            "initialize",
            json!({"protocolVersion":"2024-11-05","capabilities":{},
                "clientInfo":{"name":"AIGuardFabric probe","version":crate::VERSION}}),
            Some(1),
        )
        .await?;
        if server["protocolVersion"] != "2024-11-05" {
            return Err(super::super::invalid("MCP SSE server did not negotiate protocol 2024-11-05").into());
        }
        request(
            state,
            principal,
            endpoint.id,
            session_id,
            &mut stream,
            &mut decoder,
            "notifications/initialized",
            json!({}),
            None,
        )
        .await?;
        let tools = list_tools(state, principal, endpoint.id, session_id, &mut stream, &mut decoder).await?;
        Ok::<_, crate::ApiError>((server, tools))
    }
    .await;
    let closed = session::close(state, principal, endpoint, session_id).await.is_ok();
    let (server, tools) = queried?;
    Ok((server, tools, closed))
}

async fn request<S, E>(
    state: &AppState,
    principal: &Principal,
    endpoint_id: Id,
    session_id: Id,
    stream: &mut S,
    decoder: &mut super::super::stream::Decoder,
    method: &str,
    params: Value,
    request_id: Option<u64>,
) -> ApiResult<Value>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: Display,
{
    let mut frame = json!({"jsonrpc":"2.0","method":method,"params":params});
    if let Some(id) = request_id {
        frame["id"] = json!(id);
    }
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    let response = post::post(
        State(state.clone()),
        principal.clone(),
        Path((endpoint_id, session_id)),
        headers,
        Bytes::from(frame.to_string()),
    )
    .await?;
    if response.status() != StatusCode::ACCEPTED {
        return Err(super::super::invalid("MCP SSE discovery POST was not accepted").into());
    }
    let Some(expected) = request_id else { return Ok(Value::Null) };
    for _ in 0..64 {
        let event = next_event(stream, decoder).await?;
        if event.kind != "message" {
            return Err(super::super::invalid("MCP SSE discovery received an unexpected event").into());
        }
        let message: Value =
            serde_json::from_str(&event.data).map_err(|_| super::super::invalid("Invalid MCP SSE discovery JSON"))?;
        if message.get("method").is_some() || message["id"] != json!(expected) {
            continue;
        }
        if let Some(error) = message.get("error") {
            return Err(super::super::probe_rejection(error, true).into());
        }
        return Ok(message["result"].clone());
    }
    Err(super::super::invalid("MCP SSE discovery received too many unrelated messages").into())
}

async fn next_event<S, E>(stream: &mut S, decoder: &mut super::super::stream::Decoder) -> ApiResult<Event>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: Display,
{
    tokio::time::timeout(PROBE_TIMEOUT, async {
        loop {
            while let Some(block) = decoder.take_block() {
                if let Some(event) = decode_event(block) {
                    return Ok(event);
                }
            }
            let chunk = stream
                .next()
                .await
                .ok_or_else(|| super::super::invalid("MCP SSE discovery stream closed"))?
                .map_err(|_| super::super::invalid("MCP SSE discovery stream failed"))?;
            decoder.push(&chunk).map_err(super::super::invalid)?;
        }
    })
    .await
    .map_err(|_| super::super::invalid("MCP SSE discovery response timed out"))?
}

async fn list_tools<S, E>(
    state: &AppState,
    principal: &Principal,
    endpoint_id: Id,
    session_id: Id,
    stream: &mut S,
    decoder: &mut super::super::stream::Decoder,
) -> ApiResult<Value>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: Display,
{
    let mut collected = Vec::new();
    let mut cursors = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut params = json!({});
    for page in 0..32 {
        let mut result = request(
            state,
            principal,
            endpoint_id,
            session_id,
            stream,
            decoder,
            "tools/list",
            params.clone(),
            Some(page + 2),
        )
        .await?;
        let tools = result["tools"]
            .as_array()
            .ok_or_else(|| super::super::invalid("MCP SSE tools/list omitted its tools array"))?;
        for tool in tools {
            let name = tool["name"]
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| super::super::invalid("MCP SSE returned a tool without a name"))?;
            if !names.insert(name.to_owned()) {
                return Err(super::super::invalid("MCP SSE returned duplicate tool names").into());
            }
            collected.push(tool.clone());
        }
        if collected.len() > 5000 || serde_json::to_vec(&collected)?.len() > 4 * super::super::MAX_FRAME {
            return Err(super::super::invalid("MCP SSE discovery exceeds 5000 tools or 4 MiB").into());
        }
        match result.get("nextCursor").filter(|value| !value.is_null()) {
            None => {
                result["tools"] = json!(collected);
                return Ok(result);
            }
            Some(value) => {
                let cursor = value
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| super::super::invalid("Invalid MCP SSE tools cursor"))?;
                if !cursors.insert(cursor.to_owned()) {
                    return Err(super::super::invalid("MCP SSE pagination repeated its cursor").into());
                }
                params["cursor"] = json!(cursor);
            }
        }
    }
    Err(super::super::invalid("MCP SSE discovery exceeds 32 pages").into())
}
