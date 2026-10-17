//! Upstream SSE events are inspected before they enter the client stream.
use super::super::{forward::Context, invalid, protocol, stream::Decoder, usage};
use super::{authorized, decode_event, session, validate_post_url};
use crate::{ApiResult, Principal, runtime_quota, state::AppState};
use agf_core::{error::DomainError, ids::Id};
use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, HeaderValue},
    response::Response,
};
use futures::stream;
use serde_json::{Value, json};
use std::{
    convert::Infallible,
    time::{Duration, Instant},
};

pub(crate) async fn listen(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Id>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let endpoint = authorized(&state, &principal, id, &headers).await?;
    crate::containment::enforce_http_mcp(
        &state,
        principal.tenant,
        principal.agent_id,
        &format!("mcp-sse:{id}:{}", principal.display()),
        &Value::Null,
        id,
    )
    .await?;
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(upstream_error)?;
    let mut request = client.get(&endpoint.url).header("accept", "text/event-stream");
    if let Some(token) = super::super::oauth::credential(&state, principal.tenant, &endpoint).await? {
        request = request.bearer_auth(token);
    }
    let idle = Duration::from_secs(endpoint.idle_timeout_secs);
    let mut upstream = tokio::time::timeout(idle, request.send())
        .await
        .map_err(|_| invalid("MCP SSE upstream did not open before the configured timeout"))?
        .map_err(upstream_error)?;
    if !upstream.status().is_success()
        || upstream.status().is_redirection()
        || upstream
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_none_or(|kind| kind.split(';').next() != Some("text/event-stream"))
    {
        return Err(DomainError::DependencyUnavailable {
            dependency: "mcp-sse-upstream".into(),
            cause: format!("Expected a successful SSE response; upstream status was {}", upstream.status()),
        }
        .into());
    }
    let mut decoder = Decoder::default();
    let post_url = 'announce: loop {
        while let Some(block) = decoder.take_block() {
            let Some(event) = decode_event(block) else { continue };
            if event.kind != "endpoint" {
                return Err(invalid("MCP SSE server must advertise a POST endpoint before messages").into());
            }
            break 'announce validate_post_url(&endpoint.url, &event.data)?;
        }
        let chunk = tokio::time::timeout(idle, upstream.chunk())
            .await
            .map_err(|_| invalid("MCP SSE upstream did not advertise a POST endpoint before timeout"))?
            .map_err(upstream_error)?
            .ok_or_else(|| invalid("MCP SSE upstream closed before advertising a POST endpoint"))?;
        decoder.push(&chunk).map_err(invalid)?;
    };
    let session_id = session::open(&state, &principal, &endpoint, post_url.as_str()).await?;
    let prefix = state.config.server.api_prefix.trim_end_matches('/');
    let initial = format!("event: endpoint\ndata: {prefix}/mcp/legacy/{id}/messages/{session_id}\n\n");
    let context = Context {
        state,
        principal,
        endpoint_id: id,
        session: format!("mcp-sse:{session_id}"),
        request_id: Value::Null,
        modern: false,
        idle,
    };
    let now = Instant::now();
    let stream_state = Stream {
        context,
        endpoint,
        upstream,
        decoder,
        session_id,
        initial: Some(initial),
        done: false,
        last_data: now,
        last_heartbeat: now,
        last_renewal: now,
    };
    let body = stream::unfold(stream_state, |mut state| async move {
        if state.done {
            return None;
        }
        let chunk = match state.next().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => return None,
            Err(message) => {
                state.done = true;
                let error = json!({"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":message}});
                format!("event: message\ndata: {error}\n\n")
            }
        };
        Some((Ok::<_, Infallible>(Bytes::from(chunk)), state))
    });
    let mut response = Response::new(Body::from_stream(body));
    response.headers_mut().insert("content-type", HeaderValue::from_static("text/event-stream"));
    response.headers_mut().insert("cache-control", HeaderValue::from_static("no-store"));
    response.headers_mut().insert("x-accel-buffering", HeaderValue::from_static("no"));
    Ok(response)
}

fn upstream_error(error: reqwest::Error) -> DomainError {
    DomainError::DependencyUnavailable { dependency: "mcp-sse-upstream".into(), cause: error.without_url().to_string() }
}

struct Stream {
    context: Context,
    endpoint: super::super::config::Endpoint,
    upstream: reqwest::Response,
    decoder: Decoder,
    session_id: Id,
    initial: Option<String>,
    done: bool,
    last_data: Instant,
    last_heartbeat: Instant,
    last_renewal: Instant,
}

impl Drop for Stream {
    fn drop(&mut self) {
        let state = self.context.state.clone();
        let principal = self.context.principal.clone();
        let endpoint = self.endpoint.clone();
        let session_id = self.session_id;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                // Disconnect does not prove an upstream tool stopped; detached leases expire conservatively.
                let _ = session::close(&state, &principal, &endpoint, session_id).await;
            });
        }
    }
}

impl Stream {
    async fn next(&mut self) -> Result<Option<String>, String> {
        if let Some(initial) = self.initial.take() {
            return Ok(Some(initial));
        }
        loop {
            if self.last_heartbeat.elapsed() >= Duration::from_secs(15) {
                self.heartbeat().await?;
            }
            if let Some(block) = self.decoder.take_block() {
                if let Some(event) = decode_event(block) {
                    if event.kind != "message" {
                        return Err("MCP SSE upstream sent an unexpected event after the endpoint announcement".into());
                    }
                    return self.message(&event.data).await.map(Some);
                }
                continue;
            }
            let remaining = self.context.idle.saturating_sub(self.last_data.elapsed());
            if remaining.is_zero() {
                return Err("MCP SSE upstream exceeded the configured idle timeout".into());
            }
            match tokio::time::timeout(remaining.min(Duration::from_secs(15)), self.upstream.chunk()).await {
                Ok(Ok(Some(chunk))) => {
                    self.last_data = Instant::now();
                    self.decoder.push(&chunk).map_err(str::to_string)?;
                }
                Ok(Ok(None)) => {
                    self.done = true;
                    return Ok(None);
                }
                Ok(Err(_)) => return Err("MCP SSE upstream connection failed; calls were not retried".into()),
                Err(_) => {
                    self.heartbeat().await?;
                    return Ok(Some(": keepalive\n\n".into()));
                }
            }
        }
    }

    async fn heartbeat(&mut self) -> Result<(), String> {
        let ids = session::heartbeat(&self.context.state, &self.context.principal, &self.endpoint, self.session_id)
            .await
            .map_err(|error| error.to_string())?;
        self.last_heartbeat = Instant::now();
        if self.last_renewal.elapsed() >= Duration::from_mins(1) {
            for (id, sample_id) in ids {
                runtime_quota::renew_remote(
                    &self.context.state,
                    self.context.principal.tenant,
                    id,
                    &self.context.principal.display(),
                )
                .await
                .map_err(|error| error.to_string())?;
                if let Some(sample_id) = sample_id {
                    usage::renew_remote(
                        &self.context.state,
                        self.context.principal.tenant,
                        self.endpoint.id,
                        sample_id,
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                }
            }
            self.last_renewal = Instant::now();
        }
        Ok(())
    }

    async fn message(&self, raw: &str) -> Result<String, String> {
        let frame: Value = serde_json::from_str(raw).map_err(|_| "MCP SSE message is not JSON")?;
        if !protocol::valid_frame(&frame, false) {
            return Err("MCP SSE message is not a valid JSON-RPC frame".into());
        }
        let response_id = (frame.get("method").is_none()).then(|| frame.get("id").cloned()).flatten();
        let pending = if let Some(id) = response_id.as_ref() {
            session::pending_for(&self.context.state, &self.context.principal, &self.endpoint, self.session_id, id)
                .await
                .map_err(|error| error.to_string())?
        } else {
            None
        };
        let outcome = usage::response_outcome(&frame);
        let checked = self.context.inspect(frame, true).await;
        if let (Some(request_id), Some((lease_id, sample_id))) = (response_id.as_ref(), pending) {
            let metered = if let Some(sample_id) = sample_id {
                usage::finish_remote(
                    &self.context.state,
                    self.context.principal.tenant,
                    self.endpoint.id,
                    sample_id,
                    if checked.is_ok() { outcome } else { usage::Outcome::Failed },
                )
                .await
            } else {
                Ok(())
            };
            let settled = runtime_quota::finish_remote(
                &self.context.state,
                self.context.principal.tenant,
                lease_id,
                &self.context.principal.display(),
            )
            .await;
            let forgotten = session::forget_pending(
                &self.context.state,
                &self.context.principal,
                &self.endpoint,
                self.session_id,
                request_id,
            )
            .await;
            metered.map_err(|error| error.to_string())?;
            settled.map_err(|error| error.to_string())?;
            forgotten.map_err(|error| error.to_string())?;
        }
        let checked = checked.map_err(|error| error.to_string())?;
        Ok(format!("event: message\ndata: {checked}\n\n"))
    }
}
