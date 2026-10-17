//! HTTP forwarding preserves JSON-RPC messages while applying the same checks as the stdio proxy.
use super::{
    MAX_FRAME,
    config::{self, Endpoint, Transport},
    cursor, invalid, oauth, protocol, rpc_error, sessions, stream, usage,
};
use crate::{
    ApiResult, Principal,
    routes::runtime_control::{self, Check},
    runtime_quota::Lease,
    state::AppState,
};
use agf_core::{error::DomainError, ids::Id, quota::QuotaConsumption};
use axum::{
    Json,
    body::Bytes,
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use std::time::Duration;

pub(super) const UPSTREAM_UNAUTHORIZED: &str =
    "MCP upstream rejected its configured credential (401). Update the upstream bearer token or reconnect MCP OAuth";
pub(super) const UPSTREAM_FORBIDDEN: &str =
    "MCP upstream denied this request (403). Check the upstream token audience and tool scopes";

#[derive(Clone)]
pub(super) struct Context {
    pub state: AppState,
    pub principal: Principal,
    pub endpoint_id: Id,
    pub session: String,
    pub request_id: Value,
    pub modern: bool,
    pub idle: Duration,
}

impl Context {
    pub(super) async fn inspect(&self, frame: Value, response: bool) -> ApiResult<Value> {
        let frame = if response { super::safe_upstream_frame(frame) } else { frame };
        crate::containment::enforce_http_mcp(
            &self.state,
            self.principal.tenant,
            self.principal.agent_id,
            &self.session,
            &frame,
            self.endpoint_id,
        )
        .await?;
        let checked = runtime_control::intercept(
            &self.state,
            &self.principal,
            Check {
                agent_id: None,
                frame,
                session_id: self.session.clone(),
                response,
                lease_id: None,
                finished: false,
            },
            false,
        )
        .await?;
        if checked["allowed"] != true {
            return Err(DomainError::Forbidden(
                checked["reason"].as_str().unwrap_or("MCP policy rejected the message").into(),
            )
            .into());
        }
        Ok(checked["frame"].clone())
    }
}

pub(crate) async fn forward(
    state: AppState,
    principal: Principal,
    id: Id,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    principal.require(&state, "mcps", "execute")?;
    principal.require(&state, "policies", "read")?;
    let endpoint = config::get(&state, principal.tenant, id).await?;
    if !endpoint.enabled {
        return Err(DomainError::PreconditionFailed("此 MCP HTTP 端点已停用".into()).into());
    }
    if endpoint.transport != Transport::StreamableHttp {
        return Err(
            DomainError::PreconditionFailed("旧版 SSE 端点须使用独立的 /mcp/legacy/{id}/sse 路径".into()).into()
        );
    }
    if headers.contains_key("origin")
        && !protocol::text(&headers, "origin")
            .is_some_and(|origin| endpoint.allowed_origins.iter().any(|allowed| allowed == origin))
    {
        return Ok(rpc_error(
            StatusCode::FORBIDDEN,
            &Value::Null,
            -32000,
            "Origin is not permitted by this MCP endpoint",
        ));
    }
    let frame: Value = if method == Method::POST {
        match serde_json::from_slice(&body) {
            Ok(frame) => frame,
            Err(_) => return Ok(rpc_error(StatusCode::BAD_REQUEST, &Value::Null, -32700, "Invalid JSON")),
        }
    } else {
        Value::Null
    };
    let version = protocol::version(&headers, &frame);
    let modern = version == protocol::MODERN;
    let request_id = frame.get("id").cloned().unwrap_or(Value::Null);
    if !protocol::VERSIONS.contains(&version.as_str()) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({"jsonrpc":"2.0","id":request_id,"error":{
            "code":-32022,"message":"Unsupported MCP protocol version","data":{"supported":protocol::VERSIONS}}})),
        )
            .into_response());
    }
    if modern && method != Method::POST {
        return Ok(rpc_error(
            StatusCode::METHOD_NOT_ALLOWED,
            &Value::Null,
            -32600,
            "This MCP version only supports POST",
        ));
    }
    if headers.contains_key("last-event-id") && (modern || method != Method::GET) {
        return Ok(rpc_error(
            StatusCode::BAD_REQUEST,
            &request_id,
            -32600,
            "Last-Event-ID is only supported for legacy Streamable HTTP GET recovery",
        ));
    }
    if method == Method::POST {
        if !protocol::valid_frame(&frame, modern) {
            return Ok(rpc_error(StatusCode::BAD_REQUEST, &request_id, -32600, "Expected one JSON-RPC 2.0 message"));
        }
        if let Err(error) = protocol::validate(&headers, &frame) {
            return Ok(rpc_error(StatusCode::BAD_REQUEST, &request_id, -32020, &error.to_string()));
        }
    }
    let proxy_session = if modern {
        None
    } else {
        protocol::text(&headers, "mcp-session-id")
            .map(Id::parse)
            .transpose()
            .map_err(|_| invalid("Invalid MCP session ID"))?
    };
    if method != Method::POST && proxy_session.is_none() {
        return Ok(rpc_error(StatusCode::BAD_REQUEST, &Value::Null, -32600, "Mcp-Session-Id is required"));
    }
    let upstream_session = match proxy_session {
        Some(id) => Some(sessions::resolve(&state, &principal, &endpoint, id).await?),
        None => None,
    };
    let context = Context {
        state: state.clone(),
        principal: principal.clone(),
        endpoint_id: id,
        session: proxy_session
            .map_or_else(|| format!("mcp:{id}:{}", principal.subject_id.unwrap_or_default()), |id| id.to_string()),
        request_id: request_id.clone(),
        modern,
        idle: Duration::from_secs(endpoint.idle_timeout_secs),
    };
    let outgoing = if method == Method::POST { context.inspect(frame.clone(), false).await? } else { frame.clone() };
    if method == Method::GET {
        crate::containment::enforce_http_mcp(
            &state,
            principal.tenant,
            principal.agent_id,
            &context.session,
            &frame,
            id,
        )
        .await?;
    }
    let mut outgoing_headers = protocol::outgoing(&headers, &frame, &outgoing)?;
    if let Some(session) = upstream_session {
        outgoing_headers.insert(
            "mcp-session-id",
            HeaderValue::from_str(&session).map_err(|_| invalid("Invalid upstream MCP session"))?,
        );
    }
    if let Some(value) = headers.get("last-event-id") {
        let event_cursor = value.to_str().map_err(|_| invalid("Invalid MCP event cursor"))?;
        let session = proxy_session.ok_or_else(|| invalid("MCP session is required for event recovery"))?;
        let upstream_event = cursor::open(&state, &principal, endpoint.id, endpoint.version, session, event_cursor)?;
        outgoing_headers.insert(
            "last-event-id",
            HeaderValue::from_str(&upstream_event).map_err(|_| invalid("Invalid upstream MCP event cursor"))?,
        );
    }
    if let Some(token) = oauth::credential(&state, principal.tenant, &endpoint).await? {
        let mut value =
            HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| invalid("Invalid upstream bearer token"))?;
        value.set_sensitive(true);
        outgoing_headers.insert("authorization", value);
    }
    let lease = if outgoing["method"] == "tools/call" {
        Some(
            Lease::acquire(
                &state,
                principal.tenant,
                principal.agent_id,
                &context.session,
                &principal.display(),
                &QuotaConsumption::one_request(),
            )
            .await?,
        )
    } else {
        None
    };
    let mut lease = lease.map(|lease| if modern { lease } else { lease.retain_on_disconnect() });
    let mut attempt = if lease.is_some() {
        Some(
            usage::Attempt::begin(
                &state,
                principal.tenant,
                id,
                outgoing.pointer("/params/name").and_then(Value::as_str),
            )
            .await?,
        )
    } else {
        None
    };
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(upstream_error)?;
    let mut request = client.request(method.clone(), &endpoint.url).headers(outgoing_headers);
    if method == Method::POST {
        request = request.json(&outgoing);
    }
    let response = match tokio::time::timeout(context.idle, request.send()).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) if error.is_connect() => {
            if let Some(reservation) = lease.take() {
                reservation.finish(Some(&QuotaConsumption::default())).await?;
            }
            if let Some(sample) = attempt.take() {
                sample.finish(usage::Outcome::NotDelivered).await?;
            }
            return Err(upstream_error(error).into());
        }
        Ok(Err(error)) => return Err(upstream_error(error).into()),
        Err(_) => {
            return Err(invalid("MCP upstream did not send response headers before the configured timeout").into());
        }
    };
    respond(context, endpoint, response, lease, attempt, proxy_session, method, frame["method"] == "initialize").await
}

fn upstream_error(error: reqwest::Error) -> DomainError {
    DomainError::DependencyUnavailable { dependency: "mcp-upstream".into(), cause: error.without_url().to_string() }
}

async fn respond(
    context: Context,
    endpoint: Endpoint,
    mut upstream: reqwest::Response,
    mut lease: Option<Lease>,
    mut attempt: Option<usage::Attempt>,
    session: Option<Id>,
    method: Method,
    initializing: bool,
) -> ApiResult<Response> {
    let status = upstream.status();
    let mut session = session;
    if !status.is_success() {
        if let Some(lease) = lease.take() {
            // An explicit HTTP rejection settles the attempt and releases concurrency.
            lease.finish(None).await?;
        }
        if let Some(sample) = attempt.take() {
            sample.finish(usage::Outcome::Failed).await?;
        }
    }
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        let message = if status == StatusCode::UNAUTHORIZED { UPSTREAM_UNAUTHORIZED } else { UPSTREAM_FORBIDDEN };
        return Ok(rpc_error(StatusCode::BAD_GATEWAY, &context.request_id, -32000, message));
    }
    let content_type = protocol::text(upstream.headers(), "content-type").unwrap_or_default().to_string();
    let mut response_headers = HeaderMap::new();
    for key in ["mcp-protocol-version", "retry-after"] {
        if let Some(value) = upstream.headers().get(key) {
            response_headers.insert(key, value.clone());
        }
    }
    if !context.modern {
        if let Some(upstream_session) = protocol::text(upstream.headers(), "mcp-session-id") {
            let id = if let Some(id) = session {
                id
            } else if initializing && status.is_success() {
                sessions::open(&context.state, &context.principal, &endpoint, upstream_session).await?
            } else {
                return Err(invalid("Unexpected MCP session assignment outside initialize").into());
            };
            response_headers.insert(
                "mcp-session-id",
                HeaderValue::from_str(&id.to_string()).map_err(|_| invalid("Invalid proxy session"))?,
            );
            session = Some(id);
        }
        if status == StatusCode::NOT_FOUND || (method == Method::DELETE && status.is_success()) {
            if let Some(id) = session {
                sessions::remove(&context.state, &context.principal, &endpoint, id).await?;
            }
        }
    }
    if status.is_redirection() {
        return Ok(rpc_error(
            StatusCode::BAD_GATEWAY,
            &context.request_id,
            -32000,
            "Upstream redirects are disabled; configure the final MCP endpoint URL",
        ));
    }
    if !status.is_success() {
        // An upstream error frame can contain credentials or internal diagnostics. The
        // proxy has already settled the lease and invalidated a missing session.
        let (public_status, message) = match status {
            StatusCode::NOT_FOUND if session.is_some() => {
                (StatusCode::NOT_FOUND, "MCP upstream session is no longer available; initialize a new session")
            }
            StatusCode::TOO_MANY_REQUESTS => (StatusCode::TOO_MANY_REQUESTS, "MCP upstream rate limit exceeded"),
            _ => (StatusCode::BAD_GATEWAY, "MCP upstream returned an error status; check its URL and health"),
        };
        return Ok(rpc_error(public_status, &context.request_id, -32000, message));
    }
    if matches!(status, StatusCode::ACCEPTED | StatusCode::NO_CONTENT) {
        if let Some(sample) = attempt.take() {
            sample.finish(usage::Outcome::Failed).await?;
        }
        if method == Method::POST && !context.request_id.is_null() {
            return Ok(rpc_error(
                StatusCode::BAD_GATEWAY,
                &context.request_id,
                -32000,
                "MCP upstream accepted a request without returning its JSON-RPC response",
            ));
        }
        if let Some(lease) = lease {
            lease.finish(None).await?;
        }
        return Ok((status, response_headers).into_response());
    }
    if content_type.split(';').next() == Some("text/event-stream") && status.is_success() {
        let recovery = if context.modern { None } else { session.map(|id| (id, endpoint.version)) };
        return Ok(stream::response(context, upstream, lease, attempt, response_headers, recovery));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = tokio::time::timeout(context.idle, upstream.chunk())
        .await
        .map_err(|_| invalid("MCP upstream response timed out"))?
        .map_err(upstream_error)?
    {
        if bytes.len() + chunk.len() > MAX_FRAME {
            return Err(invalid("MCP upstream JSON response exceeds 1 MiB").into());
        }
        bytes.extend_from_slice(&chunk);
    }
    // The entire HTTP response arrived, so the tool attempt is no longer in flight.
    // Even a malformed or policy-rejected payload must settle the legacy lease.
    if let Some(lease) = lease.take() {
        lease.finish(None).await?;
    }
    if bytes.is_empty() && (method == Method::DELETE || !status.is_success()) {
        return Ok((status, response_headers).into_response());
    }
    let frame: Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => {
            if let Some(sample) = attempt.take() {
                sample.finish(usage::Outcome::Failed).await?;
            }
            return Ok(rpc_error(
                StatusCode::BAD_GATEWAY,
                &context.request_id,
                -32000,
                "MCP upstream returned a non-JSON response; check its URL and credential",
            ));
        }
    };
    if !protocol::valid_frame(&frame, false) {
        if let Some(sample) = attempt.take() {
            sample.finish(usage::Outcome::Failed).await?;
        }
        return Ok(rpc_error(
            StatusCode::BAD_GATEWAY,
            &context.request_id,
            -32000,
            "MCP upstream returned an invalid JSON-RPC message",
        ));
    }
    if !context.request_id.is_null() && (frame.get("method").is_some() || frame["id"] != context.request_id) {
        if let Some(sample) = attempt.take() {
            sample.finish(usage::Outcome::Failed).await?;
        }
        return Ok(rpc_error(
            StatusCode::BAD_GATEWAY,
            &context.request_id,
            -32000,
            "MCP upstream response ID mismatch",
        ));
    }
    let result = usage::response_outcome(&frame);
    let checked = context.inspect(frame, true).await;
    if let Some(sample) = attempt.take() {
        sample.finish(if checked.is_ok() { result } else { usage::Outcome::Failed }).await?;
    }
    let checked = checked?;
    Ok((status, response_headers, Json(checked)).into_response())
}
