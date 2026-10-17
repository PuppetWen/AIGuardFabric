//! Client JSON-RPC messages use the upstream POST URI discovered on the SSE stream.
use super::super::{forward::Context, invalid, protocol, usage};
use super::{authorized, session};
use crate::{
    ApiResult, Principal,
    runtime_quota::{self, Lease},
    state::AppState,
};
use agf_core::{error::DomainError, ids::Id, quota::QuotaConsumption};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::Value;
use std::time::Duration;

pub(crate) async fn post(
    State(state): State<AppState>,
    principal: Principal,
    Path((endpoint_id, session_id)): Path<(Id, Id)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    let endpoint = authorized(&state, &principal, endpoint_id, &headers).await?;
    let content_type = protocol::text(&headers, "content-type").unwrap_or_default();
    if content_type.split(';').next() != Some("application/json") {
        return Err(invalid("MCP SSE messages require Content-Type: application/json").into());
    }
    let frame: Value = serde_json::from_slice(&body).map_err(|_| invalid("MCP SSE message is not JSON"))?;
    if !protocol::valid_frame(&frame, false) {
        return Err(invalid("MCP SSE POST expects one JSON-RPC 2.0 message").into());
    }
    let upstream_url = session::post_url(&state, &principal, &endpoint, session_id).await?;
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(upstream_error)?;
    let credential = super::super::oauth::credential(&state, principal.tenant, &endpoint).await?;
    let request_id = frame.get("id").cloned().unwrap_or(Value::Null);
    let context = Context {
        state: state.clone(),
        principal: principal.clone(),
        endpoint_id,
        session: format!("mcp-sse:{session_id}"),
        request_id: request_id.clone(),
        modern: false,
        idle: Duration::from_secs(endpoint.idle_timeout_secs),
    };
    let outgoing = context.inspect(frame, false).await?;
    let (lease_id, usage_id) = if outgoing["method"] == "tools/call" {
        let lease = Lease::acquire(
            &state,
            principal.tenant,
            principal.agent_id,
            &context.session,
            &principal.display(),
            &QuotaConsumption::one_request(),
        )
        .await?;
        let sample = match usage::Attempt::begin(
            &state,
            principal.tenant,
            endpoint_id,
            outgoing.pointer("/params/name").and_then(Value::as_str),
        )
        .await
        {
            Ok(sample) => sample,
            Err(error) => {
                lease.finish(Some(&QuotaConsumption::default())).await?;
                return Err(error.into());
            }
        };
        let id = lease.detach();
        let sample_id = sample.detach();
        if let Err(error) =
            session::remember_pending(&state, &principal, &endpoint, session_id, &request_id, id, sample_id).await
        {
            if let Err(release_error) =
                runtime_quota::abort_remote(&state, principal.tenant, id, &principal.display()).await
            {
                tracing::warn!(%release_error, "未投递的 MCP SSE 调用配额释放失败");
            }
            if let Err(release_error) =
                usage::finish_remote(&state, principal.tenant, endpoint_id, sample_id, usage::Outcome::NotDelivered)
                    .await
            {
                tracing::warn!(%release_error, "未投递的 MCP SSE 调用用量释放失败");
            }
            return Err(error.into());
        }
        (Some(id), Some(sample_id))
    } else {
        (None, None)
    };
    let mut request = client.post(upstream_url).header("accept", "application/json").json(&outgoing);
    if let Some(token) = credential {
        request = request.bearer_auth(token);
    }
    // After sending a tool call, a timeout cannot prove that the upstream did not execute it.
    // Keep its durable reservation until a checked SSE result arrives or the lease expires.
    let response = match tokio::time::timeout(context.idle, request.send()).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) if error.is_connect() => {
            // No connection was established, so this tool call cannot have reached the server.
            release_rejected(&state, &principal, &endpoint, session_id, &request_id, lease_id, usage_id, false).await;
            return Err(upstream_error(error).into());
        }
        Ok(Err(error)) => return Err(upstream_error(error).into()),
        Err(_) => return Err(invalid("MCP SSE POST response timed out; inspect the session before retrying").into()),
    };
    if !response.status().is_success() || response.status().is_redirection() {
        release_rejected(&state, &principal, &endpoint, session_id, &request_id, lease_id, usage_id, true).await;
        return Err(DomainError::DependencyUnavailable {
            dependency: "mcp-sse-upstream".into(),
            cause: format!("Upstream rejected the MCP SSE POST with status {}", response.status()),
        }
        .into());
    }
    if response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|kind| kind.split(';').next() == Some("application/json"))
    {
        release_rejected(&state, &principal, &endpoint, session_id, &request_id, lease_id, usage_id, true).await;
        return Err(invalid("Legacy MCP SSE upstream returned JSON to POST instead of sending a message event").into());
    }
    Ok(StatusCode::ACCEPTED.into_response())
}

async fn release_rejected(
    state: &AppState,
    principal: &Principal,
    endpoint: &super::super::config::Endpoint,
    session_id: Id,
    request_id: &Value,
    lease_id: Option<Id>,
    usage_id: Option<Id>,
    delivered: bool,
) {
    if let Some(id) = usage_id {
        let outcome = if delivered { usage::Outcome::Failed } else { usage::Outcome::NotDelivered };
        if let Err(error) = usage::finish_remote(state, principal.tenant, endpoint.id, id, outcome).await {
            tracing::warn!(%error, "被拒绝的 MCP SSE 调用用量结算失败");
        }
    }
    if let Some(id) = lease_id {
        let settled = if delivered {
            runtime_quota::finish_remote(state, principal.tenant, id, &principal.display()).await
        } else {
            runtime_quota::abort_remote(state, principal.tenant, id, &principal.display()).await
        };
        if let Err(error) = settled {
            tracing::warn!(%error, "被拒绝的 MCP SSE 调用配额结算失败");
        }
        if let Err(error) = session::forget_pending(state, principal, endpoint, session_id, request_id).await {
            tracing::warn!(%error, "被拒绝的 MCP SSE 调用清理失败");
        }
    }
}

fn upstream_error(error: reqwest::Error) -> DomainError {
    DomainError::DependencyUnavailable { dependency: "mcp-sse-upstream".into(), cause: error.without_url().to_string() }
}
