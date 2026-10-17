//! 可执行运行时入口与黑名单维护；请求中的租户不能覆盖认证主体。
use crate::mcp_gateway::usage::{self, Outcome};
use crate::{error::ApiResult, middleware::Principal, routes::ApiJson, state::AppState};
use agf_core::{
    enums::{DataClass, InterceptPoint},
    error::DomainError,
    policy::PolicyContext,
    time::Timestamp,
};
use agf_runtime::mcp_proxy::InterceptOutcome;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{patch, post},
};
use serde::Deserialize;
use serde_json::{Value, json};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/runtime/blacklists", post(add))
        .route("/runtime/blacklists/{id}", patch(update).delete(delete))
        .route("/runtime/mcp/check", post(check))
        .route("/runtime/mcp/usage", axum::routing::get(runtime_usage))
        .route("/runtime/events/{id}/integrity", axum::routing::get(record_integrity))
}
#[derive(Debug, Deserialize)]
struct Toggle {
    enabled: bool,
    expected_version: u64,
}
#[derive(Debug, Deserialize)]
struct DeleteVersion {
    expected_version: u64,
}
async fn add(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(body): ApiJson<crate::runtime_rules::NewRule>,
) -> ApiResult<Json<Value>> {
    let submission = crate::runtime_rules::Submission::capture(&state, &principal, &headers)?;
    let entry = crate::runtime_rules::add(&state, &submission, body).await?;
    Ok(Json(json!({"id":entry.rule.id,"version":entry.version})))
}
async fn update(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Toggle>,
) -> ApiResult<Json<Value>> {
    let submission = crate::runtime_rules::Submission::capture(&state, &principal, &headers)?;
    let entry =
        crate::runtime_rules::update(&state, &submission, id, Some(body.enabled), body.expected_version).await?;
    Ok(Json(json!({"id":entry.rule.id,"enabled":entry.enabled,"version":entry.version})))
}
async fn delete(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    Query(version): Query<DeleteVersion>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let submission = crate::runtime_rules::Submission::capture(&state, &principal, &headers)?;
    let entry = crate::runtime_rules::update(&state, &submission, id, None, version.expected_version).await?;
    Ok(Json(json!({"deleted":true,"version":entry.version})))
}
#[derive(Debug, Deserialize)]
pub(crate) struct Check {
    pub agent_id: Option<agf_core::ids::Id>,
    pub frame: Value,
    pub session_id: String,
    #[serde(default)]
    pub response: bool,
    pub lease_id: Option<agf_core::ids::Id>,
    #[serde(default)]
    pub finished: bool,
}
async fn check(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<Check>,
) -> ApiResult<Json<Value>> {
    Ok(Json(intercept(&state, &principal, body, true).await?))
}

async fn runtime_usage(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Value>> {
    principal.require(&state, "policies", "read")?;
    Ok(Json(usage::runtime_snapshot(&state, principal.tenant).await?))
}

/// 核对一个已保存事实；不改变 events 裸数组，不把诊断环形记录视为已签名证据。
async fn record_integrity(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<agf_core::ids::Id>,
) -> ApiResult<Json<crate::runtime_audit::RecordIntegrity>> {
    Ok(Json(crate::runtime_audit::integrity(&state, &principal, id).await?))
}

pub(crate) async fn intercept(
    state: &AppState,
    principal: &Principal,
    mut body: Check,
    remote_lease: bool,
) -> ApiResult<Value> {
    principal.require(state, "policies", "read")?;
    if body.response {
        body.frame = crate::mcp_gateway::safe_upstream_frame(body.frame);
    }
    if body.session_id.is_empty() || body.session_id.len() > 128 {
        return Err(DomainError::Validation("会话标识长度须为 1..128".into()).into());
    }
    let owner = format!("{}:{}", principal.subject_id.map(|id| id.to_string()).unwrap_or_default(), body.session_id);
    if body.finished {
        let id = body.lease_id.ok_or_else(|| DomainError::Validation("缺少调用租约".into()))?;
        crate::runtime_quota::finish_remote(state, principal.tenant, id, &owner).await?;
        if remote_lease {
            usage::finish_runtime(state, principal.tenant, id, &owner, Outcome::Unknown).await?;
        }
        return Ok(json!({"allowed":true}));
    }
    if !body.response && body.frame["method"] == "tools/call" {
        let valid_id = body
            .frame
            .get("id")
            .is_some_and(|id| id.is_number() || id.as_str().is_some_and(|value| value.len() <= 128));
        if !valid_id {
            return Err(DomainError::Validation("tools/call 请求 id 须为不超过 128 字节的字符串或数字".into()).into());
        }
    }
    let raw = serde_json::to_string(&body.frame)?;
    let agent_id = principal.resolve_agent(body.agent_id)?;
    if let Some(id) = agent_id {
        if state
            .store
            .asset_get_durable(principal.tenant, id)
            .await?
            .is_none_or(|asset| asset.kind != agf_core::enums::AssetKind::Agent)
        {
            return Err(DomainError::Validation("Agent 不属于当前租户或不是 Agent 资产".into()).into());
        }
    }
    let completed_lease = body.response && body.frame.get("method").is_none();
    if completed_lease {
        if let Some(id) = body.lease_id {
            if remote_lease {
                usage::verify_runtime_result(state, principal.tenant, id, &owner, &body.frame["id"]).await?;
            }
            crate::runtime_quota::finish_remote(state, principal.tenant, id, &owner).await?;
        }
    }
    if let Err(error) =
        crate::containment::enforce(state, principal.tenant, agent_id, &body.session_id, &body.frame, true).await
    {
        if remote_lease && completed_lease {
            if let Some(id) = body.lease_id {
                usage::finish_runtime(state, principal.tenant, id, &owner, Outcome::Failed).await?;
            }
        }
        return Err(error.into());
    }
    let context = PolicyContext {
        tenant_id: principal.tenant,
        session_id: body.session_id,
        agent_id,
        department: principal.department.clone(),
        intercept_point: InterceptPoint::McpProxy,
        tool_name: None,
        path: None,
        domain: None,
        command: None,
        payload: body.frame.clone(),
        payload_bytes: raw.len() as u64,
        risk_domains: Vec::new(),
        max_severity: None,
        data_class: DataClass::Internal,
        now: Timestamp::now(),
    };
    let engine = state.runtime_registry.get(state, principal.tenant).await?;
    let audit_cursor = engine.audit().total();
    let outcome = if body.response && body.frame.get("method").is_none() {
        engine.intercept_mcp_response(&context, &raw).await?
    } else {
        engine.intercept_mcp_request(context.clone(), &raw).await?
    };
    let mut result = match outcome {
        InterceptOutcome::Forward => json!({"allowed":true,"frame":body.frame}),
        InterceptOutcome::ForwardRedacted { payload, .. } => {
            // 只覆盖被内核检查过的参数/结果，保留 JSON-RPC 扩展元数据。
            let parsed: Value = serde_json::from_str(&payload)?;
            let mut frame = body.frame.clone();
            for key in ["params", "result", "error"] {
                if let Some(value) = parsed.get(key) {
                    frame[key] = value.clone();
                }
            }
            json!({"allowed":true,"frame":frame,"redacted":true})
        }
        InterceptOutcome::Blocked { decision } => json!({"allowed":false,"reason":decision.reason}),
        InterceptOutcome::Throttled { retry_after } => {
            json!({"allowed":false,"reason":"已达配额上限","retry_after":retry_after})
        }
        InterceptOutcome::NeedsApproval { id, link } => {
            json!({"allowed":false,"reason":"需要人工审批","approval_id":id,"link":link})
        }
        InterceptOutcome::Degraded { reason } => json!({"allowed":false,"reason":reason}),
    };
    for record in engine
        .audit()
        .session_since(principal.tenant, &context.session_id, audit_cursor)
        .map_err(DomainError::Internal)?
    {
        if let Err(error) = crate::runtime_audit::persist(state, principal, &record).await {
            // response 的并发租约已在判定前释放；保存失败仍须关闭原工具用量，不能留下 running。
            // request 直到全部事实提交后才 acquire，因此此分支不创建租约或工具尝试。
            if remote_lease && completed_lease {
                if let Some(id) = body.lease_id {
                    usage::finish_runtime(state, principal.tenant, id, &owner, Outcome::Failed).await?;
                }
            }
            return Err(error.into());
        }
    }
    if remote_lease && completed_lease {
        if let Some(id) = body.lease_id {
            let status = if result["allowed"] == true { usage::response_outcome(&body.frame) } else { Outcome::Failed };
            usage::finish_runtime(state, principal.tenant, id, &owner, status).await?;
        }
    }
    if remote_lease && !body.response && result["allowed"] == true && body.frame["method"] == "tools/call" {
        let lease = crate::runtime_quota::Lease::acquire(
            state,
            principal.tenant,
            context.agent_id,
            &context.session_id,
            &owner,
            &agf_core::quota::QuotaConsumption::one_request(),
        )
        .await?;
        let id = lease.detach();
        if let Err(error) = usage::begin_runtime(
            state,
            principal.tenant,
            id,
            &owner,
            result["frame"].pointer("/params/name").and_then(Value::as_str),
            &result["frame"]["id"],
        )
        .await
        {
            crate::runtime_quota::abort_remote(state, principal.tenant, id, &owner).await?;
            return Err(error.into());
        }
        result["lease_id"] = json!(id);
    }
    Ok(result)
}
