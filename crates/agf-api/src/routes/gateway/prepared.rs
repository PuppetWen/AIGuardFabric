//! Shared gateway controls for HTTP clients and internal security analysis.
use super::*;
use agf_aigw::{
    AiGateway,
    gateway::{CallContext, GatewayResponse},
    wire::ChatRequest,
};
use agf_core::{
    enums::{InterceptPoint, PolicyAction},
    error::{DomainError, DomainResult},
    policy::{PolicyContext, PolicyDecision},
    time::Timestamp,
};
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct PreparedCall {
    pub gateway: Arc<AiGateway>,
    pub context: CallContext,
    pub request: ChatRequest,
    pub lease: crate::gateway_quota::Lease,
}

pub(crate) struct EvaluatedCall {
    pub gateway: Arc<AiGateway>,
    pub context: CallContext,
    pub request: ChatRequest,
    pub route: Option<crate::store::ModelRoutePolicy>,
}

pub(crate) async fn evaluate(
    state: &AppState,
    principal: &Principal,
    mut context: CallContext,
    mut request: ChatRequest,
) -> ApiResult<EvaluatedCall> {
    principal.require(state, "models", "write")?;
    let forced_endpoint = crate::containment::enforce(
        state,
        principal.tenant,
        context.agent_id,
        &context.session_id,
        &serde_json::to_value(&request.messages)?,
        false,
    )
    .await?;
    super::policy::enforce(state, principal, &mut context, &mut request).await?;
    request.ensure_anthropic_native_unchanged()?;
    if let Some(endpoint) = forced_endpoint {
        request.model = endpoint.to_string();
        context.allow_fallback = false;
    }
    let policy = crate::model_routes::resolve(state, principal.tenant, &mut request.model, &mut context).await?;
    let gateway = state.model_gateway.for_route(state, principal.tenant, policy.as_ref()).await?;
    if request.max_tokens.is_none() {
        request.max_tokens = Some(1024);
    }
    Ok(EvaluatedCall { gateway, context, request, route: policy })
}

pub(crate) async fn prepare(
    state: &AppState,
    principal: &Principal,
    context: CallContext,
    request: ChatRequest,
) -> ApiResult<PreparedCall> {
    let evaluated = evaluate(state, principal, context, request).await?;
    reserve_legacy(state, principal, evaluated).await
}

pub(crate) async fn reserve_legacy(
    state: &AppState,
    principal: &Principal,
    evaluated: EvaluatedCall,
) -> ApiResult<PreparedCall> {
    let EvaluatedCall { gateway, context, request, route } = evaluated;
    let lease = match crate::gateway_quota::Lease::acquire(state, &context, &gateway, &request, route.as_ref()).await {
        Ok(lease) => lease,
        Err(error @ DomainError::QuotaExceeded { .. }) => {
            if let Err(audit_error) = record_gateway_rejection(
                state,
                principal,
                &context,
                &error.to_string(),
                PolicyAction::Throttle,
                "gateway-quota",
            )
            .await
            {
                tracing::error!(%audit_error, "模型网关配额拒绝审计写入失败");
            }
            return Err(error.into());
        }
        Err(error) => return Err(error.into()),
    };
    Ok(PreparedCall { gateway, context, request, lease })
}

pub(super) async fn record_gateway_rejection(
    state: &AppState,
    principal: &Principal,
    call: &CallContext,
    reason: &str,
    action: PolicyAction,
    policy_name: &str,
) -> DomainResult<()> {
    let context = PolicyContext {
        tenant_id: principal.tenant,
        session_id: call.session_id.clone(),
        agent_id: call.agent_id,
        department: principal.department.clone(),
        intercept_point: InterceptPoint::AiGateway,
        tool_name: None,
        path: None,
        domain: None,
        command: None,
        payload: serde_json::Value::Null,
        payload_bytes: 0,
        risk_domains: Vec::new(),
        max_severity: None,
        data_class: call.data_class,
        now: Timestamp::now(),
    };
    let mut decision = PolicyDecision::allow(reason.to_string());
    decision.action = action;
    decision.policy_name = Some(policy_name.into());
    let engine = state.runtime_registry.get(state, principal.tenant).await?;
    let record = engine.record_decision(&context, &decision, "")?;
    state.configurations.put(principal.tenant, "runtime-interception", record.id, &record).await
}

/// Classify a failed gateway call without persisting an upstream error body.
pub(super) async fn audit_call_error(state: &AppState, principal: &Principal, call: &CallContext, error: &DomainError) {
    let (reason, action, policy) = match error {
        DomainError::PolicyDenied { .. } => {
            ("模型请求被内容安全预筛拒绝", PolicyAction::Deny, "gateway-request-screen")
        }
        DomainError::QuotaExceeded { .. } => ("模型请求超过路由预算", PolicyAction::Throttle, "gateway-budget"),
        _ => ("模型端点调用失败", PolicyAction::Audit, "gateway-call-error"),
    };
    if let Err(audit_error) = record_gateway_rejection(state, principal, call, reason, action, policy).await {
        tracing::error!(%audit_error, "模型调用失败审计写入失败");
    }
}

pub(super) async fn reject_over_limit(
    state: &AppState,
    principal: &Principal,
    call: &CallContext,
    result: &GatewayResponse,
) -> ApiResult<()> {
    if !result.screening.response_rules.iter().any(|rule| rule == "gateway-output-limit") {
        return Ok(());
    }
    let reason = "模型上游输出超过请求的 max_tokens 或 4 MiB 安全上限";
    if let Err(error) =
        record_gateway_rejection(state, principal, call, reason, PolicyAction::Deny, "gateway-output-limit").await
    {
        tracing::error!(%error, "模型网关超额输出审计写入失败");
    }
    Err(DomainError::DependencyUnavailable { dependency: "model-provider".into(), cause: reason.into() }.into())
}

pub(crate) async fn complete(
    state: &AppState,
    principal: &Principal,
    context: CallContext,
    request: ChatRequest,
) -> ApiResult<GatewayResponse> {
    let PreparedCall { gateway, context, request, lease } = prepare(state, principal, context, request).await?;
    let audit_context = context.clone();
    let result = match gateway.chat(context, request).await {
        Ok(result) => result,
        Err(error) => {
            audit_call_error(state, principal, &audit_context, &error).await;
            return Err(error.into());
        }
    };
    lease.finish(Some(&result.usage_record)).await?;
    reject_over_limit(state, principal, &audit_context, &result).await?;
    Ok(result)
}
