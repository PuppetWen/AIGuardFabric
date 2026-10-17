//! 将模型请求接入租户 Rego/CEL/结构化策略和规则检测。
use crate::{middleware::Principal, state::AppState};
use agf_aigw::{gateway::CallContext, wire::ChatRequest};
use agf_core::{
    enums::{InterceptPoint, PolicyAction},
    error::{DomainError, DomainResult},
    policy::PolicyContext,
    time::Timestamp,
};
use agf_scan::engine::{ScanRequest, ScanTarget, ScanTargetKind};

pub(super) async fn enforce(
    state: &AppState,
    principal: &Principal,
    call: &mut CallContext,
    request: &mut ChatRequest,
) -> DomainResult<()> {
    let payload = serde_json::to_value(&request.messages)?;
    let text = serde_json::to_string(&payload)?;
    let scan = ScanRequest::new("gateway-preflight").with_target(ScanTarget::new(
        "model-request",
        ScanTargetKind::Prompt,
        &text,
    ));
    let rules = crate::rule_store::pack(state, principal.tenant).await?;
    let result = state.scan_engine.scan(principal.tenant, &rules, &scan).await?;
    let engine = state.runtime_registry.get(state, principal.tenant).await?;
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
        payload,
        payload_bytes: text.len() as u64,
        risk_domains: result.findings.iter().map(|f| f.domain).collect(),
        max_severity: Some(result.max_severity),
        data_class: call.data_class,
        now: Timestamp::now(),
    };
    let decision = match engine.evaluate(context.clone()).await {
        Ok(decision) => decision,
        Err(DomainError::PolicyDenied { policy, reason, .. }) => agf_core::policy::PolicyDecision {
            action: PolicyAction::Deny,
            policy_name: Some(policy),
            reason,
            ..agf_core::policy::PolicyDecision::allow("")
        },
        Err(error) => return Err(error),
    };
    let (excerpt, _) = engine.redact_text(&text);
    let record = engine.record_decision(&context, &decision, &excerpt.chars().take(256).collect::<String>())?;
    state.configurations.put(principal.tenant, "runtime-interception", record.id, &record).await?;
    if decision.dry_run {
        return Ok(());
    }
    match decision.action {
        PolicyAction::Deny | PolicyAction::Isolate | PolicyAction::CircuitBreak | PolicyAction::Approval => {
            return Err(DomainError::PolicyDenied {
                policy: decision.policy_name.unwrap_or_else(|| "runtime".into()),
                action: decision.action.as_str().into(),
                reason: decision.reason,
            });
        }
        PolicyAction::Throttle | PolicyAction::Quota => {
            let quotas = crate::quota_definitions::list(state, principal.tenant).await?;
            if !quotas.iter().any(|q| q.enabled && q.limit > 0 && decision.quota_id.is_none_or(|id| q.id == id)) {
                return Err(DomainError::PreconditionFailed(
                    "策略要求配额，但没有有效配额；请先在配额管理中配置".into(),
                ));
            }
            // 在 gateway_quota::Lease 中原子消费，禁止仅查询快照后放行。
        }
        PolicyAction::Degrade => {
            let endpoint = decision
                .degrade_endpoint_id
                .ok_or_else(|| DomainError::PreconditionFailed("降级策略缺少目标模型端点".into()))?;
            request.model = endpoint.to_string();
            call.allow_fallback = false;
        }
        _ => {}
    }
    if decision.redact || decision.action == PolicyAction::Redact {
        let (redacted, _) = engine.redact_json(&context.payload);
        request.messages = serde_json::from_value(redacted)?;
    }
    Ok(())
}
