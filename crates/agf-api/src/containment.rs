//! Durable containment enforced on every managed MCP/model request.
use crate::{
    model_gateway::{ENDPOINT_KIND, StoredEndpoint},
    state::AppState,
};
use agf_core::{
    case::ContainmentAction,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
pub const KIND: &str = "case-containment";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    pub id: Id,
    pub case_id: Id,
    pub action: ContainmentAction,
    pub target: String,
    pub tools: Vec<String>,
    pub endpoint_id: Option<Id>,
    pub active: bool,
    pub actor: String,
    pub reason: String,
    pub created_at: Timestamp,
    pub released_by: Option<String>,
    pub released_at: Option<Timestamp>,
}
pub async fn list(state: &AppState, tenant: TenantId) -> DomainResult<Vec<Control>> {
    state.configurations.list(tenant, KIND).await
}
pub async fn release(state: &AppState, tenant: TenantId, case: Id, id: Id, actor: &str) -> DomainResult<()> {
    // Serialize release against concurrent requests without restoring an irreversible credential.
    state
        .configurations
        .mutate::<Option<Control>, _>(tenant, KIND, id, |value| {
            let row = value
                .as_mut()
                .filter(|row| row.case_id == case)
                .ok_or_else(|| DomainError::NotFound { entity: "containment", id: id.to_string() })?;
            row.active = false;
            row.released_by = Some(actor.into());
            row.released_at = Some(Timestamp::now());
            Ok(())
        })
        .await?;
    Ok(())
}

/// Reject contained identities/destinations and return a mandatory local model, if configured.
pub async fn enforce(
    state: &AppState,
    tenant: TenantId,
    agent: Option<Id>,
    session: &str,
    payload: &Value,
    mcp: bool,
) -> DomainResult<Option<Id>> {
    let mut endpoint = None;
    let tool = payload.pointer("/params/name").and_then(Value::as_str);
    for row in list(state, tenant).await?.into_iter().filter(|row| row.active) {
        let same_agent = agent.is_some_and(|id| id.to_string() == row.target);
        let denied = match row.action {
            ContainmentAction::IsolateAgent => same_agent,
            ContainmentAction::KillSession => session == row.target,
            ContainmentAction::DisableMcpServer if row.endpoint_id.is_some() => false,
            ContainmentAction::DisableMcpServer | ContainmentAction::RevokeSkill => {
                mcp && tool.is_some_and(|name| row.tools.iter().any(|blocked| blocked == name))
            }
            ContainmentAction::BlockDomain | ContainmentAction::BlockIp => destination_matches(payload, &row.target),
            ContainmentAction::ForceLocalModel if same_agent && !mcp => {
                let id = row.endpoint_id.ok_or_else(|| DomainError::Config("本地模型处置缺少端点".into()))?;
                let stored = state
                    .configurations
                    .get::<StoredEndpoint>(tenant, ENDPOINT_KIND, id)
                    .await?
                    .filter(|record| record.endpoint.enabled && record.endpoint.local_deployment)
                    .ok_or_else(|| {
                        DomainError::PreconditionFailed("强制本地模型的目标不可用，请修复端点或解除处置".into())
                    })?;
                if endpoint.is_some_and(|previous| previous != stored.endpoint.id) {
                    return Err(DomainError::PreconditionFailed("存在冲突的本地模型处置，请先解除旧处置".into()));
                }
                endpoint = Some(stored.endpoint.id);
                false
            }
            _ => false,
        };
        if denied {
            record_denial(state, tenant, agent, session, payload, mcp, &row).await?;
            return Err(DomainError::PolicyDenied {
                policy: format!("case-containment:{}", row.id),
                action: "deny".into(),
                reason: format!("案件 {} 的 {} 已生效：{}", row.case_id, row.action.as_str(), row.reason),
            });
        }
    }
    Ok(endpoint)
}

/// Endpoint identity comes from the authenticated proxy route, never from JSON-RPC arguments.
pub(crate) async fn enforce_http_mcp(
    state: &AppState,
    tenant: TenantId,
    agent: Option<Id>,
    session: &str,
    payload: &Value,
    endpoint: Id,
) -> DomainResult<()> {
    if let Some(row) = list(state, tenant).await?.into_iter().find(|row| {
        row.active && row.action == ContainmentAction::DisableMcpServer && row.endpoint_id == Some(endpoint)
    }) {
        record_denial(state, tenant, agent, session, payload, true, &row).await?;
        return Err(DomainError::PolicyDenied {
            policy: format!("case-containment:{}", row.id),
            action: "deny".into(),
            reason: format!("案件 {} 已停用此 MCP HTTP 端点：{}", row.case_id, row.reason),
        });
    }
    Ok(())
}

async fn record_denial(
    state: &AppState,
    tenant: TenantId,
    agent: Option<Id>,
    session: &str,
    payload: &Value,
    mcp: bool,
    row: &Control,
) -> DomainResult<()> {
    use agf_core::{
        enums::{DataClass, InterceptPoint, PolicyAction},
        policy::{PolicyContext, PolicyDecision},
    };
    let engine = state.runtime_registry.get(state, tenant).await?;
    let raw = serde_json::to_string(payload)?;
    let context = PolicyContext {
        tenant_id: tenant,
        session_id: session.into(),
        agent_id: agent,
        department: None,
        intercept_point: if mcp { InterceptPoint::McpProxy } else { InterceptPoint::AiGateway },
        tool_name: payload.pointer("/params/name").and_then(Value::as_str).map(str::to_owned),
        path: None,
        domain: None,
        command: None,
        payload: payload.clone(),
        payload_bytes: raw.len() as u64,
        risk_domains: Vec::new(),
        max_severity: None,
        data_class: DataClass::Internal,
        now: Timestamp::now(),
    };
    let decision = PolicyDecision {
        action: PolicyAction::Deny,
        policy_name: Some(format!("case-containment:{}", row.id)),
        reason: row.reason.clone(),
        ..PolicyDecision::allow("")
    };
    let excerpt = engine.redact_text(&raw).0.chars().take(256).collect::<String>();
    let record = engine.record_decision(&context, &decision, &excerpt)?;
    state.configurations.put(tenant, "runtime-interception", record.id, &record).await
}

// Inspect structured values and URL tokens; avoid substring matches such as goodexample.com.
fn destination_matches(value: &Value, target: &str) -> bool {
    match value {
        Value::String(text) => text
            .split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '(' | ')' | ','))
            .any(|token| {
                let token = token.trim_end_matches(['.', ';']);
                let host = url::Url::parse(token)
                    .ok()
                    .and_then(|url| url.host_str().map(str::to_owned))
                    .unwrap_or_else(|| token.to_owned())
                    .trim_end_matches('.')
                    .trim_matches(['[', ']'])
                    .to_ascii_lowercase();
                host == target || (target.parse::<std::net::IpAddr>().is_err() && host.ends_with(&format!(".{target}")))
            }),
        Value::Array(items) => items.iter().any(|item| destination_matches(item, target)),
        Value::Object(items) => items.values().any(|item| destination_matches(item, target)),
        _ => false,
    }
}
