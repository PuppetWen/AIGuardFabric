use super::append_agent;
use crate::{AppState, Principal, error::ApiResult, routes::ApiJson};
use agf_core::{
    audit::{AgentAuditAcknowledgement, AgentAuditBatch},
    enums::AssetKind,
    error::DomainError,
};
use axum::{Json, Router, extract::State, routing::post};

/// Agent 检查点路由；仅信任当前有效且绑定真实 Agent 资产的 API Key。
pub fn router() -> Router<AppState> {
    Router::new().route("/runtime/audit/anchors", post(append))
}

async fn append(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(batch): ApiJson<AgentAuditBatch>,
) -> ApiResult<Json<AgentAuditAcknowledgement>> {
    principal.require(&state, "policies", "read")?;
    let agent = principal
        .agent_id
        .ok_or_else(|| DomainError::Forbidden("Audit upload requires an Agent-bound API Key".into()))?;
    if !crate::tenant_directory::get(&state, principal.tenant).await?.enabled {
        return Err(DomainError::Forbidden("Tenant is disabled".into()).into());
    }
    let asset = state
        .store
        .asset_get_durable(principal.tenant, agent)
        .await?
        .ok_or_else(|| DomainError::NotFound { entity: "agent", id: agent.to_string() })?;
    if asset.kind != AssetKind::Agent {
        return Err(DomainError::Forbidden("API Key binding is not an Agent asset".into()).into());
    }
    Ok(Json(append_agent(&state, &principal, agent, batch).await?))
}
