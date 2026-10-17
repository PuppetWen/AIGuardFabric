//! 四组资源的路由处理器（列表与详情一律走分组元数据）。

use super::*;

// ===========================================================================
// 路由处理器
// ===========================================================================

/// Agent 列表（`GET /api/v1/agents`）。
///
/// # Errors
/// 权限不足、`kind` 非法或存储错误。
pub async fn list_agents(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    list_group(&state, &principal, &query, Group::Agents).await
}

/// Agent 详情（`GET /api/v1/agents/{id}`）。
///
/// # Errors
/// id 非法、资产不存在或类型不是 `agent`。
pub async fn get_agent(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    get_group_asset(&state, &principal, &id, Group::Agents).await
}

/// MCP 列表（`GET /api/v1/mcps` 与别名 `GET /api/v1/mcp-servers`）。
///
/// # Errors
/// 权限不足、`kind` 非法或存储错误。
pub async fn list_mcps(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "mcps", "read")?;
    crate::mcp_gateway::discovery::refresh(&state, principal.tenant).await?;
    list_group(&state, &principal, &query, Group::Mcps).await
}

/// MCP 详情（`GET /api/v1/mcps/{id}` 与别名 `GET /api/v1/mcp-servers/{id}`）。
///
/// # Errors
/// id 非法、资产不存在或类型不是 MCP。
pub async fn get_mcp(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "mcps", "read")?;
    crate::mcp_gateway::discovery::refresh(&state, principal.tenant).await?;
    get_group_asset(&state, &principal, &id, Group::Mcps).await
}

/// Skill 列表（`GET /api/v1/skills`）。
///
/// # Errors
/// 权限不足、`kind` 非法或存储错误。
pub async fn list_skills(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    list_group(&state, &principal, &query, Group::Skills).await
}

/// Skill 详情（`GET /api/v1/skills/{id}`）。
///
/// # Errors
/// id 非法、资产不存在或类型不是 `skill`。
pub async fn get_skill(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    get_group_asset(&state, &principal, &id, Group::Skills).await
}

/// 模型端点列表（`GET /api/v1/models/endpoints`）。
///
/// # Errors
/// 权限不足、`kind` 非法或存储错误。
pub async fn list_model_endpoints(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    list_group(&state, &principal, &query, Group::ModelEndpoints).await
}

/// 模型端点详情（`GET /api/v1/models/endpoints/{id}`）。
///
/// # Errors
/// id 非法、资产不存在或类型不是 `model-endpoint`。
pub async fn get_model_endpoint(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    get_group_asset(&state, &principal, &id, Group::ModelEndpoints).await
}
