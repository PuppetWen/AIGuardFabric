//! 红队用例库、战役与报告路由（自 `routes/ecosystem.rs` 拆出，逻辑未变）。

use super::*;

// ===========================================================================
// 红队
// ===========================================================================

/// 红队用例库（`GET /api/v1/redteam/cases`）。
///
/// # Errors
/// 权限不足。
pub async fn list_redteam_cases(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "redteam", "read")?;
    let cases: Vec<serde_json::Value> = state
        .redteam_cases
        .cases()
        .iter()
        .filter(|c| query.filter("category").is_none_or(|want| c.category.as_str() == want.trim().to_ascii_lowercase()))
        .filter(|c| query.filter("severity").is_none_or(|want| c.severity.as_str() == want))
        .filter(|c| query.filter("tag").is_none_or(|tag| c.tags.iter().any(|t| t.eq_ignore_ascii_case(tag))))
        .filter(|c| {
            query
                .filter("agent_http_compatible")
                .is_none_or(|value| (value == "true") == agf_scan::redteam::AgentHttpTarget::supports_case(c))
        })
        .filter(|c| {
            query
                .filter("mcp_http_compatible")
                .is_none_or(|value| (value == "true") == agf_scan::redteam::McpHttpTarget::supports_case(c))
        })
        .map(|c| {
            serde_json::json!({
                "key": c.key,
                "title": c.title,
                "category": c.category.as_str(),
                "domain": c.category.domain().as_str(),
                "severity": c.severity.as_str(),
                "mode": c.mode.as_str(),
                "turns": c.turns.len(),
                "applies_to": c.applies_to,
                "required_tools": c.required_tools,
                "tags": c.tags,
                "public_poc": c.public_poc,
                "version": c.version,
                "agent_http_compatible": agf_scan::redteam::AgentHttpTarget::supports_case(c),
                "mcp_http_compatible": agf_scan::redteam::McpHttpTarget::supports_case(c),
                "validation_error": c.validate().err(),
            })
        })
        .collect();
    let page = query.paginate_vec(
        &cases,
        |v| {
            format!(
                "{} {}",
                v.get("key").and_then(|x| x.as_str()).unwrap_or_default(),
                v.get("title").and_then(|x| x.as_str()).unwrap_or_default()
            )
        },
        |v| v.get("key").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
    );
    Ok(Json(query.render_page(&page)?))
}

/// Read-only detail for a library case; opening it never executes a campaign.
pub async fn get_redteam_case(
    State(state): State<AppState>,
    principal: Principal,
    Path(key): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "redteam", "read")?;
    let case = state
        .redteam_cases
        .cases()
        .iter()
        .find(|c| c.key == key)
        .ok_or(DomainError::NotFound { entity: "redteam-case", id: key })?;
    Ok(Json(serde_json::to_value(case)?))
}

/// 红队用例库统计（`GET /api/v1/redteam/stats`）。
///
/// # Errors
/// 权限不足。
pub async fn redteam_stats(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "redteam", "read")?;
    let library = &state.redteam_cases;
    let missing: Vec<String> = library.missing_categories().into_iter().map(|c| c.as_str().to_string()).collect();
    let campaigns = state.store.campaign_list_durable(principal.tenant).await?;
    let mut by_state: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for campaign in &campaigns {
        *by_state.entry(campaign.state.as_str().to_string()).or_insert(0) += 1;
    }
    Ok(Json(serde_json::json!({
        "library": serde_json::to_value(library.stats())?,
        "missing_categories": missing,
        "target_case_count": agf_core::constants::REDTEAM_TARGET_CASE_COUNT,
        "meets_target": library.stats().meets_target(agf_core::constants::REDTEAM_TARGET_CASE_COUNT),
        "campaigns": { "total": campaigns.len(), "by_state": by_state },
    })))
}

/// 解析攻击类别。
///
/// # Errors
/// 未知类别。
pub fn parse_attack_category(raw: &str) -> Result<AttackCategory, ApiError> {
    let wanted = raw.trim().to_ascii_lowercase().replace('_', "-");
    AttackCategory::all()
        .into_iter()
        .find(|c| c.as_str() == wanted)
        .ok_or_else(|| ApiError::new(DomainError::Validation(format!("未知攻击类别: {raw}"))))
}
