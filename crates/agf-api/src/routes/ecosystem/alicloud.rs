//! 阿里云服务与自检路由（自 `routes/ecosystem.rs` 拆出，逻辑未变）。

use super::*;

// ===========================================================================
// 阿里云
// ===========================================================================

/// 阿里云服务适配器清单（`GET /api/v1/alicloud/services`）。
///
/// # Errors
/// 权限不足。
pub async fn alicloud_services(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "alicloud", "read")?;
    let views = alicloud_views(&state, principal.tenant).await?;
    Ok(Json(serde_json::json!({
        "items": views,
        "total": views.len(),
        "tenant_id": principal.tenant,
        "descriptors": state.alicloud.descriptors().len(),
        "names": state.alicloud.names(),
    })))
}

/// 云环境自检页数据（`GET /api/v1/alicloud/selfcheck`）。
///
/// # Errors
/// 权限不足。
pub async fn alicloud_selfcheck(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "alicloud", "read")?;
    Ok(Json(crate::cloud_status::report(&state, principal.tenant).await?))
}

/// 云环境自检（Markdown 渲染，`GET /api/v1/alicloud/selfcheck/markdown`）。
///
/// # Errors
/// 权限不足。
pub async fn alicloud_selfcheck_markdown(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<axum::response::Response> {
    use axum::response::IntoResponse;
    principal.require(&state, "alicloud", "read")?;
    let report = crate::cloud_status::report(&state, principal.tenant).await?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
        report["markdown"].as_str().unwrap_or_default().to_string(),
    )
        .into_response())
}

/// 战役状态标签（供报表与前端复用）。
#[must_use]
pub const fn campaign_state_label(state: CampaignState) -> &'static str {
    state.as_str()
}
