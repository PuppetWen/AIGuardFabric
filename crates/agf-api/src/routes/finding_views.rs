//! A scan label is the inspected target, not the name of an associated inventory asset.
use super::*;
use crate::{middleware::Principal, query::ListQuery};
use agf_core::risk::Finding;
use axum::extract::Path;
use std::collections::BTreeMap;

pub(super) async fn names(state: &AppState, principal: &Principal, ids: &[Id]) -> ApiResult<BTreeMap<Id, String>> {
    if principal.require(state, "assets", "read").is_err() {
        return Ok(BTreeMap::new());
    }
    Ok(state.store.asset_names(principal.tenant, ids).await?)
}

pub(super) fn view(finding: &Finding, names: &BTreeMap<Id, String>) -> serde_json::Value {
    let name = finding.asset_id.and_then(|id| names.get(&id));
    let mut value = serde_json::json!(finding);
    value["asset_name"] = serde_json::json!(name);
    value["can_read_asset"] = serde_json::json!(name.is_some());
    value
}

/// 风险发现列表（`GET /api/v1/findings`）。
///
/// # Errors
/// 过滤参数非法或存储错误。
pub async fn list_findings(
    State(state): State<AppState>,
    principal: Principal,
    query: ListQuery,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "findings", "read")?;
    let filters = super::finding_filters::parse(&query)?;
    let page = state.store.finding_list_durable(principal.tenant, &query.to_page_request(), filters).await?;
    let ids: Vec<_> = page.items.iter().filter_map(|finding| finding.asset_id).collect();
    let names = if query.fields.is_empty()
        || query.fields.iter().any(|field| matches!(field.as_str(), "asset_name" | "can_read_asset"))
    {
        super::finding_views::names(&state, &principal, &ids).await?
    } else {
        BTreeMap::new()
    };
    let page = page.map(|finding| super::finding_views::view(&finding, &names));
    let mut value = query.render_page(&page)?;
    value["can_write"] = serde_json::json!(principal.require(&state, "findings", "write").is_ok());
    Ok(Json(value))
}

/// 发现详情（`GET /api/v1/findings/{id}`）。
///
/// # Errors
/// 发现不存在。
pub async fn get_finding(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "findings", "read")?;
    let finding_id = parse_id(&id, "finding")?;
    let Some(finding) = state.store.finding_get_durable(principal.tenant, finding_id).await? else {
        return Err(ApiError::new(DomainError::NotFound { entity: "finding", id: id.clone() }));
    };
    let names =
        super::finding_views::names(&state, &principal, &finding.asset_id.into_iter().collect::<Vec<_>>()).await?;
    Ok(Json(serde_json::json!({
        "finding": super::finding_views::view(&finding, &names),
        "three_piece_evidence": finding.has_three_piece_evidence(),
        "chains_consistent": finding.chains_consistent(),
        "report_ready": finding.is_report_ready(),
    })))
}
