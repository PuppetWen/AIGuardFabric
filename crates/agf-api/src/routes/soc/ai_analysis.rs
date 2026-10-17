//! Explicit manual analysis: request bodies cannot supply raw content, tenant or model overrides.
use super::*;
use crate::security_analysis::{self, Purpose};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EmptyInput {}

pub(super) async fn analyze_alert(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(_input): ApiJson<EmptyInput>,
) -> ApiResult<Json<serde_json::Value>> {
    security_analysis::authorize(&state, &principal, Purpose::Alert, true)?;
    let snapshot = security_analysis::load_alert(&state, &principal, parse_id(&id, "alert")?).await?;
    let analysis = security_analysis::analyze(&state, &principal, snapshot).await?;
    Ok(Json(serde_json::json!({"analysis":analysis})))
}

pub(super) async fn analyze_case(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(_input): ApiJson<EmptyInput>,
) -> ApiResult<Json<serde_json::Value>> {
    security_analysis::authorize(&state, &principal, Purpose::Case, true)?;
    let snapshot = security_analysis::load_case(&state, &principal, parse_id(&id, "case")?).await?;
    let analysis = security_analysis::analyze(&state, &principal, snapshot).await?;
    Ok(Json(serde_json::json!({"analysis":analysis})))
}

pub(super) async fn alert_analysis(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let analysis = security_analysis::latest(&state, &principal, Purpose::Alert, parse_id(&id, "alert")?).await?;
    Ok(Json(serde_json::json!({"analysis":analysis})))
}

pub(super) async fn case_analysis(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let analysis = security_analysis::latest(&state, &principal, Purpose::Case, parse_id(&id, "case")?).await?;
    Ok(Json(serde_json::json!({"analysis":analysis})))
}
