use super::{archive, authority::Submission, claim, completion, input, observation, preview, util, views};
use crate::{ApiError, Principal, routes::ApiJson, state::AppState};
use agf_core::ids::Id;
use axum::{
    Json, Router,
    extract::{Path, Query, State, rejection::QueryRejection},
    http::HeaderMap,
    routing::{get, post},
};
use serde_json::Value;
const ROOT: &str = "/alicloud/privatelink/provisioning";
pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(ROOT, get(state))
        .route("/alicloud/privatelink/provisioning/requests/{id}", get(receipt))
        .route("/alicloud/privatelink/provisioning/preview", post(prepare))
        .route("/alicloud/privatelink/provisioning/apply", post(apply))
        .route("/alicloud/privatelink/provisioning/observe", post(observe))
        .route("/alicloud/privatelink/provisioning/requests/{id}/recover-local", post(recover))
        .route("/alicloud/privatelink/provisioning/archive", post(archive))
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
}
async fn state(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    query: Result<Query<views::Page>, QueryRejection>,
) -> Result<Json<Value>, ApiError> {
    let submission = Submission::capture(&state, principal, &headers, false)?;
    let Query(page) = query.map_err(|_| ApiError::from(util::invalid()))?;
    Ok(Json(Box::pin(super::authority::bounded(submission.deadline, views::state(&state, &submission, page))).await?))
}
async fn receipt(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(id): Path<Id>,
) -> Result<Json<Value>, ApiError> {
    let submission = Submission::capture(&state, principal, &headers, false)?;
    Ok(Json(Box::pin(super::authority::bounded(submission.deadline, views::receipt(&state, &submission, id))).await?))
}
async fn prepare(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(value): ApiJson<Value>,
) -> Result<Json<Value>, ApiError> {
    let submission = Submission::capture(&state, principal, &headers, true)?;
    let input: input::Preview = serde_json::from_value(value).map_err(|_| util::invalid())?;
    let row =
        super::authority::bounded(submission.deadline, Box::pin(preview::prepare(&state, &submission, input))).await?;
    Ok(Json(
        Box::pin(super::authority::bounded(submission.deadline, views::receipt(&state, &submission, row.id))).await?,
    ))
}
async fn apply(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(value): ApiJson<Value>,
) -> Result<Json<Value>, ApiError> {
    let submission = Submission::capture(&state, principal, &headers, true)?;
    let input: input::Apply = serde_json::from_value(value).map_err(|_| util::invalid())?;
    let row = Box::pin(claim::apply(&state, &submission, input)).await?;
    Ok(Json(
        Box::pin(super::authority::bounded(submission.deadline, views::receipt(&state, &submission, row.id))).await?,
    ))
}
async fn observe(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(value): ApiJson<Value>,
) -> Result<Json<Value>, ApiError> {
    let submission = Submission::capture(&state, principal, &headers, true)?;
    let input: input::Observe = serde_json::from_value(value).map_err(|_| util::invalid())?;
    let row = Box::pin(observation::observe(&state, &submission, input)).await?;
    Ok(Json(
        Box::pin(super::authority::bounded(submission.deadline, views::receipt(&state, &submission, row.id))).await?,
    ))
}
async fn recover(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(id): Path<Id>,
    ApiJson(value): ApiJson<Value>,
) -> Result<Json<Value>, ApiError> {
    if value != serde_json::json!({}) {
        return Err(util::invalid().into());
    }
    let submission = Submission::capture(&state, principal, &headers, true)?;
    super::authority::bounded(submission.deadline, Box::pin(completion::recover(&state, &submission, id))).await?;
    Ok(Json(Box::pin(super::authority::bounded(submission.deadline, views::receipt(&state, &submission, id))).await?))
}
async fn archive(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(value): ApiJson<Value>,
) -> Result<Json<Value>, ApiError> {
    let submission = Submission::capture(&state, principal, &headers, true)?;
    let input: input::Archive = serde_json::from_value(value).map_err(|_| util::invalid())?;
    let row =
        super::authority::bounded(submission.deadline, Box::pin(archive::archive(&state, &submission, input))).await?;
    Ok(Json(
        Box::pin(super::authority::bounded(submission.deadline, views::receipt(&state, &submission, row.id))).await?,
    ))
}
