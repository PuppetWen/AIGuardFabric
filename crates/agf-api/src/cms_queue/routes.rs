use super::{archive, authority::Submission, completion, enqueue, input, send, util, views};
use crate::{ApiError, Principal, routes::ApiJson, state::AppState};
use agf_core::ids::Id;
use axum::{
    Json, Router,
    extract::{Path, Query, State, rejection::QueryRejection},
    http::HeaderMap,
    routing::{get, post},
};
use serde_json::Value;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/alicloud/cms/queue", get(state))
        .route("/alicloud/cms/queue/items/{id}", get(item))
        .route("/alicloud/cms/queue/requests/{id}", get(request))
        .route("/alicloud/cms/queue/enqueue", post(enqueue_item))
        .route("/alicloud/cms/queue/send", post(send_items))
        .route("/alicloud/cms/queue/items/{id}/recover-local", post(recover))
        .route("/alicloud/cms/queue/archive", post(archive_items))
        .layer(axum::extract::DefaultBodyLimit::max(512 * 1024))
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
async fn item(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(id): Path<Id>,
) -> Result<Json<Value>, ApiError> {
    let submission = Submission::capture(&state, principal, &headers, false)?;
    submission.authorize(&state).await?;
    let value = super::authority::bounded(submission.deadline, views::item(&state, &submission, id)).await?;
    submission.authorize(&state).await?;
    Ok(Json(value))
}
async fn request(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(id): Path<Id>,
) -> Result<Json<Value>, ApiError> {
    let submission = Submission::capture(&state, principal, &headers, false)?;
    Ok(Json(Box::pin(super::authority::bounded(submission.deadline, views::request(&state, &submission, id))).await?))
}
async fn enqueue_item(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(value): ApiJson<Value>,
) -> Result<Json<Value>, ApiError> {
    let submission = Submission::capture(&state, principal, &headers, true)?;
    let input: input::Enqueue = serde_json::from_value(value).map_err(|_| util::invalid())?;
    let row = Box::pin(enqueue::enqueue(&state, &submission, input)).await?;
    Ok(Json(
        Box::pin(super::authority::bounded(submission.deadline, views::request(&state, &submission, row.id))).await?,
    ))
}
async fn send_items(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(value): ApiJson<Value>,
) -> Result<Json<Value>, ApiError> {
    let submission = Submission::capture(&state, principal, &headers, true)?;
    let input: input::Send = serde_json::from_value(value).map_err(|_| util::invalid())?;
    let row = Box::pin(send::send(&state, &submission, input)).await?;
    Ok(Json(
        Box::pin(super::authority::bounded(submission.deadline, views::request(&state, &submission, row.id))).await?,
    ))
}
async fn archive_items(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(value): ApiJson<Value>,
) -> Result<Json<Value>, ApiError> {
    let submission = Submission::capture(&state, principal, &headers, true)?;
    let input: input::Archive = serde_json::from_value(value).map_err(|_| util::invalid())?;
    let row = Box::pin(archive::archive(&state, &submission, input)).await?;
    Ok(Json(
        Box::pin(super::authority::bounded(submission.deadline, views::request(&state, &submission, row.id))).await?,
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
    completion::recover(&state, &submission, id).await?;
    Ok(Json(Box::pin(super::authority::bounded(submission.deadline, views::item(&state, &submission, id))).await?))
}
