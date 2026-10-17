use super::super::authority::Submission;
use super::{archive, completion, input, observe, preview, views, workflow};
use crate::{ApiResult, Principal, routes::ApiJson, state::AppState};
use agf_core::{error::DomainError, ids::Id};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::HeaderMap,
    routing::{get, post, put},
};
use serde_json::{Value, json};
use std::sync::Arc;

pub(in super::super) fn router() -> Router<AppState> {
    Router::new()
        .route("/alicloud/schedulerx3/native/jobs", get(list))
        .route("/alicloud/schedulerx3/native/jobs/previews", post(prepare))
        .route("/alicloud/schedulerx3/native/jobs/previews/{id}", get(preview_receipt))
        .route("/alicloud/schedulerx3/native/jobs/operations/{id}", put(apply).get(receipt))
        .route("/alicloud/schedulerx3/native/jobs/operations/{id}/observe", post(readback))
        .route("/alicloud/schedulerx3/native/jobs/operations/{id}/recover", post(recover))
        .route("/alicloud/schedulerx3/native/jobs/operations/archive", post(archive_rows))
        .layer(DefaultBodyLimit::max(64 * 1024))
}
fn capture(state: &AppState, principal: Principal, headers: &HeaderMap, write: bool) -> ApiResult<Arc<Submission>> {
    let submission = if write {
        Submission::capture_management(state, principal, headers)?
    } else {
        Submission::capture(state, principal, headers, false)?
    };
    submission.principal.require(state, "alicloud", "read")?;
    Ok(Arc::new(submission))
}
fn parse<T: serde::de::DeserializeOwned>(body: Value) -> Result<T, DomainError> {
    serde_json::from_value(body).map_err(|_| input::invalid())
}
fn empty(body: Value) -> Result<(), DomainError> {
    if body != json!({}) {
        return Err(input::invalid());
    }
    Ok(())
}
async fn list(State(state): State<AppState>, principal: Principal, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let submission = capture(&state, principal, &headers, false)?;
    Ok(Json(Box::pin(views::list(&state, &submission)).await?))
}
async fn prepare(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> ApiResult<Json<Value>> {
    let submission = capture(&state, principal, &headers, true)?;
    let row = Box::pin(preview::create(&state, &submission, parse(body)?)).await?;
    Ok(Json(Box::pin(views::preview(&state, &submission, &row)).await?))
}
async fn apply(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(id): Path<Id>,
    ApiJson(body): ApiJson<Value>,
) -> ApiResult<Json<Value>> {
    let submission = capture(&state, principal, &headers, true)?;
    Box::pin(workflow::apply(&state, submission.clone(), id, parse(body)?)).await?;
    Ok(Json(Box::pin(views::receipt(&state, &submission, id)).await?))
}
async fn receipt(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    let submission = capture(&state, principal, &headers, false)?;
    Ok(Json(Box::pin(views::receipt(&state, &submission, id)).await?))
}
async fn preview_receipt(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    let submission = capture(&state, principal, &headers, false)?;
    let row = Box::pin(views::load_preview(&state, submission.principal.tenant, id)).await?;
    Ok(Json(Box::pin(views::preview(&state, &submission, &row)).await?))
}
async fn readback(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(id): Path<Id>,
    ApiJson(body): ApiJson<Value>,
) -> ApiResult<Json<Value>> {
    empty(body)?;
    let submission = capture(&state, principal, &headers, true)?;
    Box::pin(observe::observe(&state, &submission, id)).await?;
    Ok(Json(Box::pin(views::receipt(&state, &submission, id)).await?))
}
async fn recover(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(id): Path<Id>,
    ApiJson(body): ApiJson<Value>,
) -> ApiResult<Json<Value>> {
    empty(body)?;
    let submission = capture(&state, principal, &headers, true)?;
    Box::pin(completion::recover(&state, &submission, id)).await?;
    Ok(Json(Box::pin(views::receipt(&state, &submission, id)).await?))
}
async fn archive_rows(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> ApiResult<Json<Value>> {
    let submission = capture(&state, principal, &headers, true)?;
    let row = Box::pin(archive::archive(&state, &submission, parse(body)?)).await?;
    Ok(Json(json!({"generation":row.generation,"archivedCount":row.archived_count,
        "storedContentBytes":row.stored_bytes,"stateVersion":row.version})))
}
