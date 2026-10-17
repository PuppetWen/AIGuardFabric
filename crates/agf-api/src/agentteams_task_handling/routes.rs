//! Five local endpoints. No handler invokes a vendor API or dispatches application work.
use super::{ArchiveInput, ResolutionInput, authority::Submission, operations, query, util, views};
use crate::{ApiError, ApiResult, Principal, state::AppState};
use agf_core::{error::DomainResult, ids::Id};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, FromRequest, Path, Query, Request, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    routing::{get, post, put},
};
use serde_json::Value;

struct SafeJson(Value);
impl FromRequest<AppState> for SafeJson {
    type Rejection = ApiError;
    async fn from_request(request: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<Value>::from_request(request, state).await.map_err(|rejection| {
            let status = if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE { 413 } else { 400 };
            ApiError::new(util::invalid()).with_status(status)
        })?;
        Ok(Self(value))
    }
}
pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/alicloud/agentteams/task-handling", get(list))
        .route("/alicloud/agentteams/task-handling/events/{id}", get(detail))
        .route("/alicloud/agentteams/task-handling/events/{id}/resolution", put(resolve))
        .route("/alicloud/agentteams/task-handling/archive", post(archive))
        .route("/alicloud/agentteams/task-handling/requests/{id}", get(receipt))
        .layer(DefaultBodyLimit::max(64 * 1024))
}
fn capture(state: &AppState, principal: Principal, headers: &HeaderMap, write: bool) -> ApiResult<Submission> {
    let submission = Submission::capture(state, principal, headers, write)?;
    for (resource, action) in
        if write { [("alicloud", "write"), ("sources", "write")] } else { [("alicloud", "read"), ("sources", "read")] }
    {
        submission.principal.require(state, resource, action)?;
    }
    Ok(submission)
}
fn parse<T: serde::de::DeserializeOwned>(value: Value) -> DomainResult<T> {
    serde_json::from_value(value).map_err(|_| util::invalid())
}
async fn list(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    query: Result<Query<query::Query>, QueryRejection>,
) -> ApiResult<Json<Value>> {
    let submission = capture(&state, principal, &headers, false)?;
    let Query(input) = query.map_err(|_| util::invalid())?;
    Ok(Json(views::list(&state, &submission, input).await?))
}
async fn detail(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    let submission = capture(&state, principal, &headers, false)?;
    Ok(Json(views::detail(&state, &submission, id).await?))
}
async fn receipt(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    let submission = capture(&state, principal, &headers, false)?;
    Ok(Json(views::request(&state, &submission, id).await?))
}
async fn resolve(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(id): Path<Id>,
    SafeJson(body): SafeJson,
) -> ApiResult<Json<Value>> {
    let submission = capture(&state, principal, &headers, true)?;
    let input: ResolutionInput = parse(body)?;
    let row = operations::resolve(&state, &submission, id, input).await?;
    Ok(Json(views::resolution(&row)))
}
async fn archive(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    SafeJson(body): SafeJson,
) -> ApiResult<Json<Value>> {
    let submission = capture(&state, principal, &headers, true)?;
    let input: ArchiveInput = parse(body)?;
    let row = operations::archive(&state, &submission, input).await?;
    Ok(Json(views::archive(&row)))
}
