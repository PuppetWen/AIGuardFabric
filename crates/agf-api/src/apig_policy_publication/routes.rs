//! Eight strict workflow endpoints. No endpoint accepts raw content, credentials or a dispatch URL.
use super::{archive, authority::Submission, input, observation, operations, preview, recover, views};
use crate::{ApiResult, Principal, routes::ApiJson, state::AppState};
use agf_core::{error::DomainError, ids::Id};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
};
use serde_json::Value;
use std::sync::Arc;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/alicloud/apig/policy-publication", get(list))
        .route("/alicloud/apig/policy-publication/observe", post(observe))
        .route("/alicloud/apig/policy-publication/previews", post(create_preview))
        .route("/alicloud/apig/policy-publication/operations", post(apply))
        .route("/alicloud/apig/policy-publication/operations/{id}", get(operation))
        .route("/alicloud/apig/policy-publication/operations/{id}/observe", post(observe_original))
        .route("/alicloud/apig/policy-publication/operations/{id}/recover", post(recover_local))
        .route("/alicloud/apig/policy-publication/operations/archive", post(archive_records))
        .layer(DefaultBodyLimit::max(64 * 1024))
}
fn capture(state: &AppState, principal: Principal, headers: &HeaderMap, write: bool) -> ApiResult<Arc<Submission>> {
    let submission = Submission::capture(state, principal, headers, write)?;
    submission.principal.require(state, "alicloud", "read")?;
    submission.principal.require(state, "policies", "read")?;
    if write {
        submission.principal.require(state, "alicloud", "write")?;
    }
    Ok(Arc::new(submission))
}

async fn list(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    query: Result<Query<super::eligibility::Query>, axum::extract::rejection::QueryRejection>,
) -> ApiResult<Json<Value>> {
    let submission = capture(&state, principal, &headers, false)?;
    let Query(query) = query.map_err(|_| DomainError::Validation("来源查询字段、类型或范围错误".into()))?;
    query.validate()?;
    Ok(Json(Box::pin(views::list(&state, &submission, &query)).await?))
}
async fn observe(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> ApiResult<Json<Value>> {
    let input: input::ObserveInput = input::parse(body)?;
    let submission = capture(&state, principal, &headers, input.initialize_mock_fixture)?;
    let row = Box::pin(observation::observe(&state, submission.clone(), input)).await?;
    Ok(Json(views::observed(&state, &submission, &row).await?))
}
async fn create_preview(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> ApiResult<Json<Value>> {
    let submission = capture(&state, principal, &headers, true)?;
    let row = Box::pin(preview::create(&state, &submission, input::parse(body)?)).await?;
    Ok(Json(Box::pin(views::prepared(&state, &submission, &row)).await?))
}
async fn apply(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> ApiResult<Json<Value>> {
    let submission = capture(&state, principal, &headers, true)?;
    let fact = Box::pin(operations::apply(&state, submission.clone(), input::parse(body)?)).await?;
    Ok(Json(Box::pin(views::operation(&state, &submission, fact.request_id)).await?))
}
async fn operation(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    let submission = capture(&state, principal, &headers, false)?;
    Ok(Json(Box::pin(views::operation(&state, &submission, id)).await?))
}
async fn observe_original(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(id): Path<Id>,
    ApiJson(body): ApiJson<Value>,
) -> ApiResult<Json<Value>> {
    let submission = capture(&state, principal, &headers, false)?;
    let row = Box::pin(recover::observe(&state, submission.clone(), id, input::parse(body)?)).await?;
    Ok(Json(views::observed(&state, &submission, &row).await?))
}
async fn recover_local(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(id): Path<Id>,
    ApiJson(body): ApiJson<Value>,
) -> ApiResult<Json<Value>> {
    let submission = capture(&state, principal, &headers, true)?;
    input::parse::<input::RecoverInput>(body)?;
    let fact = Box::pin(recover::local(&state, submission.clone(), id)).await?;
    Ok(Json(Box::pin(views::operation(&state, &submission, fact.request_id)).await?))
}
async fn archive_records(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> ApiResult<Json<Value>> {
    let submission = capture(&state, principal, &headers, true)?;
    Ok(Json(Box::pin(archive::archive(&state, &submission, input::parse(body)?)).await?))
}
