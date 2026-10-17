//! Five explicit endpoints; GET never initializes provider state or publishes terminal facts.
use super::{archive, authority::Submission, binding, input, observation, views};
use crate::{ApiResult, Principal, routes::ApiJson, state::AppState};
use agf_core::{error::DomainError, ids::Id};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State, rejection::QueryRejection},
    http::HeaderMap,
    routing::{get, post, put},
};
use serde_json::Value;
use std::sync::Arc;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/alicloud/schedulerx3/native", get(list))
        .route("/alicloud/schedulerx3/native/observe", post(observe))
        .route("/alicloud/schedulerx3/native/observations/{id}", get(receipt))
        .route("/alicloud/schedulerx3/native/bindings", put(save_binding))
        .route("/alicloud/schedulerx3/native/observations/archive", post(archive_records))
        .merge(super::callback_execution::router())
        .merge(super::job_management::router())
        .layer(DefaultBodyLimit::max(64 * 1024))
}
fn capture(state: &AppState, principal: Principal, headers: &HeaderMap, write: bool) -> ApiResult<Arc<Submission>> {
    let submission = Submission::capture(state, principal, headers, write)?;
    submission.principal.require(state, "alicloud", "read")?;
    if write {
        submission.principal.require(state, "alicloud", "write")?;
    }
    Ok(Arc::new(submission))
}
fn parse<T: serde::de::DeserializeOwned>(body: Value) -> Result<T, DomainError> {
    serde_json::from_value(body).map_err(|_| DomainError::Validation("Scheduler 请求字段或类型无效".into()))
}
async fn list(State(state): State<AppState>, principal: Principal, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let submission = capture(&state, principal, &headers, false)?;
    Ok(Json(Box::pin(views::list(&state, &submission)).await?))
}
async fn observe(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> ApiResult<Json<Value>> {
    let input: input::ObserveInput = parse(body)?;
    let submission = capture(&state, principal, &headers, input.initialize_mock_fixture)?;
    let fact = Box::pin(observation::observe(&state, submission.clone(), input)).await?;
    Ok(Json(Box::pin(views::receipt(&state, &submission, fact.request_id, &input::PageQuery::default())).await?))
}
async fn receipt(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(id): Path<Id>,
    query: Result<Query<input::PageQuery>, QueryRejection>,
) -> ApiResult<Json<Value>> {
    let submission = capture(&state, principal, &headers, false)?;
    let Query(page) = query.map_err(|_| DomainError::Validation("Scheduler 分页参数无效".into()))?;
    Ok(Json(Box::pin(views::receipt(&state, &submission, id, &page)).await?))
}
async fn save_binding(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> ApiResult<Json<Value>> {
    let submission = capture(&state, principal, &headers, true)?;
    let row = Box::pin(binding::save(&state, &submission, parse(body)?)).await?;
    Ok(Json(views::binding_result(&state, &submission, &row).await?))
}
async fn archive_records(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> ApiResult<Json<Value>> {
    let submission = capture(&state, principal, &headers, true)?;
    let row = Box::pin(archive::archive(&state, &submission, parse(body)?)).await?;
    Ok(Json(
        serde_json::json!({"generation":row.generation,"archivedCount":row.archived_count,"storedContentBytes":row.stored_bytes,"stateVersion":row.version}),
    ))
}
