use super::super::authority::{self, Submission};
use super::{admission, completion, current, input, model::Fact, start, views};
use crate::{ApiError, ApiResult, Principal, state::AppState};
use agf_core::{error::DomainResult, ids::Id};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, FromRequest, Path, Request, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde_json::Value;
use std::sync::Arc;

struct CallbackJson(Value);

impl FromRequest<AppState> for CallbackJson {
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<Value>::from_request(request, state).await.map_err(|rejection| {
            let status = if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE { 413 } else { 400 };
            ApiError::new(input::invalid()).with_status(status)
        })?;
        Ok(Self(value))
    }
}

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/alicloud/schedulerx3/native/callback-executions", post(admit))
        .route("/alicloud/schedulerx3/native/callback-executions/{id}/validate", post(validate))
        .route("/alicloud/schedulerx3/native/callback-executions/{id}/complete", post(complete))
        .route("/alicloud/schedulerx3/native/callback-executions/{id}", get(status))
        .route("/alicloud/schedulerx3/native/callback-executions/requests/{id}", get(request_status))
        .layer(DefaultBodyLimit::max(64 * 1024))
}
fn parse<T: serde::de::DeserializeOwned>(value: Value) -> DomainResult<T> {
    serde_json::from_value(value).map_err(|_| input::invalid())
}
fn initial(state: &AppState, principal: Principal, headers: &HeaderMap) -> ApiResult<Submission> {
    let submission = Submission::capture(state, principal, headers, false)?;
    current::service(state, &submission.principal)?;
    submission.principal.require(state, "alicloud", "read")?;
    Ok(submission)
}
async fn execution(
    state: &AppState,
    principal: Principal,
    headers: &HeaderMap,
    id: Id,
) -> DomainResult<(Arc<Submission>, Fact)> {
    prepare(state, principal, headers, id, false).await
}
async fn prepare(
    state: &AppState,
    principal: Principal,
    headers: &HeaderMap,
    id: Id,
    by_request: bool,
) -> DomainResult<(Arc<Submission>, Fact)> {
    let initial = initial(state, principal, headers).map_err(|error| error.error)?;
    // Capture before the first read; discovering the server-owned kind does not renew this budget.
    authority::bounded(
        initial.deadline,
        Box::pin(async {
            initial.authorize(state).await?;
            let row = if by_request {
                views::load_request(state, initial.principal.tenant, id).await?
            } else {
                views::load(state, initial.principal.tenant, id).await?
            };
            let mut submission = Submission::capture_execution(state, initial.principal, headers, &row.context.kind)?;
            submission.submitted_at = initial.submitted_at;
            submission.deadline = initial.deadline;
            current::owner(state, &submission, &row.context.owner).await?;
            Ok((Arc::new(submission), row))
        }),
    )
    .await
}
async fn admit(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    CallbackJson(body): CallbackJson,
) -> ApiResult<Json<Value>> {
    let input: input::AdmissionInput = parse(body)?;
    input.validate()?;
    let submission = Submission::capture_execution(&state, principal, &headers, &input.kind)?;
    current::service(&state, &submission.principal)?;
    let (row, first) =
        authority::bounded(submission.deadline, Box::pin(admission::admit(&state, &submission, input))).await?;
    Ok(Json(views::receipt(&state, &submission, &row, first, false).await?))
}
async fn validate(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(id): Path<Id>,
    CallbackJson(body): CallbackJson,
) -> ApiResult<Json<Value>> {
    let input: input::ClaimInput = parse(body)?;
    let (submission, _) = execution(&state, principal, &headers, id).await?;
    let (row, first) =
        authority::bounded(submission.deadline, Box::pin(start::consume(&state, &submission, id, input.claim_id)))
            .await?;
    Ok(Json(views::receipt(&state, &submission, &row, false, first).await?))
}
async fn complete(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(id): Path<Id>,
    CallbackJson(body): CallbackJson,
) -> ApiResult<Json<Value>> {
    let input: input::CompleteInput = parse(body)?;
    let (submission, _) = execution(&state, principal, &headers, id).await?;
    let row = completion::complete(&state, submission.clone(), id, input).await?;
    Ok(Json(views::receipt(&state, &submission, &row, false, false).await?))
}
async fn status(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    let (submission, row) = execution(&state, principal, &headers, id).await?;
    Ok(Json(views::receipt(&state, &submission, &row, false, false).await?))
}
async fn request_status(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    let (submission, row) = prepare(&state, principal, &headers, id, true).await?;
    Ok(Json(views::receipt(&state, &submission, &row, false, false).await?))
}
