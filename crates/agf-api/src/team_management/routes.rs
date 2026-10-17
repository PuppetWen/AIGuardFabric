use super::{
    input::{ApplyInput, ListQuery, PreviewInput, RecoveryInput, UsersInput},
    observe, operations, preview, projection, users,
};
use crate::{ApiResult, Principal, routes::ApiJson, state::AppState};
use agf_core::ids::Id;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    routing::{get, post},
};
use serde_json::Value;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/alicloud/agentteams/team-management", get(list))
        .route("/alicloud/agentteams/team-management/users/observe", post(directory))
        .route("/alicloud/agentteams/team-management/previews", post(create_preview))
        .route("/alicloud/agentteams/team-management/previews/{id}", get(get_preview))
        .route("/alicloud/agentteams/team-management/operations", post(apply))
        .route("/alicloud/agentteams/team-management/operations/{id}", get(get_operation))
        .route("/alicloud/agentteams/team-management/operations/{id}/observe", post(observe))
        .route("/alicloud/agentteams/team-management/operations/{id}/publish", post(publish))
        .layer(DefaultBodyLimit::max(128 * 1024))
}
fn prepare(state: &AppState, principal: &Principal) -> ApiResult<()> {
    principal.require(state, "alicloud", "read")?;
    principal.require(state, "alicloud", "write")?;
    Ok(())
}
async fn list(
    State(state): State<AppState>,
    principal: Principal,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "read")?;
    Ok(Json(projection::list(&state, &principal, query).await?))
}
async fn directory(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(input): ApiJson<UsersInput>,
) -> ApiResult<Json<Value>> {
    prepare(&state, &principal)?;
    Ok(Json(users::observe(&state, &principal, input).await?))
}
async fn create_preview(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(input): ApiJson<PreviewInput>,
) -> ApiResult<Json<Value>> {
    prepare(&state, &principal)?;
    Ok(Json(preview::create(&state, &principal, input).await?))
}
async fn get_preview(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "read")?;
    Ok(Json(preview::get(&state, &principal, id).await?))
}
async fn apply(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(input): ApiJson<ApplyInput>,
) -> ApiResult<Json<Value>> {
    prepare(&state, &principal)?;
    principal.require(&state, "assets", "write")?;
    Ok(Json(operations::apply(&state, &principal, input).await?))
}
async fn get_operation(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "read")?;
    Ok(Json(operations::get(&state, &principal, id).await?))
}
async fn observe(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Id>,
    ApiJson(input): ApiJson<RecoveryInput>,
) -> ApiResult<Json<Value>> {
    prepare(&state, &principal)?;
    Ok(Json(observe::recover(&state, &principal, id, input, false).await?))
}
async fn publish(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Id>,
    ApiJson(input): ApiJson<RecoveryInput>,
) -> ApiResult<Json<Value>> {
    prepare(&state, &principal)?;
    principal.require(&state, "assets", "write")?;
    Ok(Json(observe::recover(&state, &principal, id, input, true).await?))
}
