use super::*;
use crate::{
    error::ApiResult,
    policy_store::{AccessLease, AuthorizedSubmission, authorize_publication},
    routes::ApiJson,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
};

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/alicloud/agentteams/orchestration-definitions", get(list))
        .route("/alicloud/agentteams/orchestration-definitions/requests/{request}", get(receipt))
        .route("/alicloud/agentteams/orchestration-definitions/teams/{team}", get(one).put(save))
        .route("/alicloud/agentteams/orchestration-definitions/teams/{team}/preview", post(preview))
}
async fn list(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "read")?;
    Ok(Json(views::state(&state, &principal).await?))
}
async fn one(State(state): State<AppState>, principal: Principal, Path(team): Path<String>) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "read")?;
    let rows = codec::load(&state, principal.tenant).await?;
    let record =
        rows.records.get(&team).ok_or(DomainError::NotFound { entity: "application orchestration", id: team })?;
    Ok(Json(views::record(record)))
}
async fn receipt(
    State(state): State<AppState>,
    principal: Principal,
    Path(request): Path<Id>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "read")?;
    let rows = codec::load(&state, principal.tenant).await?;
    let receipt = rows
        .intents
        .get(&request)
        .ok_or_else(|| DomainError::NotFound { entity: "application orchestration intent", id: request.to_string() })?;
    Ok(Json(views::intent(receipt, state.store.database().is_some())))
}
async fn save(
    State(state): State<AppState>,
    principal: Principal,
    Path(team): Path<String>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<model::Input>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "platform", "admin")?;
    principal.require(&state, "alicloud", "read")?;
    principal.require(&state, "alicloud", "write")?;
    let lease = AccessLease::capture(&state, &principal, &headers)?;
    let fact = write::submit(&state, &principal, lease.as_ref(), &team, input).await?;
    Ok(Json(views::intent(&fact, state.store.database().is_some())))
}
async fn preview(
    State(state): State<AppState>,
    principal: Principal,
    Path(team): Path<String>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<model::Input>,
) -> ApiResult<Json<Value>> {
    if principal.subject_kind != agf_core::rbac::SubjectKind::User {
        return Err(DomainError::Forbidden("预览需要管理员用户会话".into()).into());
    }
    let lease = AccessLease::capture(&state, &principal, &headers)?;
    let submission = AuthorizedSubmission {
        principal: &principal,
        submitted_at: Timestamp::now(),
        lease: lease.as_ref(),
        authorization: &write::AUTHORIZATION,
    };
    authorize_publication(&state, &submission).await?;
    let rows = codec::load(&state, principal.tenant).await?;
    let current = source::current(&state, principal.tenant, &team).await?;
    for id in &current.assets {
        source::live_asset(
            principal.tenant,
            *id,
            state.store.asset_get_durable(principal.tenant, *id).await?.as_ref(),
        )?;
    }
    let (record, difference) = reducer::prepare(&rows, &current, &input)?;
    authorize_publication(&state, &submission).await?;
    Ok(Json(json!({"teamName":team,"requestId":input.request_id,"expectedVersion":input.expected_version,
        "configurationVersion":current.source.configuration_version,"difference":difference,
        "result":views::record(&record),"providerCalled":false,"consumerApplied":null,"previewOnly":true})))
}
