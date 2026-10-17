use super::*;
use crate::{error::ApiResult, policy_store::AccessLease, routes::ApiJson};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::get,
};

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/alicloud/agentteams/role-mappings", get(list))
        .route("/alicloud/agentteams/role-mappings/{asset}", get(one).put(save))
        .route("/alicloud/agentteams/role-mappings/{asset}/requests/{request}", get(receipt))
}
async fn list(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "read")?;
    principal.require(&state, "platform", "admin")?;
    Ok(Json(views::list(&state, &principal).await?))
}
async fn one(State(state): State<AppState>, principal: Principal, Path(asset): Path<Id>) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "read")?;
    principal.require(&state, "platform", "admin")?;
    let sealed = state
        .configurations
        .get::<model::Sealed>(principal.tenant, KIND, asset)
        .await?
        .ok_or_else(|| DomainError::NotFound { entity: "role mapping", id: asset.to_string() })?;
    Ok(Json(views::record(&codec::record(&state, principal.tenant, asset, &sealed)?)))
}
async fn save(
    State(state): State<AppState>,
    principal: Principal,
    Path(asset): Path<Id>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<model::Input>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "read")?;
    principal.require(&state, "platform", "admin")?;
    principal.require(&state, "assets", "write")?;
    let lease = AccessLease::capture(&state, &principal, &headers)?;
    let fact = write::save(&state, &principal, lease.as_ref(), asset, input).await?;
    Ok(Json(views::intent(&fact)))
}
async fn receipt(
    State(state): State<AppState>,
    principal: Principal,
    Path((asset, request)): Path<(Id, Id)>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "read")?;
    principal.require(&state, "platform", "admin")?;
    let sealed = state
        .configurations
        .get::<model::Sealed>(principal.tenant, INTENTS, request)
        .await?
        .ok_or_else(|| DomainError::NotFound { entity: "role mapping intent", id: request.to_string() })?;
    let fact: model::Intent = codec::open(&state, principal.tenant, INTENTS, request, &sealed)?;
    if fact.tenant != principal.tenant || fact.asset_id != asset || fact.request_id != request {
        return Err(DomainError::NotFound { entity: "role mapping intent", id: request.to_string() }.into());
    }
    Ok(Json(views::intent(&fact)))
}
