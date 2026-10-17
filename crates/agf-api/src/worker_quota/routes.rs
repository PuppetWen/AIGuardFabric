//! Administrative bindings and explicit preview-confirm-reconcile operations.
use super::{
    binding,
    contract::{BindInput, ObserveInput, SyncInput},
    operations,
};
use crate::{ApiResult, Principal, routes::ApiJson, state::AppState};
use agf_core::ids::Id;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    routing::{get, post, put},
};
use serde_json::Value;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/alicloud/agentteams/worker-quotas", get(list))
        .route("/alicloud/agentteams/worker-quotas/{id}", put(save))
        .route("/alicloud/agentteams/worker-quotas/{id}/observe", post(observe))
        .route("/alicloud/agentteams/worker-quotas/{id}/sync", post(sync))
        .layer(DefaultBodyLimit::max(4096))
}

async fn list(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "read")?;
    principal.require(&state, "quotas", "read")?;
    Ok(Json(binding::list(&state, &principal).await?))
}

async fn save(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Id>,
    ApiJson(input): ApiJson<BindInput>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "write")?;
    principal.require(&state, "quotas", "write")?;
    Ok(Json(binding::save(&state, &principal, id, input).await?))
}

async fn observe(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Id>,
    ApiJson(input): ApiJson<ObserveInput>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "write")?;
    principal.require(&state, "quotas", "read")?;
    Ok(Json(operations::observe(&state, &principal, id, input).await?))
}

async fn sync(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Id>,
    ApiJson(input): ApiJson<SyncInput>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "write")?;
    principal.require(&state, "quotas", "write")?;
    Ok(Json(operations::sync(&state, &principal, id, input).await?))
}
