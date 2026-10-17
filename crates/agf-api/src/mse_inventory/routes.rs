use super::{
    archive, collect,
    contract::{ArchiveInput, SyncInput},
    guard, store, views,
};
use crate::{ApiResult, Principal, routes::ApiJson, state::AppState};
use agf_core::{ids::Id, time::Timestamp};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyInput {}

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/alicloud/mse/inventory", get(list))
        .route("/alicloud/mse/inventory/sync", post(sync))
        .route("/alicloud/mse/inventory/operations/{request_id}", get(receipt))
        .route("/alicloud/mse/inventory/operations/{request_id}/cancel", post(cancel))
        .route("/alicloud/mse/operations/archive", post(archive_runs))
        .layer(DefaultBodyLimit::max(8192))
}

fn write(state: &AppState, principal: &Principal) -> ApiResult<()> {
    principal.require(state, "alicloud", "read")?;
    principal.require(state, "alicloud", "write")?;
    principal.require(state, "assets", "write")?;
    Ok(())
}

async fn list(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "read")?;
    Ok(Json(views::list(&state, principal.tenant).await?))
}

async fn sync(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(input): ApiJson<SyncInput>,
) -> ApiResult<Json<Value>> {
    write(&state, &principal)?;
    let run = collect::sync(&state, &principal, input).await?;
    project(&state, principal.tenant, &run).await
}

async fn archive_runs(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(input): ApiJson<ArchiveInput>,
) -> ApiResult<Json<Value>> {
    write(&state, &principal)?;
    Ok(Json(archive::save(&state, &principal, input).await?))
}

async fn receipt(State(state): State<AppState>, principal: Principal, Path(id): Path<Id>) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "read")?;
    let run = store::get(&state, principal.tenant, id).await?;
    // The original source is immutable; unavailable credentials/configuration cannot trigger a provider call.
    project(&state, principal.tenant, &run).await
}

async fn cancel(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Id>,
    ApiJson(_): ApiJson<EmptyInput>,
) -> ApiResult<Json<Value>> {
    write(&state, &principal)?;
    let submitted_at = Timestamp::now();
    guard::authorize(&state, &principal, submitted_at).await?;
    let run = store::cancel(&state, &principal, id, submitted_at).await?;
    project(&state, principal.tenant, &run).await
}

async fn project(
    state: &AppState,
    tenant: agf_core::ids::TenantId,
    run: &super::contract::Run,
) -> ApiResult<Json<Value>> {
    let current = views::current_scope(state, tenant).await?;
    let mut response = views::operation(run, current.as_ref());
    if !run.archived {
        let row = store::load(state, tenant).await?;
        response["archivable"] = serde_json::json!(archive::archivable(&row, run));
    }
    Ok(Json(response))
}
