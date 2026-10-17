//! Tenant-authenticated audit reads, administrator bindings and scoped collector ingestion.
use super::{binding, contract, ingest, trace, views};
use crate::{ApiResult, Principal, routes::ApiJson, state::AppState};
use agf_core::ids::Id;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    routing::{get, post},
};
use serde_json::Value;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/alicloud/agentteams/audit-sources", get(sources))
        .route("/alicloud/agentteams/audit-sources/{id}", axum::routing::put(save))
        .route("/alicloud/agentteams/audit-sources/{id}/events", post(push))
        .route("/alicloud/agentteams/audit-events", get(events))
        .route("/alicloud/agentteams/traces/{trace_id}", get(trace))
        .layer(DefaultBodyLimit::max(crate::source_store::MAX_BYTES))
}
async fn sources(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "read")?;
    principal.require(&state, "sources", "read")?;
    Ok(Json(views::list_bindings(&state, &principal).await?))
}
async fn save(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Id>,
    ApiJson(input): ApiJson<contract::BindInput>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "write")?;
    principal.require(&state, "sources", "write")?;
    let saved = binding::save(&state, &principal, id, input).await?;
    // Never expose the internal membership/asset map or frozen configuration payload.
    Ok(Json(serde_json::json!({"sourceId":saved.source_id,"version":saved.version,"bindingId":saved.binding_id,
        "scopeId":saved.scope_id,"cloudVersion":saved.cloud_version,"enabled":saved.enabled,
        "mocked":saved.mocked,"boundAt":saved.bound_at})))
}
async fn push(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Id>,
    bytes: Bytes,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "sources", "write")?;
    Ok(Json(ingest::accept(&state, principal.tenant, id, &bytes).await?))
}
async fn events(
    State(state): State<AppState>,
    principal: Principal,
    Query(query): Query<views::EventQuery>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "read")?;
    principal.require(&state, "sources", "read")?;
    Ok(Json(views::events(&state, principal.tenant, query).await?))
}

async fn trace(
    State(state): State<AppState>,
    principal: Principal,
    Path(trace_id): Path<String>,
    Query(query): Query<trace::TraceQuery>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "alicloud", "read")?;
    principal.require(&state, "sources", "read")?;
    Ok(Json(trace::view(&state, principal.tenant, &trace_id, query).await?))
}
