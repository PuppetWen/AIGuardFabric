//! Configuration writes are acknowledged after encrypted persistence; probes never send notifications.
use crate::{error::ApiResult, integration_store as store, middleware::Principal, routes::ApiJson, state::AppState};
use agf_core::audit::{AuditAction, AuditOutcome, AuditTarget};
use agf_core::ids::Id;
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use serde_json::Value;
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/integrations/adapters/{name}/configuration", get(view).put(save))
        .route("/integrations/adapters/{name}/probe", post(probe))
        .route("/integrations/adapters/{name}/operations", get(history).post(execute))
        .route("/integrations/adapters/{name}/operations/{id}", get(receipt))
        .route("/integrations/adapters/{name}/operations/{id}/recover", post(recover))
}
async fn history(
    State(state): State<AppState>,
    principal: Principal,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "integrations", "read")?;
    Ok(Json(serde_json::json!({"items":crate::integration_runtime::history(&state, principal.tenant, &name).await?})))
}
async fn execute(
    State(state): State<AppState>,
    principal: Principal,
    Path(name): Path<String>,
    ApiJson(body): ApiJson<crate::integration_runtime::Request>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "integrations", "write")?;
    if matches!(name.as_str(), "edr-isolation" | "iam-scim") {
        principal.require(&state, "policies", "write")?;
    }
    let value = crate::integration_runtime::execute_authorized(&state, &principal, &name, body).await?;
    Ok(Json(value))
}
async fn receipt(
    State(state): State<AppState>,
    principal: Principal,
    Path((name, id)): Path<(String, Id)>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "integrations", "write")?;
    store::vendor(&name)?;
    Ok(Json(crate::integration_receipts::get(&state, principal.tenant, &name, id).await?))
}
async fn recover(
    State(state): State<AppState>,
    principal: Principal,
    Path((name, id)): Path<(String, Id)>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "integrations", "write")?;
    store::vendor(&name)?;
    Ok(Json(crate::integration_receipts::recover(&state, principal.tenant, &name, id).await?))
}
async fn view(State(state): State<AppState>, principal: Principal, Path(name): Path<String>) -> ApiResult<Json<Value>> {
    principal.require(&state, "integrations", "write")?;
    Ok(Json(store::view(&state, principal.tenant, &name).await?))
}
async fn save(
    State(state): State<AppState>,
    principal: Principal,
    Path(name): Path<String>,
    ApiJson(body): ApiJson<store::Update>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "integrations", "write")?;
    let entry = AppState::audit_entry(
        principal.tenant,
        AuditAction::Configure,
        AuditOutcome::Success,
        AppState::audit_actor(&principal, "integration-config"),
        AuditTarget::new("integration", None, Some(name.clone())),
        "保存加密集成配置",
    );
    let value = store::save_audited(&state, principal.tenant, &name, body, entry).await?;
    Ok(Json(value))
}
async fn probe(
    State(state): State<AppState>,
    principal: Principal,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "integrations", "write")?;
    let result =
        store::probe_audited(&state, principal.tenant, &name, AppState::audit_actor(&principal, "integration-probe"))
            .await?;
    Ok(Json(serde_json::to_value(result)?))
}
