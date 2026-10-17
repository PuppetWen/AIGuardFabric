//! Manual applications and automatic daily inventory, exposed alongside the asset ledger.
use crate::{error::ApiResult, middleware::Principal, routes::ApiJson, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use serde_json::{Value, json};
pub mod daily;
pub mod manual;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/assets/register", post(register))
        .route("/assets/inventory", get(history).post(run_now))
        .route("/assets/inventory/{id}/changes", get(changes))
}

async fn register(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<manual::Registration>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "assets", "write")?;
    let actor = AppState::audit_actor(&principal, "asset-registration");
    let asset = manual::register(&state, principal.tenant, &principal.display(), actor, body).await?;
    Ok(Json(json!({"asset":asset})))
}

#[derive(serde::Deserialize)]
struct PageQuery {
    #[serde(default = "first_page")]
    page: u64,
}
fn first_page() -> u64 {
    1
}

async fn history(
    State(state): State<AppState>,
    principal: Principal,
    Query(query): Query<PageQuery>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "assets", "read")?;
    let enabled = state.store.has_database();
    let mut result = if enabled {
        daily::list(&state, principal.tenant, query.page).await?
    } else {
        json!({"items":[],"total":0,"page":query.page,"page_size":20})
    };
    result["automatic_enabled"] = json!(enabled);
    result["can_write"] = json!(principal.require(&state, "assets", "write").is_ok());
    result["timezone"] = json!("UTC");
    Ok(Json(result))
}

async fn run_now(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Value>> {
    principal.require(&state, "assets", "write")?;
    let run = daily::run_for_date(&state, principal.tenant, agf_core::time::Date::today()).await?;
    Ok(Json(serde_json::to_value(run)?))
}

async fn changes(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    Query(query): Query<PageQuery>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "assets", "read")?;
    let id = crate::routes::parse_id(&id, "asset-inventory")?;
    Ok(Json(daily::changes(&state, principal.tenant, id, query.page).await?))
}

fn database(state: &AppState) -> DomainResult<&agf_storage::Store> {
    state
        .store
        .database()
        .map(AsRef::as_ref)
        .ok_or_else(|| DomainError::PreconditionFailed("Daily inventory requires PostgreSQL".into()))
}

/// Runs once per UTC day for each enabled tenant, catching up after an outage.
/// SQL locking and a unique tenant/day constraint coordinate multiple API instances.
pub async fn run_loop(state: AppState) {
    if !state.store.has_database() {
        return;
    }
    loop {
        match crate::tenant_directory::list(&state).await {
            Ok(tenants) => {
                for tenant in tenants.into_iter().filter(|tenant| tenant.enabled) {
                    let result = tokio::time::timeout(
                        std::time::Duration::from_mins(2),
                        daily::run_for_date(&state, tenant.id, agf_core::time::Date::today()),
                    )
                    .await;
                    match result {
                        Ok(Ok(_)) => {}
                        Ok(Err(error)) => tracing::warn!(tenant=%tenant.id,%error,"Daily asset inventory will retry"),
                        Err(_) => {
                            tracing::warn!(tenant=%tenant.id,"Daily asset inventory timed out; transaction rolled back");
                        }
                    }
                }
            }
            Err(error) => tracing::warn!(%error,"Daily asset inventory tenant lookup will retry"),
        }
        tokio::time::sleep(std::time::Duration::from_mins(1)).await;
    }
}
