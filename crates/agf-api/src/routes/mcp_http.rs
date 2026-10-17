//! MCP management and transport routes are separate so port 8091 exposes no console administration.
use crate::{
    ApiResult, Principal,
    mcp_gateway::{config, forward, legacy_sse, oauth},
    routes::ApiJson,
    state::AppState,
};
use agf_core::ids::{Id, TenantId};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, Method},
    response::Response,
    routing::{get, post},
};
use serde_json::{Value, json};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/mcp/oauth/client-metadata/{tenant}/{id}/{revision}", get(oauth_client_metadata))
        .route("/mcp/endpoints", get(list).post(save))
        .route("/mcp/endpoints/{id}/usage", get(usage))
        .route("/mcp/endpoints/{id}/probe", post(probe))
        .route("/mcp/endpoints/{id}/oauth", get(oauth_get).put(oauth_save))
        .route("/mcp/endpoints/{id}/oauth/start", post(oauth_start))
        .route("/mcp/endpoints/{id}/oauth/complete", post(oauth_complete))
        .route("/mcp/endpoints/{id}/oauth/disconnect", post(oauth_disconnect))
        .merge(transport_router())
}

/// Public by design: authorization servers fetch this exact HTTPS Client ID URL without a platform session.
async fn oauth_client_metadata(
    State(state): State<AppState>,
    Path((tenant, id, revision)): Path<(TenantId, Id, Id)>,
) -> ApiResult<Json<Value>> {
    Ok(Json(oauth::client_metadata_document(&state, tenant, id, revision).await?))
}

pub fn transport_router() -> Router<AppState> {
    Router::new()
        .route("/mcp/proxy/{id}", post(proxy).get(proxy).delete(proxy))
        .route("/mcp/legacy/{id}/sse", get(legacy_sse::listen))
        .route("/mcp/legacy/{id}/messages/{session}", post(legacy_sse::post))
        .layer(DefaultBodyLimit::max(1024 * 1024))
}

async fn probe(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Id>,
    ApiJson(input): ApiJson<crate::mcp_gateway::probe::Input>,
) -> ApiResult<Json<crate::mcp_gateway::probe::Result>> {
    principal.require(&state, "mcps", "execute")?;
    Ok(Json(crate::mcp_gateway::probe::run(&state, &principal, id, input).await?))
}

async fn list(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Value>> {
    principal.require(&state, "mcps", "read")?;
    Ok(Json(
        json!({"items":config::list(&state, principal.tenant).await?.iter().map(config::public).collect::<Vec<_>>(),
        "can_write":principal.require(&state,"mcps","write").is_ok(),
        "can_execute":principal.require(&state,"mcps","execute").is_ok() && principal.require(&state,"policies","read").is_ok()}),
    ))
}

async fn usage(State(state): State<AppState>, principal: Principal, Path(id): Path<Id>) -> ApiResult<Json<Value>> {
    principal.require(&state, "mcps", "read")?;
    crate::mcp_gateway::config::get(&state, principal.tenant, id).await?;
    Ok(Json(crate::mcp_gateway::usage::snapshot(&state, principal.tenant, id).await?))
}

async fn oauth_get(State(state): State<AppState>, principal: Principal, Path(id): Path<Id>) -> ApiResult<Json<Value>> {
    principal.require(&state, "mcps", "read")?;
    let endpoint = config::get(&state, principal.tenant, id).await?;
    let stored = oauth::get(&state, principal.tenant, id).await?;
    let status = if let Some(row) =
        stored.as_ref().filter(|row| row.endpoint_url == endpoint.url && endpoint.secret.is_none())
    {
        oauth::connected(&state, principal.tenant, id, row).await?
    } else {
        json!({"connected":false,"expires_at":null,"refreshable":false})
    };
    Ok(Json(json!({"configuration":stored.as_ref().map(oauth::public),"status":status})))
}

async fn oauth_save(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Id>,
    ApiJson(body): ApiJson<oauth::Input>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "mcps", "write")?;
    Ok(Json(oauth::public(&oauth::save(&state, &principal, id, body).await?)))
}

async fn oauth_start(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "mcps", "write")?;
    Ok(Json(oauth::start(&state, &principal, id).await?))
}

async fn oauth_complete(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Id>,
    ApiJson(body): ApiJson<oauth::Complete>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "mcps", "write")?;
    Ok(Json(oauth::complete(&state, &principal, id, body).await?))
}

async fn oauth_disconnect(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "mcps", "write")?;
    Ok(Json(oauth::disconnect(&state, &principal, id).await?))
}

async fn save(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(input): ApiJson<config::Input>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "mcps", "write")?;
    let actor = AppState::audit_actor(&principal, "mcp-http-endpoint");
    let row = config::save(&state, principal.tenant, input, actor).await?;
    Ok(Json(config::public(&row)))
}

async fn proxy(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<Id>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    forward::forward(state, principal, id, method, headers, body).await
}
