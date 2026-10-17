use super::{
    authority::Authority,
    execution,
    records::Fact,
    source, store,
    types::{Empty, ExecuteInput, PreviewInput, hash, topology},
};
use crate::{
    AppState, Principal,
    error::ApiResult,
    routes::{ApiJson, parse_id},
};
use agf_core::error::DomainError;
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde_json::Value;

pub(super) async fn playbook(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let authority = Authority::capture(&state, principal, &headers, true)?;
    authority.check(&state).await?;
    Ok(Json(execution::playbook_view()?))
}
pub(super) async fn preview(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(input): ApiJson<PreviewInput>,
) -> ApiResult<Json<Value>> {
    let authority = Authority::capture(&state, principal, &headers, false)?;
    let value = tokio::time::timeout_at(authority.deadline, async {
        authority.check(&state).await?;
        let loaded = source::capture(&state, authority.principal.tenant, &input.targets).await?;
        let targets: Vec<_> = loaded.into_iter().map(|loaded| loaded.target).collect();
        authority.check(&state).await?;
        topology(&targets)
    })
    .await
    .map_err(|_| DomainError::Timeout("Multi-target preview original deadline".into()))??;
    Ok(Json(value))
}
pub(super) async fn execute(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(input): ApiJson<ExecuteInput>,
) -> ApiResult<Json<Value>> {
    let authority = Authority::capture(&state, principal, &headers, false)?;
    authority.check(&state).await?;
    if input.request_id.is_nil() {
        return Err(DomainError::Validation("Request UUID must be nonnil".into()).into());
    }
    // Resolve permanent original UUID before touching current target state; GET/replay can never dispatch.
    if let Some(original) = authority.within(store::get(&state, authority.principal.tenant, input.request_id)).await? {
        original.owns(&authority.principal)?;
        if original.input_sha256 != hash(&input)? {
            return Err(DomainError::Conflict("Request UUID belongs to another immutable request body".into()).into());
        }
        return Ok(Json(project(&state, &authority, original).await?));
    }
    if !input.confirm_registered_targets {
        return Err(DomainError::PreconditionFailed(
            "Confirm the reviewed finite topology and current registered targets".into(),
        )
        .into());
    }
    let (fact, targets, new) = tokio::time::timeout_at(authority.deadline, async {
        let targets = source::capture(&state, authority.principal.tenant, &input.targets).await?;
        if targets.iter().any(|loaded| loaded.target.transport_mode != "test-loopback") && !input.confirm_live {
            return Err(DomainError::PreconditionFailed(
                "Confirm live bounded read requests to the exact registered targets".into(),
            ));
        }
        let metadata: Vec<_> = targets.iter().map(|loaded| loaded.target.clone()).collect();
        if topology(&metadata)?["topologySha256"].as_str() != Some(input.reviewed_topology_sha256.as_str()) {
            return Err(DomainError::Conflict("Reviewed topology or target versions changed; preview again".into()));
        }
        let fact = Fact::new(&authority.principal, input, metadata, authority.submitted_at)?;
        let (fact, new) = store::claim(&state, &authority, fact).await?;
        Ok((fact, targets, new))
    })
    .await
    .map_err(|_| DomainError::Timeout("Multi-target original admission deadline".into()))??;
    if !new {
        return Ok(Json(project(&state, &authority, fact).await?));
    }
    let result = execution::run(&state, &authority, fact, targets).await?;
    Ok(Json(project(&state, &authority, result).await?))
}
pub(super) async fn get(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(raw): Path<String>,
) -> ApiResult<Json<Value>> {
    let authority = Authority::capture(&state, principal, &headers, true)?;
    authority.check(&state).await?;
    let request = parse_id(&raw, "redteam-multi-target-run")?;
    let fact = authority
        .within(store::get(&state, authority.principal.tenant, request))
        .await?
        .ok_or(DomainError::NotFound { entity: "redteam multi-target run", id: raw })?;
    fact.owns(&authority.principal)?;
    Ok(Json(project(&state, &authority, fact).await?))
}
async fn local(
    state: AppState,
    principal: Principal,
    headers: HeaderMap,
    raw: String,
    cancel: bool,
) -> ApiResult<Json<Value>> {
    let authority = Authority::capture(&state, principal, &headers, false)?;
    authority.check(&state).await?;
    let request = parse_id(&raw, "redteam-multi-target-run")?;
    let fact = authority
        .within(store::get(&state, authority.principal.tenant, request))
        .await?
        .ok_or(DomainError::NotFound { entity: "redteam multi-target run", id: raw })?;
    fact.owns(&authority.principal)?;
    let result = tokio::time::timeout_at(authority.deadline, store::finish(&state, &authority, &fact, true, cancel))
        .await
        .map_err(|_| DomainError::Timeout("Multi-target local publication deadline".into()))??;
    Ok(Json(result.view()))
}
pub(super) async fn cancel(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(raw): Path<String>,
    ApiJson(_): ApiJson<Empty>,
) -> ApiResult<Json<Value>> {
    local(state, principal, headers, raw, true).await
}
pub(super) async fn recover(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path(raw): Path<String>,
    ApiJson(_): ApiJson<Empty>,
) -> ApiResult<Json<Value>> {
    local(state, principal, headers, raw, false).await
}
pub(super) async fn project(state: &AppState, authority: &Authority, mut fact: Fact) -> Result<Value, DomainError> {
    fact.source_current = Some(authority.within(source::current_metadata(state, fact.tenant, &fact.targets)).await?);
    authority.check(state).await?;
    Ok(fact.view())
}
