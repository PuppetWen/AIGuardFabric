//! Tenant parser authoring, validation, history and restore.
use super::*;
use crate::{
    parser_store::{self as store, Input, Record},
    routes::ApiJson,
};
use agf_core::audit::AuditAction;
use serde_json::{Value, json};

pub(super) async fn create(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(input): ApiJson<Input>,
) -> ApiResult<(axum::http::StatusCode, Json<Value>)> {
    principal.require(&state, "parsers", "write")?;
    let row = store::save_audited(&state, &principal, None, input, AuditAction::Create).await?;
    Ok((axum::http::StatusCode::CREATED, Json(public(&row)?)))
}
pub(super) async fn update(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(input): ApiJson<Input>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "parsers", "write")?;
    let row =
        store::save_audited(&state, &principal, Some(parse_id(&id, "parser")?), input, AuditAction::Update).await?;
    Ok(Json(public(&row)?))
}
pub(super) async fn validate(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(mut input): ApiJson<Input>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "parsers", "write")?;
    let outcome = tokio::task::spawn_blocking(move || {
        store::validate(&mut input)?;
        Ok::<_, DomainError>(agf_ingest::engine::parse_with(&input.definition, &input.sample))
    })
    .await
    .map_err(|_| DomainError::Internal("模板验证任务失败".into()))??;
    Ok(Json(serde_json::to_value(outcome)?))
}
pub(super) async fn history(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "parsers", "read")?;
    let row = store::custom(&state, principal.tenant, parse_id(&id, "parser")?).await?;
    Ok(Json(json!({"items":row.history.iter().rev().map(|r|json!({
        "version":r.parser.definition.version, "updated_at":r.parser.updated_at,
        "enabled":r.parser.enabled, "content_hash":r.parser.content_hash,
    })).collect::<Vec<_>>()})))
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Restore {
    version: u32,
    expected_version: u32,
}
pub(super) async fn restore(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(input): ApiJson<Restore>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "parsers", "write")?;
    let id = parse_id(&id, "parser")?;
    let row = store::custom(&state, principal.tenant, id).await?;
    let revision = row
        .history
        .iter()
        .find(|r| r.parser.definition.version == input.version)
        .ok_or_else(|| DomainError::Validation("该版本不在最近 20 个保存版本中".into()))?;
    let row = store::save_audited(
        &state,
        &principal,
        Some(id),
        Input {
            definition: revision.parser.definition.clone(),
            sample: revision.sample.clone(),
            enabled: revision.parser.enabled,
            priority: revision.parser.priority,
            expected_version: Some(input.expected_version),
        },
        AuditAction::Configure,
    )
    .await?;
    Ok(Json(public(&row)?))
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Delete {
    expected_version: u32,
}
pub(super) async fn delete(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(input): ApiJson<Delete>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "parsers", "write")?;
    let id = parse_id(&id, "parser")?;
    store::delete_audited(&state, &principal, id, input.expected_version).await?;
    Ok(Json(json!({"deleted":true})))
}
fn public(row: &Record) -> DomainResult<Value> {
    let current = row.current.as_ref().ok_or_else(|| DomainError::Internal("模板保存结果为空".into()))?;
    Ok(json!({"id":current.parser.id,"version":current.parser.definition.version,"enabled":current.parser.enabled}))
}
