//! 关联规则管理和正负序列试跑；自动执行只使用已经发布并启用的版本。
use crate::{
    correlation::{self, Definition},
    error::ApiResult,
    middleware::Principal,
    routes::ApiJson,
    state::AppState,
};
use agf_core::{
    audit::{AuditAction, AuditOutcome, AuditTarget},
    error::DomainError,
};
use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use serde::Deserialize;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/correlation/rules", get(list).post(save))
        .route("/correlation/examples", get(examples))
        .route("/correlation/validate", post(validate))
}

async fn list(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "rules", "read")?;
    let registry = correlation::registry::get(&state, principal.tenant).await?;
    let items: Vec<_> = registry
        .entries
        .into_values()
        .filter_map(|history| {
            history.last().cloned().map(|current| serde_json::json!({"current":current,"history":history}))
        })
        .collect();
    Ok(Json(serde_json::json!({"items":items,"automatic":state.ingest_sink.database().is_some(),
        "max_window_events":10000,"history_limit":10})))
}

async fn examples(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "rules", "read")?;
    Ok(Json(serde_json::json!({"items":correlation::samples::examples(principal.tenant).into_iter()
        .map(|definition| serde_json::json!({"definition":definition})).collect::<Vec<_>>()})))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Save {
    definition: Definition,
    expected_version: u64,
    #[serde(default)]
    deleted: bool,
}

async fn save(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(input): ApiJson<Save>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "rules", "write")?;
    let definition = checked(input.definition)?;
    let audit = AppState::audit_entry(
        principal.tenant,
        if input.deleted { AuditAction::Delete } else { AuditAction::Configure },
        AuditOutcome::Success,
        AppState::audit_actor(&principal, "correlation-rule"),
        AuditTarget::new("correlation-rule", Some(definition.rule.key().into()), None),
        &format!(
            "Correlation version {}, enabled {}, deleted {}",
            input.expected_version.saturating_add(1),
            definition.enabled,
            input.deleted
        ),
    );
    let row = correlation::registry::save_audited(
        &state,
        principal.tenant,
        principal.display(),
        definition,
        input.expected_version,
        input.deleted,
        audit,
    )
    .await?;
    Ok(Json(serde_json::json!({"current":row})))
}

async fn validate(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(definition): ApiJson<Definition>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "rules", "read")?;
    let definition = checked(definition)?;
    let result = tokio::task::spawn_blocking(move || correlation::registry::validate(&definition))
        .await
        .map_err(|_| DomainError::Internal("Correlation sample worker failed".into()))??;
    Ok(Json(result))
}

fn checked(definition: Definition) -> Result<Definition, DomainError> {
    if serde_json::to_vec(&definition)?.len() > 524_288 {
        return Err(DomainError::Validation("Correlation definition including samples must not exceed 512 KiB".into()));
    }
    Ok(definition)
}

pub fn endpoint_specs() -> Vec<super::platform::EndpointSpec> {
    use utoipa::openapi::path::HttpMethod::{Get, Post};
    [
        ("/api/v1/correlation/rules", Get, "correlationRules", "关联规则与版本历史"),
        ("/api/v1/correlation/rules", Post, "saveCorrelationRule", "发布、启停或删除关联规则"),
        ("/api/v1/correlation/examples", Get, "correlationExamples", "四类关联规则样例"),
        ("/api/v1/correlation/validate", Post, "validateCorrelationRule", "关联规则正负事件序列试跑"),
    ]
    .into_iter()
    .map(|(path, method, id, summary)| super::platform::EndpointSpec {
        path,
        method,
        id,
        summary,
        tag: "rules",
        implemented: true,
    })
    .collect()
}
