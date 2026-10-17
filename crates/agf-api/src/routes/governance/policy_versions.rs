//! Explicit restoration creates a new signed revision; old snapshots remain immutable.
use super::*;
use axum::http::HeaderMap;

pub(super) async fn history(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "policies", "read")?;
    let id = parse_id(&id, "policy")?;
    let versions = crate::policy_store::history(&state, principal.tenant, id).await?;
    if versions.is_empty() {
        return Err(DomainError::NotFound { entity: "policy", id: id.to_string() }.into());
    }
    Ok(Json(serde_json::json!({"versions":versions})))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RestoreInput {
    version: u32,
    expected_version: Option<u64>,
}

pub(super) async fn rollback(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Path((id, version)): Path<(String, u32)>,
    ApiJson(input): ApiJson<RestoreInput>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "policies", "write")?;
    let submitted_at = Timestamp::now();
    let lease = crate::policy_store::AccessLease::capture(&state, &principal, &headers)?;
    let expected = super::policies::expected_version(input.expected_version)?;
    if input.version == 0 || input.version != version {
        return Err(DomainError::Validation("恢复请求 version 必须与路径中明确选择的正整数历史版本一致".into()).into());
    }
    let id = parse_id(&id, "policy")?;
    let saved =
        crate::policy_store::restore_audited(&state, &principal, id, version, expected, submitted_at, lease).await?;
    Ok(Json(serde_json::json!({"policy":saved})))
}
