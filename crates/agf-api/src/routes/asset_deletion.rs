//! Reviewed inventory removal; evidence and the audit chain remain retained.
use agf_core::audit::{AuditAction, AuditOutcome, AuditTarget};
use agf_core::time::Timestamp;
use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use utoipa::ToSchema;

use crate::error::ApiResult;
use crate::middleware::Principal;
use crate::routes::{ApiJson, parse_id};
use crate::state::AppState;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoveAssetBody {
    /// Current `governance.updated_at` from asset detail.
    #[schema(value_type = String)]
    pub expected_updated_at: Timestamp,
    /// Type the asset's current name to confirm the intended record.
    pub confirm_name: String,
    /// Human reason retained in history and audit.
    pub reason: String,
}

/// Remove a terminal asset from current inventory, retaining history for audits.
///
/// # Errors
/// Permission denied, stale version, nonterminal lifecycle or storage failure.
pub async fn remove(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<RemoveAssetBody>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "assets", "write")?;
    let asset_id = parse_id(&id, "asset")?;
    let audit = AppState::audit_entry(
        principal.tenant,
        AuditAction::Delete,
        AuditOutcome::Success,
        AppState::audit_actor(&principal, "asset-removal"),
        AuditTarget::new("asset", Some(asset_id.to_string()), None),
        &format!("从当前资产台账移除：{}", body.reason.trim()),
    );
    state
        .store
        .asset_remove_durable(
            principal.tenant,
            asset_id,
            body.expected_updated_at,
            &body.confirm_name,
            &body.reason,
            &principal.display(),
            audit,
        )
        .await?;
    Ok(Json(serde_json::json!({"removed":true,"id":asset_id})))
}
