//! Bind an existing inventory asset to its exact EDR host before any isolation action.
use agf_asset::service::next_review_time;
use agf_core::{
    asset::{AssetChange, ChangeKind},
    audit::{AuditAction, AuditOutcome, AuditTarget},
    error::DomainError,
    ids::Id,
    time::Timestamp,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::put,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::ApiResult,
    middleware::Principal,
    routes::{ApiJson, parse_id},
    state::AppState,
};

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BindEdrHost {
    /// Empty string removes the binding; a live action then cannot target this asset.
    pub host_id: String,
    /// Asset detail's governance.updated_at, required to avoid overwriting another review.
    #[schema(value_type = String, format = DateTime)]
    pub expected_updated_at: Timestamp,
    /// Human reason recorded in asset change history.
    pub reason: String,
}

pub fn router() -> Router<AppState> {
    Router::new().route("/assets/{id}/edr-host", put(bind))
}

/// Change an asset's EDR host binding under the same lock as discovery and reviews.
///
/// # Errors
/// Returns 400 for invalid input, 404 for an unknown asset, or 409 for a stale asset revision.
pub async fn bind(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<BindEdrHost>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "assets", "write")?;
    let asset_id = parse_id(&id, "asset")?;
    let host = body.host_id.trim().to_owned();
    if host.len() > 128 {
        return Err(DomainError::Validation("EDR host ID must be at most 128 bytes".into()).into());
    }
    if !host.is_empty() {
        agf_adapters::vendors::require_safe_id("edr-isolation", &host, "host id")?;
    }
    let reason = body.reason.trim().to_owned();
    if reason.is_empty() || reason.len() > 1024 || reason.chars().any(char::is_control) {
        return Err(
            DomainError::Validation("Explain the EDR host binding change in at most 1024 characters".into()).into()
        );
    }
    let actor = principal.display();
    let audit = AppState::audit_entry(
        principal.tenant,
        AuditAction::Update,
        AuditOutcome::Success,
        AppState::audit_actor(&principal, "asset-edr-host"),
        AuditTarget::new("asset", Some(asset_id.to_string()), None),
        "核对资产的 EDR 主机绑定",
    );
    let asset = state
        .store
        .asset_mutate_audited_durable(principal.tenant, asset_id, audit, |current| {
            let mut asset = current.ok_or_else(|| DomainError::NotFound { entity: "asset", id: id.clone() })?;
            if asset.updated_at != body.expected_updated_at {
                return Err(DomainError::Conflict(
                    "Asset changed; reload its details before changing the EDR host".into(),
                ));
            }
            let before = asset.attributes.get("edr_host_id").cloned().unwrap_or(Value::Null);
            let after = if host.is_empty() { Value::Null } else { json!(host) };
            if before == after {
                return Ok((asset, None));
            }
            if host.is_empty() {
                asset.attributes.remove("edr_host_id");
            } else {
                asset.attributes.insert("edr_host_id".into(), after.clone());
            }
            asset.updated_at = next_review_time(asset.updated_at)?;
            let change = AssetChange {
                id: Id::new(),
                tenant_id: principal.tenant,
                asset_id,
                kind: asset.kind,
                change_kind: ChangeKind::Modified,
                field: Some("attributes.edr_host_id".into()),
                old_value: Some(before),
                new_value: Some(after),
                risky: true,
                risk_note: Some(format!("{actor}: {reason}")),
                domain: None,
                detected_at: asset.updated_at,
            };
            Ok((asset, Some(change)))
        })
        .await?;
    state.publish(crate::state::WsEvent {
        kind: "asset".into(),
        tenant_id: principal.tenant,
        at: Timestamp::now(),
        payload: json!({"asset_id":asset_id,"action":"edr-host-binding"}),
    });
    Ok(Json(json!({"asset":asset})))
}
