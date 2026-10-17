//! Versioned SCIM identity binding for credential assets.
use crate::{
    error::ApiResult,
    middleware::Principal,
    routes::{ApiJson, parse_id},
    state::AppState,
};
use agf_asset::service::next_review_time;
use agf_core::{
    asset::{AssetChange, ChangeKind},
    audit::{AuditAction, AuditOutcome, AuditTarget},
    enums::AssetKind,
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

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BindScimUser {
    /// Empty string removes the binding.
    pub user_id: String,
    #[schema(value_type = String, format = DateTime)]
    pub expected_updated_at: Timestamp,
    pub reason: String,
}

pub fn router() -> Router<AppState> {
    Router::new().route("/assets/{id}/scim-user", put(bind))
}

/// Bind an exact SCIM user ID to a credential asset with optimistic concurrency.
///
/// # Errors
/// Returns validation, not found or conflict errors for unsafe/stale changes.
pub async fn bind(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<BindScimUser>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "assets", "write")?;
    let asset_id = parse_id(&id, "asset")?;
    let user = body.user_id.trim().to_owned();
    if user.len() > 128 {
        return Err(DomainError::Validation("SCIM user ID must be at most 128 bytes".into()).into());
    }
    if !user.is_empty() {
        agf_adapters::vendors::require_safe_id("iam-scim", &user, "SCIM user id")?;
    }
    let reason = body.reason.trim().to_owned();
    if reason.is_empty() || reason.len() > 1024 || reason.chars().any(char::is_control) {
        return Err(
            DomainError::Validation("Explain the SCIM user binding change in at most 1024 characters".into()).into()
        );
    }
    let actor = principal.display();
    let audit = AppState::audit_entry(
        principal.tenant,
        AuditAction::Update,
        AuditOutcome::Success,
        AppState::audit_actor(&principal, "asset-scim-user"),
        AuditTarget::new("asset", Some(asset_id.to_string()), None),
        "核对身份资产的 SCIM 用户绑定",
    );
    let asset = state
        .store
        .asset_mutate_audited_durable(principal.tenant, asset_id, audit, |current| {
            let mut asset = current.ok_or_else(|| DomainError::NotFound { entity: "asset", id: id.clone() })?;
            if asset.kind != AssetKind::Credential {
                return Err(DomainError::Validation("SCIM binding requires a credential asset".into()));
            }
            if asset.updated_at != body.expected_updated_at {
                return Err(DomainError::Conflict("Asset changed; reload before changing its SCIM user".into()));
            }
            let before = asset.attributes.get("scim_user_id").cloned().unwrap_or(Value::Null);
            let after = if user.is_empty() { Value::Null } else { json!(user) };
            if before == after {
                return Ok((asset, None));
            }
            if user.is_empty() {
                asset.attributes.remove("scim_user_id");
            } else {
                asset.attributes.insert("scim_user_id".into(), after.clone());
            }
            asset.updated_at = next_review_time(asset.updated_at)?;
            let change = AssetChange {
                id: Id::new(),
                tenant_id: principal.tenant,
                asset_id,
                kind: asset.kind,
                change_kind: ChangeKind::Modified,
                field: Some("attributes.scim_user_id".into()),
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
        payload: json!({"asset_id":asset_id,"action":"scim-user-binding"}),
    });
    Ok(Json(json!({"asset":asset})))
}
