//! Reviewed corrections to the human-maintained fields of an inventory asset.
use agf_asset::service::next_review_time;
use agf_core::{
    asset::{AssetChange, ChangeKind},
    audit::{AuditAction, AuditOutcome, AuditTarget},
    enums::DataClass,
    error::DomainError,
    ids::Id,
    time::Timestamp,
};
use axum::{
    Json,
    extract::{Path, State},
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
pub struct AssetMetadata {
    pub name: String,
    pub owner: String,
    /// Empty string removes the optional department.
    pub department: String,
    pub data_class: String,
    #[schema(value_type = String, format = DateTime)]
    pub expected_updated_at: Timestamp,
    pub reason: String,
}

fn field(value: &str, label: &str, limit: usize, required: bool) -> Result<String, DomainError> {
    let value = value.trim();
    if (required && value.is_empty()) || value.len() > limit || value.chars().any(char::is_control) {
        return Err(DomainError::Validation(format!("{label} is empty, too long or contains control characters")));
    }
    Ok(value.to_owned())
}

fn classification(value: &str) -> Result<DataClass, DomainError> {
    match value {
        "public" => Ok(DataClass::Public),
        "internal" => Ok(DataClass::Internal),
        "confidential" => Ok(DataClass::Confidential),
        "restricted" => Ok(DataClass::Restricted),
        _ => Err(DomainError::Validation("Unknown data classification".into())),
    }
}

/// Correct name, ownership and data class without changing immutable identity or lifecycle.
///
/// # Errors
/// Returns 400 for invalid fields, 404 for an unknown tenant asset and 409 for a stale form.
pub async fn update(
    State(state): State<AppState>,
    principal: Principal,
    Path(raw_id): Path<String>,
    ApiJson(body): ApiJson<AssetMetadata>,
) -> ApiResult<Json<Value>> {
    principal.require(&state, "assets", "write")?;
    let id = parse_id(&raw_id, "asset")?;
    let name = field(&body.name, "Asset name", 256, true)?;
    let owner = field(&body.owner, "Asset owner", 256, true)?;
    let department = field(&body.department, "Department", 256, false)?;
    let reason = field(&body.reason, "Change reason", 1024, true)?;
    let data_class = classification(&body.data_class)?;
    let actor = principal.display();
    let entry = AppState::audit_entry(
        principal.tenant,
        AuditAction::Update,
        AuditOutcome::Success,
        AppState::audit_actor(&principal, "asset-metadata"),
        AuditTarget::new("asset", Some(id.to_string()), Some(name.clone())),
        "人工更正资产台账元数据",
    );
    let asset = state
        .store
        .asset_mutate_audited_durable(principal.tenant, id, entry, |current| {
            let mut asset = current.ok_or_else(|| DomainError::NotFound { entity: "asset", id: raw_id.clone() })?;
            if asset.updated_at != body.expected_updated_at {
                return Err(DomainError::Conflict("Asset changed; reload its details before saving".into()));
            }
            let before = json!({"name":asset.name,"owner":asset.owner,"department":asset.department,
            "data_class":asset.data_class});
            let after = json!({"name":name,"owner":owner,"department":department,"data_class":data_class});
            if before == after {
                return Ok((asset, None));
            }
            asset.name = name;
            asset.owner = Some(owner);
            asset.department = Some(department);
            asset.data_class = data_class;
            asset.updated_at = next_review_time(asset.updated_at)?;
            let change = AssetChange {
                id: Id::new(),
                tenant_id: principal.tenant,
                asset_id: id,
                kind: asset.kind,
                change_kind: ChangeKind::Modified,
                field: Some("metadata".into()),
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
        payload: json!({"asset_id":id,"action":"metadata"}),
    });
    Ok(Json(json!({"asset":asset})))
}
