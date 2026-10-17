//! Shared lifecycle validation and review evidence, used by all inventory write paths.
use super::*;
use agf_core::asset::ChangeKind;

/// Validate and apply a reviewed lifecycle transition, returning its atomic history row.
///
/// # Errors
/// Invalid lifecycle edge, missing production ownership/classification or invalid review text.
pub fn apply_review(asset: &mut Asset, req: &LifecycleTransition) -> DomainResult<AssetChange> {
    if asset.id != req.asset_id {
        return Err(DomainError::Validation("Review target does not match the asset".into()));
    }
    req.validate_for_production()?;
    if req.note.len() > 2000
        || req.owner.as_ref().is_some_and(|value| value.len() > 256)
        || req.department.as_ref().is_some_and(|value| value.len() > 256)
    {
        return Err(DomainError::Validation("Review note exceeds 2000 bytes or ownership exceeds 256 bytes".into()));
    }
    if !asset.lifecycle.can_transition_to(req.to) {
        return Err(DomainError::Conflict(format!(
            "Invalid lifecycle transition: {} -> {}; refresh the current review",
            asset.lifecycle.as_str(),
            req.to.as_str()
        )));
    }
    let from = asset.lifecycle;
    asset.lifecycle = req.to;
    if let Some(class) = req.data_class {
        asset.data_class = class;
    }
    if let Some(owner) = &req.owner {
        asset.owner = Some(owner.trim().into());
    }
    if let Some(department) = &req.department {
        asset.department = Some(department.trim().into());
    }
    asset.updated_at = next_review_time(asset.updated_at)?;
    asset.attributes.insert(
        "agf_governance".into(),
        serde_json::json!({
            "lifecycle": req.to, "at": asset.updated_at, "actor": req.actor, "note": req.note
        }),
    );
    Ok(AssetChange {
        id: Id::new(),
        tenant_id: asset.tenant_id,
        asset_id: asset.id,
        kind: asset.kind,
        change_kind: ChangeKind::Modified,
        field: Some("lifecycle".into()),
        old_value: Some(serde_json::json!(from)),
        new_value: Some(serde_json::json!(req.to)),
        risky: false,
        risk_note: Some(format!("{} -> {} by {}: {}", from.as_str(), req.to.as_str(), req.actor, req.note)),
        domain: None,
        detected_at: asset.updated_at,
    })
}

/// Keep revision timestamps distinct even at coarse clock or database precision.
///
/// # Errors
/// The previous revision is outside the supported timestamp range.
pub fn next_review_time(previous: Timestamp) -> DomainResult<Timestamp> {
    let revision = Timestamp::now().unix_millis().max(previous.unix_millis().saturating_add(1));
    Timestamp::from_unix_millis(revision).map_err(DomainError::Validation)
}
