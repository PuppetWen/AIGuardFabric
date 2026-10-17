//! Skill review and declared allowlists share the inventory transaction and revision.
use super::*;
use crate::rule_store::publication::{Grant, Submission};
use agf_asset::service::{LifecycleTransition, apply_review, next_review_time};
use axum::http::HeaderMap;
#[path = "skill_publication/mod.rs"]
mod publication;

/// A reviewed state change; legacy status/state aliases remain accepted.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct SkillStatusBody {
    /// Exact inventory state (preferred).
    #[serde(default)]
    pub to: Option<String>,
    /// Legacy pending/approved/rejected/revoked alias.
    #[serde(default)]
    pub status: Option<String>,
    /// Legacy status alias.
    #[serde(default)]
    pub state: Option<String>,
    /// Revision returned by the Skill list/detail.
    #[serde(default, alias = "expectedUpdatedAt")]
    #[schema(value_type = Option<String>)]
    pub expected_updated_at: Option<Timestamp>,
    /// Required review note, at most 2000 UTF-8 bytes.
    pub note: String,
    /// Owner; production requires an explicit reviewed value.
    #[serde(default)]
    pub owner: Option<String>,
    /// Department.
    #[serde(default)]
    pub department: Option<String>,
    /// Data classification; production requires an explicit reviewed value.
    #[serde(default, alias = "dataClass")]
    pub data_class: Option<String>,
}

/// Declared allowlist. Both collections are required to prevent accidental clearing.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct SkillWhitelistBody {
    /// Exact domains or a leading *. subdomain pattern; up to 100.
    pub domains: Vec<String>,
    /// Absolute local paths/patterns; up to 100.
    pub paths: Vec<String>,
    /// Revision returned by the Skill list/detail.
    #[serde(default, alias = "expectedUpdatedAt")]
    #[schema(value_type = Option<String>)]
    pub expected_updated_at: Option<Timestamp>,
}

fn check_revision(asset: &Asset, expected: Option<Timestamp>) -> Result<(), DomainError> {
    if expected.is_some_and(|expected| expected != asset.updated_at) {
        return Err(DomainError::Conflict("Skill changed; compare the latest record before saving".into()));
    }
    Ok(())
}

fn target(body: &SkillStatusBody) -> ApiResult<LifecycleState> {
    let mut states = Vec::new();
    if let Some(raw) = &body.to {
        states.push(crate::routes::assets::parse_lifecycle(raw)?);
    }
    for raw in [&body.status, &body.state].into_iter().flatten() {
        states.push(parse_skill_status(raw)?);
    }
    let Some(first) = states.first().copied() else {
        return Err(ApiError::new(DomainError::Validation("Provide to or status".into())));
    };
    if states.iter().any(|value| *value != first) {
        return Err(ApiError::new(DomainError::Validation("Conflicting lifecycle and status fields".into())));
    }
    Ok(first)
}

/// Review a Skill using the same legal transitions as asset inventory.
pub async fn set_skill_status(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<SkillStatusBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let submission = Submission::capture(&state, &principal, &headers, Grant::Skills)?;
    let target = target(&body)?;
    if body.note.trim().is_empty() {
        return Err(ApiError::new(DomainError::Validation("Review note is required".into())));
    }
    let asset_id = parse_id(&id, "skill")?;
    let mut review = LifecycleTransition::new(asset_id, target, principal.display(), body.note.trim());
    review.owner = body.owner;
    review.department = body.department;
    review.data_class = body.data_class.as_deref().map(crate::routes::assets::parse_data_class).transpose()?;
    let asset = publication::save(&state, &submission, asset_id, "skill-review", |current| {
        let mut asset = skill_asset(current, asset_id)?;
        check_revision(&asset, body.expected_updated_at)?;
        let change = apply_review(&mut asset, &review)?;
        Ok((asset, Some(change)))
    })
    .await?;
    publish(&state, &principal, &asset);
    Ok(Json(skill_json(&asset)?))
}

/// Update declared allowlist metadata; actual runtime enforcement is configured separately.
pub async fn set_skill_whitelist(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<SkillWhitelistBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let submission = Submission::capture(&state, &principal, &headers, Grant::Skills)?;
    let asset_id = parse_id(&id, "skill")?;
    let after = serde_json::json!({"domains": domains(body.domains)?, "paths": paths(body.paths)?});
    let asset = publication::save(&state, &submission, asset_id, "skill-allowlist", |current| {
        let mut asset = skill_asset(current, asset_id)?;
        check_revision(&asset, body.expected_updated_at)?;
        if matches!(asset.lifecycle, LifecycleState::Archived | LifecycleState::Rejected) {
            return Err(DomainError::Conflict("An archived or rejected Skill is read-only".into()));
        }
        let before = whitelist_json(&asset);
        if before == after {
            return Ok((asset, None));
        }
        asset.attributes.insert("whitelist".into(), after.clone());
        asset.updated_at = next_review_time(asset.updated_at)?;
        let change = AssetChange {
            id: Id::new(),
            tenant_id: principal.tenant,
            asset_id,
            kind: AssetKind::Skill,
            change_kind: ChangeKind::Modified,
            field: Some("attributes.whitelist".into()),
            old_value: Some(before),
            new_value: Some(after.clone()),
            risky: false,
            risk_note: Some(format!("Declared allowlist updated by {}", principal.display())),
            domain: None,
            detected_at: asset.updated_at,
        };
        Ok((asset, Some(change)))
    })
    .await?;
    publish(&state, &principal, &asset);
    Ok(Json(skill_json(&asset)?))
}

fn publish(state: &AppState, principal: &Principal, asset: &Asset) {
    state.publish(crate::state::WsEvent {
        kind: "skill".into(),
        tenant_id: principal.tenant,
        at: Timestamp::now(),
        payload: serde_json::json!({"skill_id": asset.id, "status": skill_status(asset.lifecycle)}),
    });
}

fn list(values: Vec<String>) -> Result<Vec<String>, DomainError> {
    if values.len() > 100 || values.iter().any(|s| s.len() > 1024 || s.chars().any(char::is_control)) {
        return Err(DomainError::Validation(
            "Allowlist supports 100 entries of at most 1024 bytes, without controls".into(),
        ));
    }
    let mut result: Vec<_> = values.into_iter().map(|value| value.trim().to_string()).collect();
    if result.iter().any(String::is_empty) {
        return Err(DomainError::Validation("Allowlist entries cannot be empty".into()));
    }
    result.sort();
    result.dedup();
    Ok(result)
}

fn domains(values: Vec<String>) -> Result<Vec<String>, DomainError> {
    let mut output = Vec::new();
    for value in list(values)? {
        let (prefix, host) = value.strip_prefix("*.").map_or(("", value.as_str()), |host| ("*.", host));
        if host.len() > 253 || host.contains(['/', '\\', ':', '?', '#', '@', '*', ' ']) {
            return Err(DomainError::Validation("Use a domain or *.domain without scheme, port or path".into()));
        }
        let host = url::Host::parse(host).map_err(|_| DomainError::Validation("Invalid allowlist domain".into()))?;
        output.push(format!("{prefix}{host}").to_lowercase());
    }
    output.sort();
    output.dedup();
    Ok(output)
}

fn paths(values: Vec<String>) -> Result<Vec<String>, DomainError> {
    let values = list(values)?;
    for value in &values {
        let windows = value.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && value.as_bytes().get(1) == Some(&b':')
            && value.as_bytes().get(2).is_some_and(|b| matches!(b, b'/' | b'\\'));
        if !(value.starts_with('/') || value.starts_with("\\\\") || windows)
            || value.split(['/', '\\']).any(|part| part == "..")
        {
            return Err(DomainError::Validation("Use an absolute path without parent traversal".into()));
        }
    }
    Ok(values)
}
