//! Inspect/release active controls; credential revocation is intentionally irreversible.
use super::*;
pub(super) async fn list(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "cases", "read")?;
    let case = parse_id(&id, "case")?;
    if state.store.case_get_durable(principal.tenant, case).await?.is_none() {
        return Err(DomainError::NotFound { entity: "case", id }.into());
    }
    let rows: Vec<_> = crate::containment::list(&state, principal.tenant)
        .await?
        .into_iter()
        .filter(|row| row.case_id == case)
        .collect();
    Ok(Json(serde_json::json!({"items":rows,
        "can_write":principal.require(&state,"cases","write").is_ok(),
        "can_release":principal.require(&state,"cases","admin").is_ok() && principal.require(&state,"policies","write").is_ok()
    })))
}
pub(super) async fn release(
    State(state): State<AppState>,
    principal: Principal,
    Path((id, control)): Path<(String, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "cases", "admin")?;
    principal.require(&state, "policies", "write")?;
    let case = parse_id(&id, "case")?;
    crate::containment::release(
        &state,
        principal.tenant,
        case,
        parse_id(&control, "containment")?,
        &principal.display(),
    )
    .await?;
    state
        .store
        .case_add_event_durable(
            principal.tenant,
            case,
            CaseEventKind::Containment,
            &principal.display(),
            &format!("解除处置 {control}"),
        )
        .await?;
    state
        .audit(
            principal.tenant,
            AuditAction::Update,
            AuditOutcome::Success,
            AppState::audit_actor(&principal, "containment-release"),
            AuditTarget::new("case", Some(id), Some(control)),
            "解除案件处置",
        )
        .await?;
    Ok(Json(serde_json::json!({"released":true})))
}
