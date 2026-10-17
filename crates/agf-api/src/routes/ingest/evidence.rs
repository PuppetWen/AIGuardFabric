//! Tenant-scoped normalized event evidence linked from findings and alerts.
use super::*;

pub(super) async fn event(
    State(state): State<AppState>,
    principal: Principal,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "sources", "read")?;
    let event_id = parse_id(&id, "event")?;
    let event = state
        .ingest_sink
        .get_event(principal.tenant, event_id)
        .await?
        .ok_or(DomainError::NotFound { entity: "event", id })?;
    Ok(Json(serde_json::json!({"event":event})))
}
