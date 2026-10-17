//! Pure node projection health, separate from tenant durable UsageRows and budget ledgers.
use super::*;

pub(super) async fn meter_projection_status(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    principal.require(&state, "models", "read")?;
    let snapshot = state.meter.snapshot();
    // No tenant traversal, hydration, database initialization, audit or provider request.
    // No other tenant's totals, identifiers or grouping labels are exposed.
    Ok(Json(serde_json::json!({
        "scope":"node", "readOnly":true,
        "committedProjectionIncomplete":snapshot.committed_projection_incomplete,
        "committedGroupsMerged":snapshot.committed_groups_merged,
        "maxUsageRecordsPerTenant":512_u16, "maxFactsPerTenant":512_u16,
        "maxWitnessBytesPerTenant":8_388_608_u32
    })))
}
