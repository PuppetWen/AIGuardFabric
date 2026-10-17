//! Internal typed adoption of an existing, fully observed endpoint; no user body or cloud call.
use super::{
    KIND, NAME,
    contract::{Record, Snapshot},
    publication, scope,
};
use crate::state::AppState;
use agf_alicloud::privatelink::provisioning::{CreateEndpoint, EndpointObservation, Zone};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde_json::Value;
pub(crate) struct Selection {
    pub(crate) plan: CreateEndpoint,
    pub(crate) observation: EndpointObservation,
    pub(crate) checked_at: Timestamp,
    pub(crate) scope_id: Id,
    pub(crate) payload_hash: String,
}
pub(crate) fn key(tenant: TenantId) -> (&'static str, Id) {
    (KIND, crate::integration_store::id(tenant, NAME))
}
pub(crate) async fn load(state: &AppState, tenant: TenantId, scope_id: Id) -> DomainResult<Selection> {
    let value = state.configurations.get::<Value>(tenant, KIND, key(tenant).1).await?.ok_or_else(invalid)?;
    let current = scope::load(state, tenant).await?.1;
    from_locked(state, tenant, scope_id, &current, &value)
}
pub(crate) fn from_locked(
    state: &AppState,
    tenant: TenantId,
    scope_id: Id,
    current: &super::contract::Scope,
    value: &Value,
) -> DomainResult<Selection> {
    if serde_json::to_vec(value)?.len() > super::MAX_BYTES {
        return Err(invalid());
    }
    let row: Record = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
    super::store::bounded(&row)?;
    let snapshot: Snapshot = publication::snapshot(state, tenant, &row)?.ok_or_else(invalid)?;
    let now = Timestamp::now();
    // 各只读调用分别记录观测时间；必须属于同次成功盘点区间，不要求等于最后完成时间。
    let within = |at: Timestamp| at >= snapshot.started_at && at <= snapshot.checked_at;
    if snapshot.scope != *current
        || snapshot.scope.id != scope_id
        || snapshot.scope.cloud_id != key(tenant).1
        || snapshot.checked_at > now
        || snapshot.checked_at.offset_secs(300) < now
        || snapshot.checked_at < snapshot.started_at
        || !within(snapshot.endpoint.observed_at)
        || snapshot.zones.iter().any(|zone| !within(zone.observed_at))
        || snapshot.security_groups.iter().any(|group| !within(group.observed_at))
        || !row.runs.values().any(|r| {
            r.scope == snapshot.scope
                && r.started_at == snapshot.started_at
                && r.status == "succeeded"
                && r.published
                && r.endpoints_observed == 1
                && r.zones_observed == snapshot.zones.len() as u64
                && r.security_groups_observed == snapshot.security_groups.len() as u64
                && r.finished_at == Some(snapshot.checked_at)
        })
    {
        return Err(invalid());
    }
    let plan = CreateEndpoint {
        region_id: snapshot.endpoint.region.clone().ok_or_else(invalid)?,
        service_region_id: snapshot.endpoint.service_region_id.clone().ok_or_else(invalid)?,
        service_id: snapshot.endpoint.service_id.clone().ok_or_else(invalid)?,
        vpc_id: snapshot.endpoint.vpc_id.clone().ok_or_else(invalid)?,
        name: "ObservedExistingEndpoint".into(),
        zones: snapshot
            .zones
            .iter()
            .map(|z| Ok(Zone { zone_id: z.id.clone(), vswitch_id: z.vswitch_id.clone().ok_or_else(invalid)? }))
            .collect::<DomainResult<_>>()?,
        security_group_ids: snapshot.security_groups.iter().map(|g| g.id.clone()).collect(),
        cross_region_bandwidth: None,
    };
    let endpoint = snapshot.endpoint.id;
    agf_alicloud::privatelink::provisioning::validate_reference(&plan, &endpoint)?;
    super::parse::endpoint(
        &serde_json::json!({"EndpointId":endpoint,"RegionId":plan.region_id}),
        current,
        snapshot.checked_at,
    )?;
    if !endpoint.starts_with("ep-") || endpoint.len() > 67 {
        return Err(invalid());
    }
    let observation = EndpointObservation {
        endpoint_id: endpoint,
        endpoint_state: snapshot
            .endpoint
            .status
            .filter(|s| ["Creating", "Active", "Pending", "Deleting", "Deleted", "Failed"].contains(&s.as_str()))
            .unwrap_or_else(|| "Unknown".into()),
        connection_state: snapshot
            .endpoint
            .connection_status
            .filter(|s| ["Disconnected", "Connecting", "Connected", "Disconnecting"].contains(&s.as_str()))
            .unwrap_or_else(|| "Unknown".into()),
        requested_resources_match: true,
        connectivity_verified: false,
    };
    Ok(Selection {
        plan,
        observation,
        checked_at: snapshot.checked_at,
        scope_id,
        payload_hash: crate::privatelink_provisioning::source_fingerprint(value)?,
    })
}
fn invalid() -> DomainError {
    DomainError::PreconditionFailed("Choose the current complete PrivateLink inventory snapshot, with explicit service/VPC/zones/groups and fresh original evidence".into())
}
