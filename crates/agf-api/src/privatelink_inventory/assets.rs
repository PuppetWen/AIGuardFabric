//! Only the selected endpoint becomes an asset; cloud references remain topology evidence.
use super::{contract::Snapshot, scope};
use agf_core::{
    asset::Asset,
    enums::{AssetKind, DiscoverySource},
    error::DomainResult,
    ids::{TenantId, deterministic_id},
};
use serde_json::json;

pub(super) fn observation(tenant: TenantId, snapshot: &mut Snapshot) -> DomainResult<Asset> {
    let identity = scope::hash(&json!([
        tenant,
        snapshot.scope.source_identity,
        snapshot.scope.region,
        snapshot.scope.endpoint_id,
        snapshot.scope.mocked
    ]))?;
    let fingerprint = format!("privatelink-endpoint:{identity}");
    let id = deterministic_id("agf.privatelink.endpoint.asset", &fingerprint);
    snapshot.asset_id = Some(id);
    let endpoint = &snapshot.endpoint;
    let name = endpoint.name.clone().unwrap_or_else(|| endpoint.id.clone());
    let mut asset = Asset::new(tenant, AssetKind::Other, name, fingerprint);
    asset.id = id;
    asset.discovery_source = DiscoverySource::CloudApi;
    asset.vendor = Some("alicloud-privatelink".into());
    asset.cloud_resource_id = Some(endpoint.id.clone());
    asset.last_seen_at = Some(snapshot.checked_at);
    asset.updated_at = snapshot.checked_at;
    asset.attributes.extend([
        ("privatelink_scope_id".into(), json!(snapshot.scope.id)),
        ("privatelink_source_identity".into(), json!(snapshot.scope.source_identity)),
        ("privatelink_configuration_version".into(), json!(snapshot.scope.configuration_version)),
        ("privatelink_mocked".into(), json!(snapshot.scope.mocked)),
        ("privatelink_checked_at".into(), json!(snapshot.checked_at)),
        ("privatelink_observed".into(), json!(true)),
        ("privatelink_endpoint_id".into(), json!(endpoint.id)),
        ("privatelink_name".into(), json!(endpoint.name)),
        ("privatelink_region".into(), json!(endpoint.region)),
        ("privatelink_vpc_id".into(), json!(endpoint.vpc_id)),
        ("privatelink_service_id".into(), json!(endpoint.service_id)),
        ("privatelink_service_region_id".into(), json!(endpoint.service_region_id)),
        ("privatelink_domain".into(), json!(endpoint.domain)),
        ("privatelink_endpoint_type".into(), json!(endpoint.endpoint_type)),
        ("privatelink_status".into(), json!(endpoint.status)),
        ("privatelink_connection_status".into(), json!(endpoint.connection_status)),
        ("privatelink_business_status".into(), json!(endpoint.business_status)),
        ("privatelink_zones".into(), serde_json::to_value(&snapshot.zones)?),
        ("privatelink_security_groups".into(), serde_json::to_value(&snapshot.security_groups)?),
        ("privatelink_network_reachability".into(), json!(null)),
        ("privatelink_authorization_allowed".into(), json!(null)),
        (
            "privatelink_evidence".into(),
            json!(["GetVpcEndpointAttribute", "ListVpcEndpointZones", "ListVpcEndpointSecurityGroups"]),
        ),
    ]);
    Ok(asset)
}
