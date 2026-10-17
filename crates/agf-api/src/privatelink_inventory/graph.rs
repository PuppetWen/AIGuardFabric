//! Every edge names the public action which returned the corresponding explicit resource ID.
use super::{contract::Snapshot, scope};
use agf_core::{error::DomainResult, ids::deterministic_id, time::Timestamp};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Default)]
struct Graph {
    scope_id: agf_core::ids::Id,
    nodes: BTreeMap<String, Value>,
    edges: BTreeMap<(String, String, String), Value>,
}

impl Graph {
    fn node(
        &mut self,
        kind: &str,
        cloud_id: &str,
        region: Option<&str>,
        asset: Option<agf_core::ids::Id>,
    ) -> DomainResult<String> {
        let key = scope::hash(&json!([self.scope_id, kind, cloud_id, region]))?;
        let id = deterministic_id("agf.privatelink.graph.node", &key).to_string();
        self.nodes.entry(id.clone()).or_insert_with(|| {
            json!({"id":id,"kind":kind,"cloudId":cloud_id,
            "region":region,"assetId":asset,"referenceOnly":asset.is_none()})
        });
        Ok(id)
    }

    fn edge(&mut self, from: &str, to: &str, relation: &str, action: &str, at: Timestamp) {
        let key = (from.into(), to.into(), relation.into());
        self.edges.entry(key).or_insert_with(|| {
            json!({"from":from,"to":to,"relation":relation,
            "evidenceAction":action,"observedAt":at})
        });
    }
}

pub(super) fn project(snapshot: &Snapshot) -> DomainResult<Value> {
    let endpoint = &snapshot.endpoint;
    let mut graph = Graph { scope_id: snapshot.scope.id, ..Graph::default() };
    let root = graph.node("endpoint", &endpoint.id, endpoint.region.as_deref(), snapshot.asset_id)?;
    if let Some(id) = &endpoint.vpc_id {
        let node = graph.node("vpc", id, endpoint.region.as_deref(), None)?;
        graph.edge(&root, &node, "in_vpc", "GetVpcEndpointAttribute", endpoint.observed_at);
    }
    if let Some(id) = &endpoint.service_id {
        let node = graph.node("service", id, endpoint.service_region_id.as_deref(), None)?;
        graph.edge(&root, &node, "references_service", "GetVpcEndpointAttribute", endpoint.observed_at);
    }
    for zone in &snapshot.zones {
        let node = graph.node("zone", &zone.id, zone.region.as_deref(), None)?;
        graph.edge(&root, &node, "has_zone", "ListVpcEndpointZones", zone.observed_at);
        if let Some(id) = &zone.eni_id {
            let reference = graph.node("eni", id, zone.region.as_deref(), None)?;
            graph.edge(&node, &reference, "zone_eni", "ListVpcEndpointZones", zone.observed_at);
        }
        if let Some(id) = &zone.vswitch_id {
            let reference = graph.node("vswitch", id, zone.region.as_deref(), None)?;
            graph.edge(&node, &reference, "zone_vswitch", "ListVpcEndpointZones", zone.observed_at);
        }
    }
    for group in &snapshot.security_groups {
        let node = graph.node("security_group", &group.id, None, None)?;
        graph.edge(&root, &node, "has_security_group", "ListVpcEndpointSecurityGroups", group.observed_at);
    }
    Ok(
        json!({"nodes":graph.nodes.into_values().collect::<Vec<_>>(),"edges":graph.edges.into_values().collect::<Vec<_>>() }),
    )
}
