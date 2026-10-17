use super::{
    assets,
    contract::{Scope, Snapshot},
    graph, parse,
};
use agf_core::{
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde_json::{Value, json};

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../tests/fixtures/alicloud/privatelink-inventory.json")).unwrap()
}
fn scope() -> Scope {
    Scope { endpoint_id: "ep-agf-demo".into(), region: "cn-hangzhou".into(), mocked: true, ..Scope::default() }
}

#[test]
fn endpoint_has_only_validated_safe_fields_and_keeps_service_region_independent() {
    let mut value = fixture()["GetVpcEndpointAttribute"].clone();
    let endpoint = parse::endpoint(&value, &scope(), Timestamp::now()).unwrap();
    assert_eq!(endpoint.service_region_id.as_deref(), Some("cn-beijing"));
    assert_eq!(endpoint.region.as_deref(), Some("cn-hangzhou"));
    let safe = serde_json::to_string(&endpoint).unwrap();
    assert!(!safe.contains("DO_NOT_EXPOSE"));
    assert!(!safe.contains("PolicyDocument"));
    for (key, bad) in [
        ("EndpointId", json!("foreign")),
        ("RegionId", json!("cn-beijing")),
        ("VpcId", json!({"id":"bad"})),
        ("EndpointName", json!("bad\ntext")),
    ] {
        let prior = value[key].clone();
        value[key] = bad;
        assert!(parse::endpoint(&value, &scope(), Timestamp::now()).is_err(), "{key}");
        value[key] = prior;
    }
}

#[test]
fn absent_and_null_values_remain_unknown_and_are_not_empty_arrays() {
    let value = json!({"EndpointId":"ep-agf-demo","EndpointName":null});
    let endpoint = parse::endpoint(&value, &scope(), Timestamp::now()).unwrap();
    assert!(endpoint.name.is_none());
    assert!(endpoint.vpc_id.is_none());
    assert!(endpoint.region.is_none());
    for missing in [json!({}), json!({"Zones":null,"TotalCount":0}), json!({"Zones":[],"TotalCount":null})] {
        assert!(parse::page(&missing, "Zones").is_err());
    }
    assert!(parse::page(&json!({"Zones":[],"TotalCount":0}), "Zones").unwrap().items.is_empty());
}

#[test]
fn documented_end_tokens_are_valid_but_malformed_paging_is_rejected() {
    for token in [None, Some(Value::Null), Some(json!(""))] {
        let mut value = json!({"Zones":[],"TotalCount":0});
        if let Some(token) = token {
            value["NextToken"] = token;
        }
        assert!(parse::page(&value, "Zones").unwrap().next_token.is_none());
    }
    for token in [json!(3), json!({}), json!([]), json!("bad\ntoken"), json!("a".repeat(4097))] {
        assert!(parse::page(&json!({"Zones":[],"TotalCount":0,"NextToken":token}), "Zones").is_err());
    }
    for total in [json!(-1), json!(0.5), json!(1001), json!("1")] {
        assert!(parse::page(&json!({"Zones":[],"TotalCount":total}), "Zones").is_err());
    }
    assert!(parse::page(&json!({"Zones":[{}],"TotalCount":0}), "Zones").is_err());
    assert!(parse::page(&json!({"Zones":vec![json!({});51],"TotalCount":51}), "Zones").is_err());
}

#[test]
fn zones_validate_addresses_identity_and_scope_without_inferring_connectivity() {
    let mut zone = fixture()["ListVpcEndpointZones"]["Zones"][0].clone();
    assert!(parse::zone(&zone, &scope(), Timestamp::now()).is_ok());
    for (key, bad) in [
        ("ZoneId", json!(" ")),
        ("RegionId", json!("foreign")),
        ("EniIp", json!("2001:db8::1")),
        ("ZoneIpv6Address", json!("192.0.2.2")),
        ("EniId", json!(true)),
        ("ZoneDomain", json!("bad\rdomain")),
    ] {
        let prior = zone[key].clone();
        zone[key] = bad;
        assert!(parse::zone(&zone, &scope(), Timestamp::now()).is_err(), "{key}");
        zone[key] = prior;
    }
    assert!(
        parse::security_group(&json!({"SecurityGroupId":"sg-demo","SecurityGroupStatus":null}), Timestamp::now())
            .unwrap()
            .status
            .is_none()
    );
}

fn snapshot() -> Snapshot {
    let fixture = fixture();
    let at = Timestamp::now();
    let scope = scope();
    Snapshot {
        endpoint: parse::endpoint(&fixture["GetVpcEndpointAttribute"], &scope, at).unwrap(),
        zones: vec![parse::zone(&fixture["ListVpcEndpointZones"]["Zones"][0], &scope, at).unwrap()],
        security_groups: vec![
            parse::security_group(&fixture["ListVpcEndpointSecurityGroups"]["SecurityGroups"][0], at).unwrap(),
        ],
        scope,
        started_at: at,
        checked_at: at,
        pages_read: 2,
        asset_id: None,
    }
}

#[test]
fn graph_uses_only_explicit_ids_and_endpoint_is_the_only_managed_asset() {
    let mut snapshot = snapshot();
    let asset = assets::observation(TenantId::new(), &mut snapshot).unwrap();
    let graph = graph::project(&snapshot).unwrap();
    assert_eq!(graph["nodes"].as_array().unwrap().len(), 7);
    assert_eq!(graph["edges"].as_array().unwrap().len(), 6);
    for node in graph["nodes"].as_array().unwrap() {
        if node["kind"] == "endpoint" {
            assert_eq!(node["assetId"], json!(asset.id));
            assert_eq!(node["referenceOnly"], false);
        } else {
            assert!(node["assetId"].is_null());
            assert_eq!(node["referenceOnly"], true);
        }
        if node["kind"] == "service" {
            assert_eq!(node["region"], "cn-beijing");
        }
        if node["kind"] == "security_group" {
            assert!(node["region"].is_null());
        }
    }
    assert!(asset.attributes["privatelink_network_reachability"].is_null());
    assert!(asset.attributes["privatelink_authorization_allowed"].is_null());
    snapshot.endpoint.vpc_id = None;
    snapshot.endpoint.service_region_id = None;
    snapshot.zones[0].eni_id = None;
    let changed = graph::project(&snapshot).unwrap();
    assert!(
        !changed["edges"]
            .as_array()
            .unwrap()
            .iter()
            .any(|edge| matches!(edge["relation"].as_str(), Some("in_vpc" | "zone_eni")))
    );
    let service = changed["nodes"].as_array().unwrap().iter().find(|node| node["kind"] == "service").unwrap();
    assert!(service["region"].is_null());
}

#[test]
fn identical_cloud_ids_from_two_scopes_never_share_graph_identity() {
    let mut first = snapshot();
    first.scope.id = Id::new();
    assets::observation(TenantId::new(), &mut first).unwrap();
    let first_graph = graph::project(&first).unwrap();
    let mut second = first.clone();
    second.scope.id = Id::new();
    assets::observation(TenantId::new(), &mut second).unwrap();
    let second_graph = graph::project(&second).unwrap();
    for node in first_graph["nodes"].as_array().unwrap() {
        assert!(!second_graph["nodes"].as_array().unwrap().iter().any(|other| other["id"] == node["id"]));
    }
}
