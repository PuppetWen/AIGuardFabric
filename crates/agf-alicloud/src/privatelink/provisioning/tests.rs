#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use crate::{http::RpcResponse, openapi};
use agf_core::{enums::AliCloudService, ids::Id};
use serde_json::json;

fn create() -> CreateEndpoint {
    CreateEndpoint {
        region_id: "cn-hangzhou".into(),
        service_region_id: "cn-hangzhou".into(),
        service_id: "epsrv-ownedservice".into(),
        vpc_id: "vpc-ownedvpc".into(),
        name: "AGF-private".into(),
        zones: vec![Zone { zone_id: "cn-hangzhou-b".into(), vswitch_id: "vsw-ownedswitch".into() }],
        security_group_ids: vec!["sg-ownedgroup".into()],
        cross_region_bandwidth: None,
    }
}

fn response(status: u16, mut body: serde_json::Value) -> RpcResponse {
    body["RequestId"] = json!("0ed8d006-f706-4d23-88ed-e11ed28dcac0");
    RpcResponse { status, body, raw: String::new() }
}

#[test]
fn selected_resources_and_original_uuid_are_the_exact_official_create_input() {
    let original = Id::new();
    let plan = create().prepare(original).expect("valid plan");
    assert_eq!(plan.action(), "CreateVpcEndpoint");
    assert_eq!(plan.input()["ClientToken"], original.to_string());
    assert_eq!(plan.input()["Zone"][0], json!({"ZoneId":"cn-hangzhou-b","VSwitchId":"vsw-ownedswitch"}));
    assert_eq!(plan.input()["SecurityGroupId"], json!(["sg-ownedgroup"]));
    assert_eq!(plan.input()["EndpointType"], "Interface");
    assert_eq!(plan.input()["ProtectedEnabled"], true);
    assert!(plan.input().get("CrossRegionBandwidth").is_none());
    openapi::contract(AliCloudService::Privatelink, plan.action())
        .expect("catalog")
        .validate(plan.input())
        .expect("shape");
}

#[test]
fn cross_region_has_explicit_bandwidth_without_guessing_a_transit_router() {
    let mut target = create();
    target.service_region_id = "cn-beijing".into();
    assert!(target.prepare(Id::new()).is_err());
    target.cross_region_bandwidth = Some(1000);
    assert_eq!(target.prepare(Id::new()).expect("cross region").input()["CrossRegionBandwidth"], 1000);
    target.service_region_id = target.region_id.clone();
    assert!(target.prepare(Id::new()).is_err());
}

#[test]
fn absent_duplicate_or_invalid_resources_cannot_create_an_implicit_default_network() {
    let mut target = create();
    target.name = "https://unsafe".into();
    assert!(target.prepare(Id::new()).is_err());
    target = create();
    target.service_id = "epsrv-user:secret@bad".into();
    assert!(target.prepare(Id::new()).is_err());
    target = create();
    target.zones.clear();
    assert!(target.prepare(Id::new()).is_err());
    target = create();
    target.zones.push(target.zones[0].clone());
    assert!(target.prepare(Id::new()).is_err());
    target = create();
    target.security_group_ids.clear();
    assert!(target.prepare(Id::new()).is_err());
    target = create();
    target.security_group_ids.push(target.security_group_ids[0].clone());
    assert!(target.prepare(Id::new()).is_err());
    target = create();
    target.zones[0].zone_id = "cn-beijing-b".into();
    assert!(target.prepare(Id::new()).is_err());
}

#[test]
fn acceptance_is_separate_and_does_not_add_bandwidth_or_autoaccept_flags() {
    let input = AcceptConnection {
        region_id: "cn-hangzhou".into(),
        service_id: "epsrv-ownedservice".into(),
        endpoint_id: "ep-ownedendpoint".into(),
    }
    .prepare(Id::new())
    .expect("valid acceptance");
    assert_eq!(input.action(), "EnableVpcEndpointConnection");
    assert_eq!(input.input().as_object().expect("object").len(), 5);
    assert!(input.input().get("Bandwidth").is_none());
    openapi::contract(AliCloudService::Privatelink, input.action())
        .expect("catalog")
        .validate(input.input())
        .expect("shape");
}

#[test]
fn ack_with_endpoint_is_still_only_ack_and_safe_unknown_drops_raw_response() {
    let plan = create().prepare(Id::new()).expect("plan");
    let result =
        dispatch::classify(&response(200, json!({"EndpointId":"ep-ownedendpoint","EndpointStatus":"Creating"})), &plan);
    assert_eq!(result.0, WriteStatus::Acknowledged);
    assert_eq!(result.2.as_deref(), Some("ep-ownedendpoint"));
    for body in [json!({"EndpointId":"private response"}), json!({}), json!({"Code":"Failure","EndpointId":"ep-owned"})]
    {
        assert_eq!(dispatch::classify(&response(200, body), &plan).0, WriteStatus::Unknown);
    }
    assert_eq!(
        dispatch::classify(&response(503, json!({"Code":"ServerError","Message":"private"})), &plan).0,
        WriteStatus::Unknown
    );
    assert_eq!(
        dispatch::classify(&response(403, json!({"Code":"Forbidden","Message":"private"})), &plan).0,
        WriteStatus::Rejected
    );
}

#[test]
fn only_complete_matching_resources_are_observed_and_connected_is_not_a_tcp_proof() {
    let target = create();
    let attributes = response(
        200,
        json!({"EndpointId":"ep-ownedendpoint","VpcId":target.vpc_id,"RegionId":target.region_id,
        "ServiceId":target.service_id,"ServiceRegionId":target.service_region_id,
        "EndpointStatus":"Active","ConnectionStatus":"Connected"}),
    );
    let zones =
        response(200, json!({"TotalCount":1,"Zones":[{"ZoneId":"cn-hangzhou-b","VSwitchId":"vsw-ownedswitch"}]}));
    let groups = response(200, json!({"TotalCount":1,"SecurityGroups":[{"SecurityGroupId":"sg-ownedgroup"}]}));
    let observed = verify_observation(
        &target,
        "ep-ownedendpoint",
        &attributes,
        std::slice::from_ref(&zones),
        std::slice::from_ref(&groups),
    )
    .expect("complete observation");
    assert!(observed.requested_resources_match);
    assert_eq!(observed.connection_state, "Connected");
    assert!(!observed.connectivity_verified);
    let incomplete = response(200, json!({"TotalCount":1,"Zones":zones.body["Zones"],"NextToken":"another-page"}));
    assert!(
        verify_observation(&target, "ep-ownedendpoint", &attributes, &[incomplete], std::slice::from_ref(&groups))
            .is_err()
    );
    let wrong = response(200, json!({"TotalCount":1,"SecurityGroups":[{"SecurityGroupId":"sg-othergroup"}]}));
    assert!(verify_observation(&target, "ep-ownedendpoint", &attributes, &[zones], &[wrong]).is_err());
}

#[test]
fn missing_total_inconsistent_total_and_wrong_region_never_prove_complete_observation() {
    let target = create();
    let mut attributes = response(
        200,
        json!({"EndpointId":"ep-ownedendpoint","VpcId":target.vpc_id,
        "ServiceId":target.service_id,"ServiceRegionId":target.service_region_id,"RegionId":target.region_id,
        "EndpointStatus":"Active","ConnectionStatus":"Connected"}),
    );
    let mut zones = response(
        200,
        json!({"TotalCount":2,"Zones":[
        {"ZoneId":"cn-hangzhou-b","VSwitchId":"vsw-ownedswitch"}]}),
    );
    let groups = response(200, json!({"TotalCount":1,"SecurityGroups":[{"SecurityGroupId":"sg-ownedgroup"}]}));
    assert!(
        verify_observation(
            &target,
            "ep-ownedendpoint",
            &attributes,
            std::slice::from_ref(&zones),
            std::slice::from_ref(&groups)
        )
        .is_err()
    );
    zones.body.as_object_mut().expect("object").remove("TotalCount");
    assert!(
        verify_observation(
            &target,
            "ep-ownedendpoint",
            &attributes,
            std::slice::from_ref(&zones),
            std::slice::from_ref(&groups)
        )
        .is_err()
    );
    zones.body["TotalCount"] = json!(1);
    attributes.body["RegionId"] = json!("cn-beijing");
    assert!(verify_observation(&target, "ep-ownedendpoint", &attributes, &[zones], &[groups]).is_err());
}
