//! Native Mock and real HTTP reads publish only validated reference topology.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod privatelink_inventory_support;
use agf_core::{
    enums::{AssetKind, DataClass, LifecycleState},
    ids::Id,
};
use common::*;
use privatelink_inventory_support::*;

#[tokio::test]
async fn fixed_mock_has_true_receipts_cross_region_references_and_preserves_manual_fields() {
    let f = Fixture::new(true).await;
    let before = f.h.get(VIEW).await.json();
    assert_eq!(before["topologyAvailable"], false);
    assert!(before["endpoint"].is_null());
    let input = body(1);
    success(&f.h, input.clone()).await;
    let view = f.h.get(VIEW).await.json();
    assert_eq!(view["topologyAvailable"], true);
    assert_eq!(view["listingComplete"], true);
    assert_eq!(view["endpoint"]["serviceRegionId"], "cn-beijing");
    assert_eq!(view["pagesRead"], 2);
    assert!(view["networkReachability"].is_null());
    assert!(view["authorizationAllowed"].is_null());
    assert_eq!(view["graph"]["nodes"].as_array().unwrap().len(), 7);
    assert_eq!(view["graph"]["edges"].as_array().unwrap().len(), 6);
    assert!(!view.to_string().contains("DO_NOT_EXPOSE"));
    assert_eq!(f.count(), 0);
    let id: Id = serde_json::from_value(view["endpoint"]["assetId"].clone()).unwrap();
    let mut asset = f.h.state.store.asset_get(f.h.tenant, id).unwrap().unwrap();
    assert_eq!(asset.kind, AssetKind::Other);
    asset.name = "manual name".into();
    asset.owner = Some("manual owner".into());
    asset.data_class = DataClass::Confidential;
    asset.lifecycle = LifecycleState::Production;
    asset.endpoint = Some("manual:1234".into());
    asset.runtime = Some("manual runtime".into());
    asset.attributes.insert("manual-note".into(), json!("preserve"));
    f.h.state.store.asset_upsert(&asset).unwrap();
    success(&f.h, body(1)).await;
    let saved = f.h.state.store.asset_get(f.h.tenant, id).unwrap().unwrap();
    assert_eq!(saved.name, asset.name);
    assert_eq!(saved.owner, asset.owner);
    assert_eq!(saved.data_class, asset.data_class);
    assert_eq!(saved.lifecycle, asset.lifecycle);
    assert_eq!(saved.endpoint, asset.endpoint);
    assert_eq!(saved.runtime, asset.runtime);
    assert_eq!(saved.attributes["manual-note"], "preserve");
    let previous = snapshot(&f.h).await;
    let published = publications(&f.h).await;
    let audits = f.h.state.store.audit_chain_durable(f.h.tenant, 0, i64::MAX).await.unwrap().len();
    success(&f.h, input).await;
    assert_eq!(snapshot(&f.h).await, previous);
    assert_eq!(publications(&f.h).await, published);
    assert_eq!(f.h.state.store.audit_chain_durable(f.h.tenant, 0, i64::MAX).await.unwrap().len(), audits);
    let encoded = ledger(&f.h).await.unwrap().to_string();
    assert!(!encoded.contains("owned-privatelink-signing-secret"));
    assert!(!encoded.contains("PolicyDocument"));
    assert!(f.h.state.store.audit_verify_durable(f.h.tenant).await.unwrap().passed);
}

#[tokio::test]
async fn full_paging_and_explicit_zero_are_different_from_unobserved_and_unknown_fields_clear_old_values() {
    let f = Fixture::new(false).await;
    f.replace(
        ZONES,
        vec![
            page("Zones", 3, vec![zone("zone-a"), zone("zone-b")], Some("page-1")),
            page("Zones", 3, vec![zone("zone-c")], None),
        ],
    );
    success(&f.h, body(1)).await;
    let view = f.h.get(VIEW).await.json();
    assert_eq!(f.count(), 4);
    assert_eq!(view["pagesRead"], 3);
    assert_eq!(view["endpoint"]["zones"].as_array().unwrap().len(), 3);
    let id: Id = serde_json::from_value(view["endpoint"]["assetId"].clone()).unwrap();
    let mut detail = example()[DETAIL].clone();
    detail.as_object_mut().unwrap().remove("ServiceId");
    detail["VpcId"] = Value::Null;
    f.replace(DETAIL, vec![detail]);
    f.replace(ZONES, vec![page("Zones", 0, vec![], None)]);
    f.replace(GROUPS, vec![page("SecurityGroups", 0, vec![], Some(""))]);
    success(&f.h, body(1)).await;
    let view = f.h.get(VIEW).await.json();
    assert_eq!(view["topologyAvailable"], true);
    assert_eq!(view["endpoint"]["zonesAvailable"], true);
    assert_eq!(view["endpoint"]["zones"], json!([]));
    assert_eq!(view["endpoint"]["securityGroupsAvailable"], true);
    assert_eq!(view["endpoint"]["securityGroups"], json!([]));
    assert!(view["endpoint"]["serviceId"].is_null());
    assert!(view["endpoint"]["vpcId"].is_null());
    assert_eq!(view["graph"]["nodes"].as_array().unwrap().len(), 1);
    assert_eq!(view["graph"]["edges"], json!([]));
    let asset = f.h.state.store.asset_get(f.h.tenant, id).unwrap().unwrap();
    assert!(asset.attributes["privatelink_service_id"].is_null());
    assert!(asset.attributes["privatelink_vpc_id"].is_null());
}

#[tokio::test]
async fn malformed_totals_tokens_ids_or_addresses_preserve_exact_snapshot_and_assets() {
    let f = Fixture::new(false).await;
    success(&f.h, body(1)).await;
    let previous = snapshot(&f.h).await;
    let original = assets(&f.h).await;
    let published = publications(&f.h).await;
    for case in ["no_total", "short", "duplicate", "changed_total", "bad_token", "loop", "foreign_region", "bad_ip"] {
        let mut first = page("Zones", 1, vec![zone("new-zone")], None);
        let pages = match case {
            "no_total" => {
                first.as_object_mut().unwrap().remove("TotalCount");
                vec![first]
            }
            "short" => {
                first["TotalCount"] = json!(2);
                vec![first]
            }
            "duplicate" => {
                vec![page("Zones", 2, vec![zone("same")], Some("page-1")), page("Zones", 2, vec![zone("same")], None)]
            }
            "changed_total" => {
                vec![page("Zones", 2, vec![zone("first")], Some("page-1")), page("Zones", 3, vec![zone("next")], None)]
            }
            "bad_token" => {
                first["NextToken"] = json!(42);
                vec![first]
            }
            "loop" => {
                vec![page("Zones", 0, vec![], Some("loop"))]
            }
            "foreign_region" => {
                first["Zones"][0]["RegionId"] = json!("foreign");
                vec![first]
            }
            "bad_ip" => {
                first["Zones"][0]["EniIp"] = json!("bad-ip");
                vec![first]
            }
            _ => unreachable!(),
        };
        f.replace(ZONES, pages);
        let request = body(1);
        let response = f.h.post(SYNC, request.clone()).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{case}: {}", response.text);
        assert_eq!(snapshot(&f.h).await, previous);
        assert_eq!(assets(&f.h).await, original);
        assert_eq!(publications(&f.h).await, published);
        let calls = f.count();
        let replay = f.h.post(SYNC, request).await;
        assert_eq!(replay.status, StatusCode::OK);
        assert_eq!(replay.json()["published"], false);
        assert_eq!(f.count(), calls);
    }
}

#[tokio::test]
async fn cancellation_scope_disable_and_mode_change_stop_next_read_and_publish() {
    for change in ["cancel", "disabled", "scope", "mode"] {
        let mut f = Fixture::new(false).await;
        success(&f.h, body(1)).await;
        f.wait(GROUPS).await;
        let previous = snapshot(&f.h).await;
        let original = assets(&f.h).await;
        let published = publications(&f.h).await;
        *f.blocked.lock().unwrap() = ZONES.into();
        let request = body(1);
        let id = request["request_id"].as_str().unwrap().to_owned();
        let h = f.h.clone();
        let input = request.clone();
        let task = tokio::spawn(async move { h.post(SYNC, input).await });
        f.wait(ZONES).await;
        if change == "cancel" {
            assert_eq!(f.h.post(SYNC, body(1)).await.status, StatusCode::CONFLICT);
            let cancel = f.h.post(&format!("{VIEW}/operations/{id}/cancel"), json!({})).await;
            assert_eq!(cancel.status, StatusCode::OK);
            assert_eq!(cancel.json()["archivable"], true);
        } else {
            let mut settings = f.settings.clone();
            if change == "scope" {
                settings["endpoint_id"] = json!("foreign-endpoint");
            }
            f.change(1, change != "disabled", change == "mode", settings).await;
        }
        f.gate.add_permits(1);
        assert!(!task.await.unwrap().status.is_success());
        assert_eq!(snapshot(&f.h).await, previous);
        assert_eq!(assets(&f.h).await, original);
        assert_eq!(publications(&f.h).await, published);
        assert_eq!(f.count(), 5, "the SG call after paused zones must not be sent");
        if change != "cancel" {
            let view = f.h.get(VIEW).await.json();
            assert_eq!(view["topologyAvailable"], false);
            assert!(view["endpoint"].is_null());
        }
        let calls = f.count();
        let _ = f.h.post(SYNC, request).await;
        assert_eq!(f.count(), calls);
    }
}

#[tokio::test]
async fn forbidden_or_foreign_detail_does_not_become_absence_or_empty_child_lists() {
    let f = Fixture::new(false).await;
    success(&f.h, body(1)).await;
    let before = snapshot(&f.h).await;
    let published = publications(&f.h).await;
    f.replace(DETAIL,vec![json!({"_status":403,"RequestId":"owned-forbidden","Code":"Forbidden.RAM","Message":"provider-private-message"})]);
    assert!(!f.h.post(SYNC, body(1)).await.status.is_success());
    assert_eq!(snapshot(&f.h).await, before);
    assert_eq!(publications(&f.h).await, published);
    let mut detail = example()[DETAIL].clone();
    detail["EndpointId"] = json!("foreign");
    f.replace(DETAIL, vec![detail]);
    assert_eq!(f.h.post(SYNC, body(1)).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(snapshot(&f.h).await, before);
    assert!(!f.h.get(VIEW).await.text.contains("provider-private-message"));
}

#[tokio::test]
async fn openapi_contract_matches_five_live_routes_permissions_nullability_and_bounded_reference_evidence() {
    let h = setup().await;
    let response = h.get("/api/v1/openapi.json").await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let document = response.json();
    for (path, method, permissions) in [
        (VIEW, "get", json!(["alicloud:read"])),
        (SYNC, "post", json!(["alicloud:read", "alicloud:write", "assets:write"])),
        ("/api/v1/alicloud/privatelink/inventory/operations/{request_id}", "get", json!(["alicloud:read"])),
        (
            "/api/v1/alicloud/privatelink/inventory/operations/{request_id}/cancel",
            "post",
            json!(["alicloud:read", "alicloud:write", "assets:write"]),
        ),
        (ARCHIVE, "post", json!(["alicloud:read", "alicloud:write", "assets:write"])),
    ] {
        let operation = &document["paths"][path][method];
        assert_eq!(operation["x-required-permissions"], permissions);
        assert!(operation["operationId"].is_string());
        assert!(operation["responses"]["200"].is_object());
    }
    let sync = &document["paths"][SYNC]["post"]["requestBody"]["content"]["application/json"]["schema"];
    assert_eq!(sync["additionalProperties"], false);
    assert_eq!(sync["required"], json!(["request_id", "configuration_version"]));
    let schemas = &document["components"]["schemas"];
    assert_eq!(schemas["PrivateLinkInventory"]["properties"]["networkReachability"]["type"], "null");
    assert_eq!(schemas["PrivateLinkInventory"]["properties"]["authorizationAllowed"]["type"], "null");
    assert_eq!(
        schemas["PrivateLinkInventoryEndpoint"]["properties"]["serviceRegionId"]["type"],
        json!(["string", "null"])
    );
    assert_eq!(schemas["PrivateLinkInventoryNode"]["properties"]["region"]["type"], json!(["string", "null"]));
    assert_eq!(schemas["PrivateLinkInventoryGraph"]["properties"]["nodes"]["maxItems"], 4003);
    assert_eq!(
        schemas["PrivateLinkInventoryEdge"]["properties"]["evidenceAction"]["enum"],
        json!([DETAIL, ZONES, GROUPS])
    );
}
