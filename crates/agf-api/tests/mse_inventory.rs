//! Honest MSE source observations, complete listing and safe cancellation via actual API/loopback.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod mse_inventory_support;
use agf_core::{
    asset::Asset,
    enums::{AssetKind, DataClass, LifecycleState},
    ids::Id,
};
use common::*;
use mse_inventory_support::*;
use std::sync::atomic::Ordering;

#[tokio::test]
async fn mock_publishes_other_assets_preserves_governance_and_same_request_never_sends_again() {
    let f = Fixture::new(true).await;
    let empty = f.h.get(VIEW).await.json();
    assert_eq!(empty["inventoryAvailable"], false);
    assert_eq!(empty["totalServices"], Value::Null);
    let input = body(1);
    success(&f.h, input.clone()).await;
    let view = f.h.get(VIEW).await.json();
    assert_eq!(view["mocked"], true);
    assert_eq!(view["totalServices"], 1);
    let item = &view["items"][0];
    for field in ["endpoint", "protocol", "runtime", "networkZone", "metadata"] {
        assert_eq!(item[field], Value::Null);
    }
    let id: Id = serde_json::from_value(item["assetId"].clone()).unwrap();
    let mut asset = f.h.state.store.asset_get(f.h.tenant, id).unwrap().unwrap();
    assert_eq!(asset.kind, AssetKind::Other);
    asset.name = "manual-name".into();
    asset.owner = Some("manual-owner".into());
    asset.department = Some("manual-team".into());
    asset.data_class = DataClass::Confidential;
    asset.lifecycle = LifecycleState::Production;
    asset.runtime = Some("manual-runtime".into());
    asset.endpoint = Some("manual:1234".into());
    asset.tags = vec!["manual-tag".into()];
    asset.attributes.insert("manual-note".into(), json!("preserve me"));
    f.h.state.store.asset_upsert(&asset).unwrap();
    success(&f.h, body(1)).await;
    let saved = f.h.state.store.asset_get(f.h.tenant, id).unwrap().unwrap();
    assert_eq!(saved.name, asset.name);
    assert_eq!(saved.owner, asset.owner);
    assert_eq!(saved.department, asset.department);
    assert_eq!(saved.data_class, asset.data_class);
    assert_eq!(saved.lifecycle, asset.lifecycle);
    assert_eq!(saved.runtime, asset.runtime);
    assert_eq!(saved.endpoint, asset.endpoint);
    assert_eq!(saved.tags, asset.tags);
    assert_eq!(saved.attributes["manual-note"], asset.attributes["manual-note"]);
    let previous = snapshot(&f.h).await;
    let count = publications(&f.h).await;
    success(&f.h, input.clone()).await;
    assert_eq!(snapshot(&f.h).await, previous);
    assert_eq!(publications(&f.h).await, count);
    assert_eq!(f.count(), 0);
    let encoded = ledger(&f.h).await.unwrap().to_string();
    assert!(!encoded.contains("owned-mse-signing-secret"));
    assert!(!encoded.contains("GroupName"));
    assert!(
        f.h.state
            .configurations
            .get::<Value>(f.h.other_tenant, KIND, agf_api::integration_store::id(f.h.other_tenant, "alicloud-mse"))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(f.h.request("POST", SYNC, Some(&f.h.viewer), Some(body(1))).await.status, StatusCode::FORBIDDEN);
    let mut changed = input;
    changed["confirm_live"] = json!(false);
    assert_eq!(f.h.post(SYNC, changed).await.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn live_listing_uses_all_pages_keeps_zero_unknown_and_clears_only_owned_observations() {
    let f = Fixture::new(false).await;
    let first = (0..100).map(|i| service(&format!("service-{i}"))).collect();
    let mut unknown = service("last");
    unknown.as_object_mut().unwrap().remove("IpCount");
    unknown["HealthyInstanceCount"] = Value::Null;
    unknown["Metadata"] = json!({"access_key_secret":"private-provider-marker"});
    f.replace(vec![page(1, 101, first), page(2, 101, vec![unknown])]);
    success(&f.h, body(1)).await;
    let view = f.h.get(VIEW).await.json();
    assert_eq!(view["totalServices"], 101);
    assert_eq!(view["pagesRead"], 2);
    assert_eq!(f.count(), 2);
    assert_eq!(view["items"][0]["instanceCount"], 0);
    assert_eq!(view["items"][100]["instanceCount"], Value::Null);
    assert_eq!(view["items"][100]["healthyInstanceCount"], Value::Null);
    assert!(!view.to_string().contains("private-provider-marker"));
    let old_id: Id = serde_json::from_value(view["items"][100]["assetId"].clone()).unwrap();
    let mut old = f.h.state.store.asset_get(f.h.tenant, old_id).unwrap().unwrap();
    old.owner = Some("human".into());
    f.h.state.store.asset_upsert(&old).unwrap();
    f.replace(vec![page(1, 0, vec![])]);
    success(&f.h, body(1)).await;
    let now = f.h.get(VIEW).await.json();
    assert_eq!(now["inventoryAvailable"], true);
    assert_eq!(now["totalServices"], 0);
    let retained = f.h.state.store.asset_get(f.h.tenant, old_id).unwrap().unwrap();
    assert_eq!(retained.owner, old.owner);
    assert_eq!(retained.lifecycle, old.lifecycle);
    assert_eq!(retained.attributes["mse_observed"], false);
    assert_eq!(retained.attributes["mse_instance_count"], Value::Null);
    assert_eq!(retained.last_seen_at, old.last_seen_at);
}

#[tokio::test]
async fn bad_pages_preserve_exact_previous_snapshot_and_assets_without_success_audit() {
    let f = Fixture::new(false).await;
    success(&f.h, body(1)).await;
    let previous = snapshot(&f.h).await;
    let assets = serde_json::to_value(f.h.state.store.asset_list_all(f.h.tenant).unwrap()).unwrap();
    let count = publications(&f.h).await;
    for case in ["missing_total", "foreign_namespace", "bad_count", "short_page", "duplicate", "changed_total"] {
        let mut first = page(1, 1, vec![service("new")]);
        let pages = match case {
            "missing_total" => {
                first.as_object_mut().unwrap().remove("TotalCount");
                vec![first]
            }
            "foreign_namespace" => {
                first["NamespaceId"] = json!("foreign");
                vec![first]
            }
            "bad_count" => {
                first["Data"][0]["IpCount"] = json!("unknown");
                vec![first]
            }
            "short_page" => {
                first["TotalCount"] = json!(101);
                vec![first]
            }
            "duplicate" | "changed_total" => {
                let services = (0..100).map(|i| service(&format!("owned-{i}"))).collect();
                vec![
                    page(1, 101, services),
                    page(2, if case == "changed_total" { 102 } else { 101 }, vec![service("owned-0")]),
                ]
            }
            _ => unreachable!(),
        };
        f.replace(pages);
        let request = body(1);
        let response = f.h.post(SYNC, request.clone()).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{case}: {}", response.text);
        assert_eq!(snapshot(&f.h).await, previous);
        assert_eq!(publications(&f.h).await, count);
        assert_eq!(serde_json::to_value(f.h.state.store.asset_list_all(f.h.tenant).unwrap()).unwrap(), assets);
        let calls = f.count();
        let replay = f.h.post(SYNC, request).await;
        assert_eq!(replay.status, StatusCode::OK);
        assert_eq!(replay.json()["published"], false);
        assert_eq!(f.count(), calls);
    }
}

#[tokio::test]
async fn cancellation_and_configuration_changes_during_a_sent_page_block_publication() {
    for change in ["cancel", "disabled", "scope", "mode"] {
        let mut f = Fixture::new(false).await;
        success(&f.h, body(1)).await;
        f.wait(1).await;
        let previous = snapshot(&f.h).await;
        let count = publications(&f.h).await;
        f.blocked.store(1, Ordering::SeqCst);
        let request = body(1);
        let id = request["request_id"].as_str().unwrap().to_owned();
        let h = f.h.clone();
        let input = request.clone();
        let task = tokio::spawn(async move { h.post(SYNC, input).await });
        f.wait(1).await;
        if change == "cancel" {
            let conflicting = f.h.post(SYNC, body(1)).await;
            assert_eq!(conflicting.status, StatusCode::CONFLICT);
            let cancel = f.h.post(&format!("{VIEW}/operations/{id}/cancel"), json!({})).await;
            assert_eq!(cancel.status, StatusCode::OK);
            assert_eq!(cancel.json()["status"], "cancelled");
        } else {
            let mut settings = f.settings.clone();
            if change == "scope" {
                settings["namespace_id"] = json!("new-namespace");
            }
            f.change(1, change != "disabled", change == "mode", settings).await;
        }
        f.gate.add_permits(1);
        let response = task.await.unwrap();
        assert!(!response.status.is_success(), "{}", response.text);
        assert_eq!(snapshot(&f.h).await, previous);
        assert_eq!(publications(&f.h).await, count);
        let receipt = f.h.get(&format!("{VIEW}/operations/{id}")).await;
        assert_eq!(receipt.status, StatusCode::OK);
        assert_eq!(receipt.json()["published"], false);
        if change != "cancel" {
            let view = f.h.get(VIEW).await.json();
            assert_eq!(view["inventoryAvailable"], false);
            assert_eq!(view["totalServices"], Value::Null);
        }
        let calls = f.count();
        let _ = f.h.post(SYNC, request).await;
        assert_eq!(f.count(), calls);
    }
}

#[tokio::test]
async fn callback_identity_failure_rolls_back_snapshot_and_every_offline_asset() {
    let f = Fixture::new(false).await;
    success(&f.h, body(1)).await;
    let previous = snapshot(&f.h).await;
    let count = publications(&f.h).await;
    let view = f.h.get(VIEW).await.json();
    let id: Id = serde_json::from_value(view["items"][0]["assetId"].clone()).unwrap();
    let original = f.h.state.store.asset_get(f.h.tenant, id).unwrap().unwrap();
    let mut foreign = Asset::new(f.h.tenant, AssetKind::Other, "canonical collision", original.fingerprint.clone());
    foreign.id = Id::new();
    f.h.state.store.asset_upsert(&foreign).unwrap();
    // Keep the older canonical object but a second same-fingerprint object makes the candidate unsafe.
    // Force lookup to encounter the conflicting ID first by using the lowest UUID.
    foreign.id = Id::nil();
    f.h.state.store.asset_upsert(&foreign).unwrap();
    let assets = serde_json::to_value(f.h.state.store.asset_list_all(f.h.tenant).unwrap()).unwrap();
    f.replace(vec![page(1, 2, vec![service("new-before-conflict"), service("original-service")])]);
    let failed = f.h.post(SYNC, body(1)).await;
    assert_eq!(failed.status, StatusCode::CONFLICT, "{}", failed.text);
    assert_eq!(snapshot(&f.h).await, previous);
    assert_eq!(publications(&f.h).await, count);
    assert_eq!(serde_json::to_value(f.h.state.store.asset_list_all(f.h.tenant).unwrap()).unwrap(), assets);
}
