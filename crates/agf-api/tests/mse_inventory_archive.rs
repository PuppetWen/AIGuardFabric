//! Explicit archival frees capacity without erasing claims or touching assets.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod mse_archive_support;
mod mse_inventory_support;
use agf_core::ids::Id;
use common::*;
use mse_archive_support::*;
use mse_inventory_support::*;
use std::sync::atomic::Ordering;

#[tokio::test]
async fn archived_receipts_survive_disabled_configuration_and_never_redispatch() {
    let f = Fixture::new(true).await;
    let first = body(1);
    let second = body(1);
    success(&f.h, first.clone()).await;
    success(&f.h, second.clone()).await;
    let old_snapshot = snapshot(&f.h).await;
    let old_assets = asset_view(&f.h).await;
    let before = archive_audits(&f.h).await;
    let response = archive(&f.h, vec![first["request_id"].clone()]).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.json()["archivedCount"], 1);
    assert_eq!(snapshot(&f.h).await, old_snapshot);
    assert_eq!(asset_view(&f.h).await, old_assets);
    let calls = f.count();
    let replay = f.h.post(SYNC, first.clone()).await;
    assert_eq!(replay.status, StatusCode::OK, "{}", replay.text);
    assert_eq!(replay.json()["status"], "archived");
    assert_eq!(replay.json()["originalStatus"], "succeeded");
    assert_eq!(replay.json()["published"], true);
    assert_eq!(replay.json()["archived"], true);
    assert_eq!(replay.json()["archivable"], false);
    assert_eq!(replay.json()["canRedispatch"], false);
    assert!(replay.json()["archivedAt"].is_string());
    assert_eq!(f.count(), calls);
    let unchanged = archive(&f.h, vec![first["request_id"].clone()]).await;
    assert_eq!(unchanged.status, StatusCode::OK);
    assert_eq!(unchanged.json()["generation"], response.json()["generation"]);
    assert_eq!(archive_audits(&f.h).await, before + 1);
    let mut altered = first.clone();
    altered["confirm_live"] = json!(false);
    assert_eq!(f.h.post(SYNC, altered).await.status, StatusCode::CONFLICT);
    f.change(1, false, true, f.settings.clone()).await;
    let receipt = f.h.get(&format!("{VIEW}/operations/{}", first["request_id"].as_str().unwrap())).await;
    assert_eq!(receipt.status, StatusCode::OK);
    assert_eq!(receipt.json()["status"], "archived");
    assert_eq!(f.h.post(SYNC, first.clone()).await.status, StatusCode::CONFLICT);
    assert_eq!(archive(&f.h, vec![second["request_id"].clone()]).await.status, StatusCode::OK);
    assert_eq!(f.h.get(VIEW).await.json()["archivedCount"], 2);
    assert_eq!(f.count(), calls);
    let foreign = setup().await;
    assert_eq!(
        foreign.get(&format!("{VIEW}/operations/{}", first["request_id"].as_str().unwrap())).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_full_ledger_can_release_one_hundred_slots_with_cas_and_permanent_tombstones() {
    let f = Fixture::new(true).await;
    success(&f.h, body(1)).await;
    let requests = fill_capacity(&f.h).await;
    let before = snapshot(&f.h).await;
    let assets = asset_view(&f.h).await;
    let count = archive_audits(&f.h).await;
    assert_eq!(f.h.post(SYNC, body(1)).await.status, StatusCode::PRECONDITION_FAILED);
    let ids = requests.iter().take(100).map(|request| request["request_id"].clone()).collect::<Vec<_>>();
    let conflict = f.h.post(ARCHIVE, json!({"expected_generation":511,"request_ids":ids})).await;
    assert_eq!(conflict.status, StatusCode::CONFLICT);
    assert_eq!(ledger(&f.h).await.unwrap()["runs"].as_object().unwrap().len(), 512);
    let result = archive(&f.h, ids.clone()).await;
    assert_eq!(result.status, StatusCode::OK, "{}", result.text);
    assert_eq!(result.json()["generation"], 513);
    assert_eq!(result.json()["archivedCount"], 100);
    assert_eq!(result.json()["archivedRequestIds"], json!(ids));
    assert_eq!(ledger(&f.h).await.unwrap()["runs"].as_object().unwrap().len(), 412);
    assert_eq!(snapshot(&f.h).await, before);
    assert_eq!(asset_view(&f.h).await, assets);
    assert_eq!(archive_audits(&f.h).await, count + 1);
    let calls = f.count();
    for request in requests.iter().take(100) {
        let replay = f.h.post(SYNC, request.clone()).await;
        assert_eq!(replay.status, StatusCode::OK, "{}", replay.text);
        assert_eq!(replay.json()["status"], "archived");
    }
    assert_eq!(f.count(), calls);
    success(&f.h, body(1)).await;
    assert_eq!(ledger(&f.h).await.unwrap()["runs"].as_object().unwrap().len(), 413);
    let viewer =
        f.h.request("POST", ARCHIVE, Some(&f.h.viewer), Some(json!({"expected_generation":514,"request_ids":ids})))
            .await;
    assert_eq!(viewer.status, StatusCode::FORBIDDEN);
    for ids in
        [vec![], vec![json!(Id::nil())], vec![requests[100]["request_id"].clone(); 2], vec![json!(Id::new()); 101]]
    {
        assert_eq!(archive(&f.h, ids).await.status, StatusCode::BAD_REQUEST);
    }
    assert!(f.h.state.store.audit_verify_durable(f.h.tenant).await.unwrap().passed);
}

#[tokio::test]
async fn expired_running_requires_explicit_cancellation_before_archival() {
    let mut f = Fixture::new(false).await;
    f.blocked.store(1, Ordering::SeqCst);
    let input = body(1);
    let id = input["request_id"].as_str().unwrap().to_owned();
    let h = f.h.clone();
    let request = input.clone();
    let task = tokio::spawn(async move { h.post(SYNC, request).await });
    f.wait(1).await;
    let mut row = ledger(&f.h).await.unwrap();
    row["runs"][&id]["started_at"] = json!(Timestamp::now().offset_secs(-121));
    row["active"]["expires_at"] = json!(Timestamp::now().offset_secs(-1));
    f.h.state
        .configurations
        .put(f.h.tenant, KIND, agf_api::integration_store::id(f.h.tenant, "alicloud-mse"), &row)
        .await
        .unwrap();
    let run = f.h.get(&format!("{VIEW}/operations/{id}")).await.json();
    assert_eq!(run["status"], "interrupted");
    assert_eq!(run["archivable"], false);
    assert_eq!(run["canCancel"], true);
    assert_eq!(archive(&f.h, vec![json!(id)]).await.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(f.h.post(&format!("{VIEW}/operations/{id}/cancel"), json!({})).await.status, StatusCode::OK);
    assert_eq!(archive(&f.h, vec![json!(id)]).await.status, StatusCode::OK);
    f.blocked.store(0, Ordering::SeqCst);
    f.gate.add_permits(1);
    assert_eq!(task.await.unwrap().status, StatusCode::CONFLICT);
    let calls = f.count();
    assert_eq!(f.h.post(SYNC, input).await.json()["originalStatus"], "cancelled");
    assert_eq!(f.count(), calls);
    assert_eq!(publications(&f.h).await, 0);
}
