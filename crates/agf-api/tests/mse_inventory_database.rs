//! Isolated SQL proves atomic publication, retired-asset refusal and cross-instance claims.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod configuration_audit_support;
mod integration_completion_support;
mod mse_inventory_sql_owner;
mod mse_inventory_support;
use agf_core::ids::Id;
use common::*;
use mse_inventory_support::*;
use std::sync::atomic::Ordering;

async fn assets(h: &Harness) -> Value {
    serde_json::to_value(h.state.store.asset_list_all_durable(h.tenant).await.unwrap()).unwrap()
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn publication_audit_failure_rolls_back_snapshot_assets_and_terminal_success() {
    let case = mse_inventory_sql_owner::open("mse-publication-rollback").await;
    let f = Fixture::attach(case.h.clone(), false).await;
    success(&f.h, body(1)).await;
    let id: Id = serde_json::from_value(f.h.get(VIEW).await.json()["items"][0]["assetId"].clone()).unwrap();
    sqlx::query("UPDATE assets SET name='manual-name',owner='manual-owner',department='manual-team',data_class='confidential',lifecycle='production',endpoint='manual:1234',runtime='manual-runtime',attributes=attributes||'{\"manual-note\":\"preserve\"}'::jsonb WHERE tenant_id=$1 AND id=$2")
        .bind(f.h.tenant.as_uuid()).bind(id.as_uuid()).execute(&case.pool).await.unwrap();
    let previous = snapshot(&f.h).await;
    let before = assets(&f.h).await;
    let count = publications(&f.h).await;
    f.replace(vec![page(1, 2, vec![service("original-service"), service("second-service")])]);
    let constraint = integration_completion_support::fault(
        &case.pool,
        f.h.tenant,
        "audit_logs",
        "target->>'kind'='mse-inventory-run' AND action='execute' AND outcome='success'",
    )
    .await;
    let request = body(1);
    let failure = f.h.post(SYNC, request.clone()).await;
    assert!(failure.status.is_server_error(), "{}", failure.text);
    assert_eq!(snapshot(&f.h).await, previous);
    assert_eq!(assets(&f.h).await, before);
    assert_eq!(publications(&f.h).await, count);
    let stored = ledger(&f.h).await.unwrap();
    let run = &stored["runs"][request["request_id"].as_str().unwrap()];
    assert_eq!(run["published"], false);
    assert_eq!(run["status"], "failed");
    integration_completion_support::unfault(&case.pool, "audit_logs", &constraint).await;
    let calls = f.count();
    assert_eq!(f.h.post(SYNC, request).await.status, StatusCode::OK);
    assert_eq!(f.count(), calls);
    success(&f.h, body(1)).await;
    let manual = f.h.state.store.asset_get_durable(f.h.tenant, id).await.unwrap().unwrap();
    assert_eq!(manual.name, "manual-name");
    assert_eq!(manual.owner.as_deref(), Some("manual-owner"));
    assert_eq!(manual.department.as_deref(), Some("manual-team"));
    assert_eq!(manual.endpoint.as_deref(), Some("manual:1234"));
    assert_eq!(manual.runtime.as_deref(), Some("manual-runtime"));
    assert_eq!(manual.data_class, agf_core::enums::DataClass::Confidential);
    assert_eq!(manual.lifecycle, agf_core::enums::LifecycleState::Production);
    assert_eq!(manual.attributes["manual-note"], "preserve");
    assert_eq!(publications(&f.h).await, count + 1);
    assert!(f.h.state.store.audit_verify_durable(f.h.tenant).await.unwrap().passed);
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn already_removed_assets_are_not_revived_or_reclassified_by_a_source_listing() {
    let case = mse_inventory_sql_owner::open("mse-retired-assets").await;
    let f = Fixture::attach(case.h.clone(), false).await;
    success(&f.h, body(1)).await;
    let previous = snapshot(&f.h).await;
    let count = publications(&f.h).await;
    let id: Id = serde_json::from_value(f.h.get(VIEW).await.json()["items"][0]["assetId"].clone()).unwrap();
    sqlx::query(
        "UPDATE assets SET owner='manual-owner',lifecycle='archived',deleted_at=now() WHERE tenant_id=$1 AND id=$2",
    )
    .bind(f.h.tenant.as_uuid())
    .bind(id.as_uuid())
    .execute(&case.pool)
    .await
    .unwrap();
    let failure = f.h.post(SYNC, body(1)).await;
    assert_eq!(failure.status, StatusCode::CONFLICT, "{}", failure.text);
    assert_eq!(snapshot(&f.h).await, previous);
    assert_eq!(publications(&f.h).await, count);
    let retired: (bool, String, String) =
        sqlx::query_as("SELECT deleted_at IS NOT NULL,owner,lifecycle FROM assets WHERE tenant_id=$1 AND id=$2")
            .bind(f.h.tenant.as_uuid())
            .bind(id.as_uuid())
            .fetch_one(&case.pool)
            .await
            .unwrap();
    assert_eq!(retired, (true, "manual-owner".into(), "archived".into()));
    // Explicit owned user restoration is separate from rediscovery and preserves governance.
    sqlx::query("UPDATE assets SET deleted_at=NULL WHERE tenant_id=$1 AND id=$2")
        .bind(f.h.tenant.as_uuid())
        .bind(id.as_uuid())
        .execute(&case.pool)
        .await
        .unwrap();
    success(&f.h, body(1)).await;
    let restored = f.h.state.store.asset_get_durable(f.h.tenant, id).await.unwrap().unwrap();
    assert_eq!(restored.owner.as_deref(), Some("manual-owner"));
    assert_eq!(restored.lifecycle, agf_core::enums::LifecycleState::Archived);
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn independent_instances_cannot_overlap_claims_and_restart_or_foreign_reads_do_not_redispatch() {
    let case = mse_inventory_sql_owner::open("mse-two-instances").await;
    let mut f = Fixture::attach(case.h.clone(), false).await;
    let mut second = case.second_instance().await;
    integration_completion_support::live(&mut second);
    f.blocked.store(1, Ordering::SeqCst);
    let request = body(1);
    let id = request["request_id"].as_str().unwrap().to_owned();
    let h = f.h.clone();
    let input = request.clone();
    let task = tokio::spawn(async move { h.post(SYNC, input).await });
    f.wait(1).await;
    let concurrent = second.post(SYNC, body(1)).await;
    assert_eq!(concurrent.status, StatusCode::CONFLICT, "{}", concurrent.text);
    let same = second.post(SYNC, request.clone()).await;
    assert_eq!(same.status, StatusCode::OK);
    assert_eq!(same.json()["status"], "running");
    assert_eq!(f.count(), 1);
    let cancelled = second.post(&format!("{VIEW}/operations/{id}/cancel"), json!({})).await;
    assert_eq!(cancelled.status, StatusCode::OK);
    assert_eq!(cancelled.json()["status"], "cancelled");
    f.blocked.store(0, Ordering::SeqCst);
    f.gate.add_permits(1);
    assert_eq!(task.await.unwrap().status, StatusCode::CONFLICT);
    assert!(ledger(&f.h).await.unwrap()["snapshot"].is_null());
    assert_eq!(publications(&f.h).await, 0);
    success(&second, body(1)).await;
    let view = second.get(VIEW).await.json();
    assert_eq!(view["inventoryAvailable"], true);
    assert_eq!(view["totalServices"], 1);
    let mut restarted = case.second_instance().await;
    integration_completion_support::live(&mut restarted);
    let receipt = restarted.get(&format!("{VIEW}/operations/{id}")).await;
    assert_eq!(receipt.status, StatusCode::OK);
    assert_eq!(receipt.json()["status"], "cancelled");
    let calls = f.count();
    assert_eq!(restarted.post(SYNC, request).await.status, StatusCode::OK);
    assert_eq!(f.count(), calls);
    let foreign = case.foreign_instance().await;
    assert_eq!(foreign.get(&format!("{VIEW}/operations/{id}")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(foreign.get(VIEW).await.json()["totalServices"], Value::Null);
    assert!(second.state.store.audit_verify_durable(second.tenant).await.unwrap().passed);
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn source_change_under_the_cloud_writer_lock_rejects_a_waiting_claim_without_any_provider_request() {
    let case = mse_inventory_sql_owner::open("mse-cloud-cas").await;
    let f = Fixture::attach(case.h.clone(), false).await;
    success(&f.h, body(1)).await;
    let previous = snapshot(&f.h).await;
    let count = publications(&f.h).await;
    let id = agf_api::integration_store::id(f.h.tenant, "alicloud-mse");
    let mut gate = integration_completion_support::SqlGate::acquire(
        &case.pool,
        f.h.tenant,
        format!("{}:{}:{id}", f.h.tenant, agf_api::cloud_store::KIND),
    )
    .await;
    let h = f.h.clone();
    let task = tokio::spawn(async move { h.post(SYNC, body(1)).await });
    gate.waiting(&case.pool).await;
    let mut cloud: agf_api::integration_store::Stored =
        f.h.state.configurations.get(f.h.tenant, agf_api::cloud_store::KIND, id).await.unwrap().unwrap();
    cloud.enabled = false;
    cloud.version += 1;
    gate.rewrite(agf_api::cloud_store::KIND, id, serde_json::to_value(cloud).unwrap()).await;
    gate.release().await;
    assert_eq!(task.await.unwrap().status, StatusCode::CONFLICT);
    assert_eq!(f.count(), 1);
    assert_eq!(snapshot(&f.h).await, previous);
    assert_eq!(publications(&f.h).await, count);
    let view = f.h.get(VIEW).await.json();
    assert_eq!(view["configured"], false);
    assert_eq!(view["inventoryAvailable"], false);
    assert_eq!(view["totalServices"], Value::Null);
    case.pool.close().await;
}
