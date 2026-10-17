//! Actual PostgreSQL validates final publication authority, rollback and durable no-redispatch facts.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod configuration_audit_support;
mod integration_completion_support;
mod privatelink_inventory_sql_owner;
mod privatelink_inventory_support;
use agf_core::ids::Id;
use common::*;
use privatelink_inventory_support::*;

#[tokio::test]
#[ignore = "requires the exact owned AGF_PRIVATELINK_DATABASE_OWNER database"]
async fn publication_audit_failure_rolls_back_snapshot_asset_and_terminal_success() {
    let case = privatelink_inventory_sql_owner::open("privatelink-publication").await;
    let f = Fixture::attach(case.h.clone(), false).await;
    success(&f.h, body(1)).await;
    let id: Id = serde_json::from_value(f.h.get(VIEW).await.json()["endpoint"]["assetId"].clone()).unwrap();
    sqlx::query("UPDATE assets SET name='manual-name',owner='manual-owner',data_class='confidential',lifecycle='production',attributes=attributes||'{\"manual-note\":\"preserve\"}'::jsonb WHERE tenant_id=$1 AND id=$2")
        .bind(f.h.tenant.as_uuid()).bind(id.as_uuid()).execute(&case.pool).await.unwrap();
    let previous = snapshot(&f.h).await;
    let original = assets(&f.h).await;
    let count = publications(&f.h).await;
    let mut detail = example()[DETAIL].clone();
    detail["VpcId"] = Value::Null;
    f.replace(DETAIL, vec![detail]);
    let fault = integration_completion_support::fault(
        &case.pool,
        f.h.tenant,
        "audit_logs",
        "target->>'kind'='privatelink-inventory-run' AND action='execute' AND outcome='success'",
    )
    .await;
    let request = body(1);
    let rejected = f.h.post(SYNC, request.clone()).await;
    integration_completion_support::unfault(&case.pool, "audit_logs", &fault).await;
    assert!(rejected.status.is_server_error(), "{}", rejected.text);
    assert_eq!(snapshot(&f.h).await, previous);
    assert_eq!(assets(&f.h).await, original);
    assert_eq!(publications(&f.h).await, count);
    let run = ledger(&f.h).await.unwrap()["runs"][request["request_id"].as_str().unwrap()].clone();
    assert_eq!(run["status"], "failed");
    assert_eq!(run["published"], false);
    let calls = f.count();
    assert_eq!(f.h.post(SYNC, request).await.status, StatusCode::OK);
    assert_eq!(f.count(), calls);
    success(&f.h, body(1)).await;
    let saved = f.h.state.store.asset_get_durable(f.h.tenant, id).await.unwrap().unwrap();
    assert_eq!(saved.name, "manual-name");
    assert_eq!(saved.owner.as_deref(), Some("manual-owner"));
    assert_eq!(saved.attributes["manual-note"], "preserve");
    assert!(saved.attributes["privatelink_vpc_id"].is_null());
    assert!(f.h.state.store.audit_verify_durable(f.h.tenant).await.unwrap().passed);
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires the exact owned AGF_PRIVATELINK_DATABASE_OWNER database"]
async fn retired_endpoint_is_not_revived_and_all_previous_evidence_survives() {
    let case = privatelink_inventory_sql_owner::open("privatelink-retired").await;
    let f = Fixture::attach(case.h.clone(), false).await;
    success(&f.h, body(1)).await;
    let id: Id = serde_json::from_value(f.h.get(VIEW).await.json()["endpoint"]["assetId"].clone()).unwrap();
    let previous = snapshot(&f.h).await;
    let published = publications(&f.h).await;
    sqlx::query(
        "UPDATE assets SET deleted_at=now(),lifecycle='archived',owner='manual-owner' WHERE tenant_id=$1 AND id=$2",
    )
    .bind(f.h.tenant.as_uuid())
    .bind(id.as_uuid())
    .execute(&case.pool)
    .await
    .unwrap();
    assert_eq!(f.h.post(SYNC, body(1)).await.status, StatusCode::CONFLICT);
    assert_eq!(snapshot(&f.h).await, previous);
    assert_eq!(publications(&f.h).await, published);
    let deleted: (bool, String, String) =
        sqlx::query_as("SELECT deleted_at IS NOT NULL,owner,lifecycle FROM assets WHERE tenant_id=$1 AND id=$2")
            .bind(f.h.tenant.as_uuid())
            .bind(id.as_uuid())
            .fetch_one(&case.pool)
            .await
            .unwrap();
    assert_eq!(deleted, (true, "manual-owner".into(), "archived".into()));
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires the exact owned AGF_PRIVATELINK_DATABASE_OWNER database"]
async fn two_instances_cancel_and_restart_without_resending_the_original_uuid_or_exposing_foreign_scope() {
    let case = privatelink_inventory_sql_owner::open("privatelink-claims").await;
    let mut f = Fixture::attach(case.h.clone(), false).await;
    let mut second = case.second_instance().await;
    integration_completion_support::live(&mut second);
    *f.blocked.lock().unwrap() = ZONES.into();
    let request = body(1);
    let id = request["request_id"].as_str().unwrap().to_owned();
    let h = f.h.clone();
    let input = request.clone();
    let task = tokio::spawn(async move { h.post(SYNC, input).await });
    f.wait(ZONES).await;
    assert_eq!(second.post(SYNC, body(1)).await.status, StatusCode::CONFLICT);
    let same = second.post(SYNC, request.clone()).await;
    assert_eq!(same.status, StatusCode::OK);
    assert_eq!(same.json()["status"], "running");
    assert_eq!(f.count(), 2);
    assert_eq!(second.post(&format!("{VIEW}/operations/{id}/cancel"), json!({})).await.status, StatusCode::OK);
    f.blocked.lock().unwrap().clear();
    f.gate.add_permits(1);
    assert_eq!(task.await.unwrap().status, StatusCode::CONFLICT);
    assert!(snapshot(&f.h).await.unwrap_or(Value::Null).is_null());
    success(&second, body(1)).await;
    assert_eq!(second.get(VIEW).await.json()["topologyAvailable"], true);
    let mut restarted = case.second_instance().await;
    integration_completion_support::live(&mut restarted);
    let calls = f.count();
    assert_eq!(restarted.get(&format!("{VIEW}/operations/{id}")).await.json()["status"], "cancelled");
    assert_eq!(restarted.post(SYNC, request).await.status, StatusCode::OK);
    assert_eq!(f.count(), calls);
    let foreign = case.foreign_instance().await;
    assert_eq!(foreign.get(&format!("{VIEW}/operations/{id}")).await.status, StatusCode::NOT_FOUND);
    assert!(foreign.get(VIEW).await.json()["endpoint"].is_null());
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires the exact owned AGF_PRIVATELINK_DATABASE_OWNER database"]
async fn archive_is_atomic_generation_guarded_local_and_permanent_after_restart_or_disabled_configuration() {
    let case = privatelink_inventory_sql_owner::open("privatelink-archive").await;
    let f = Fixture::attach(case.h.clone(), false).await;
    let input = body(1);
    success(&f.h, input.clone()).await;
    let previous = ledger(&f.h).await;
    let original = assets(&f.h).await;
    let ids = vec![input["request_id"].clone()];
    let fault = integration_completion_support::fault(
        &case.pool,
        f.h.tenant,
        "audit_logs",
        "target->>'kind'='privatelink-inventory' AND action='update'",
    )
    .await;
    let rejected = archive(&f.h, ids.clone()).await;
    integration_completion_support::unfault(&case.pool, "audit_logs", &fault).await;
    assert!(rejected.status.is_server_error());
    assert_eq!(ledger(&f.h).await, previous);
    assert!(case.rows(ARCHIVES).await.is_empty());
    assert_eq!(assets(&f.h).await, original);
    let mut second = case.second_instance().await;
    integration_completion_support::live(&mut second);
    let payload = json!({"expected_generation":1,"request_ids":ids});
    let (a, b) = tokio::join!(f.h.post(ARCHIVE, payload.clone()), second.post(ARCHIVE, payload));
    assert_eq!([a.status, b.status].iter().filter(|status| **status == StatusCode::OK).count(), 1);
    assert_eq!([a.status, b.status].iter().filter(|status| **status == StatusCode::CONFLICT).count(), 1);
    assert_eq!(case.rows(ARCHIVES).await.len(), 1);
    assert_eq!(assets(&f.h).await, original);
    assert_eq!(snapshot(&f.h).await, previous.as_ref().and_then(|row| row.get("snapshot").cloned()));
    let calls = f.count();
    assert_eq!(second.post(SYNC, input.clone()).await.json()["status"], "archived");
    assert_eq!(f.count(), calls);
    f.change(1, false, false, f.settings.clone()).await;
    assert_eq!(archive(&second, vec![input["request_id"].clone()]).await.status, StatusCode::OK);
    assert_eq!(
        second.get(&format!("{VIEW}/operations/{}", input["request_id"].as_str().unwrap())).await.json()["originalStatus"],
        "succeeded"
    );
    assert_eq!(second.post(SYNC, input).await.status, StatusCode::CONFLICT);
    assert_eq!(f.count(), calls);
    assert!(second.state.store.audit_verify_durable(second.tenant).await.unwrap().passed);
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires the exact owned AGF_PRIVATELINK_DATABASE_OWNER database"]
async fn waiting_cloud_claim_sees_current_configuration_and_sends_nothing_after_disable() {
    let case = privatelink_inventory_sql_owner::open("privatelink-cloud-cas").await;
    let f = Fixture::attach(case.h.clone(), false).await;
    success(&f.h, body(1)).await;
    let previous = snapshot(&f.h).await;
    let published = publications(&f.h).await;
    let id = agf_api::integration_store::id(f.h.tenant, NAME);
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
    assert_eq!(f.count(), 3);
    assert_eq!(snapshot(&f.h).await, previous);
    assert_eq!(publications(&f.h).await, published);
    assert_eq!(f.h.get(VIEW).await.json()["topologyAvailable"], false);
    case.pool.close().await;
}
