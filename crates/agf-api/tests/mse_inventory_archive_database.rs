//! Durable archival preserves no-redispatch facts, and final publication refreshes authority.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod configuration_audit_support;
mod integration_completion_support;
mod mse_archive_support;
mod mse_inventory_sql_owner;
mod mse_inventory_support;
use agf_core::ids::Id;
use common::*;
use mse_archive_support::*;
use mse_inventory_support::*;

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn archive_audit_failure_rolls_back_all_rows_and_restart_keeps_original_receipts() {
    let case = mse_inventory_sql_owner::open("mse-archive-rollback").await;
    let f = Fixture::attach(case.h.clone(), false).await;
    let first = body(1);
    let second = body(1);
    success(&f.h, first.clone()).await;
    success(&f.h, second.clone()).await;
    let before = ledger(&f.h).await;
    let assets = asset_view(&f.h).await;
    let audit = archive_audits(&f.h).await;
    let fault = integration_completion_support::fault(
        &case.pool,
        f.h.tenant,
        "audit_logs",
        "target->>'kind'='mse-inventory' AND action='update'",
    )
    .await;
    let ids = vec![first["request_id"].clone(), second["request_id"].clone()];
    let rejected = archive(&f.h, ids.clone()).await;
    assert!(rejected.status.is_server_error(), "{}", rejected.text);
    assert_eq!(ledger(&f.h).await, before);
    assert_eq!(asset_view(&f.h).await, assets);
    assert!(case.rows(ARCHIVES).await.is_empty());
    assert_eq!(archive_audits(&f.h).await, audit);
    integration_completion_support::unfault(&case.pool, "audit_logs", &fault).await;
    let archived = archive(&f.h, ids.clone()).await;
    assert_eq!(archived.status, StatusCode::OK, "{}", archived.text);
    assert_eq!(case.rows(ARCHIVES).await.len(), 2);
    assert_eq!(snapshot(&f.h).await, before.as_ref().and_then(|row| row.get("snapshot").cloned()));
    assert_eq!(asset_view(&f.h).await, assets);
    let mut restarted = case.second_instance().await;
    integration_completion_support::live(&mut restarted);
    let calls = f.count();
    for input in [first.clone(), second.clone()] {
        let get = restarted.get(&format!("{VIEW}/operations/{}", input["request_id"].as_str().unwrap())).await;
        assert_eq!(get.status, StatusCode::OK);
        assert_eq!(get.json()["originalStatus"], "succeeded");
        assert_eq!(restarted.post(SYNC, input).await.json()["status"], "archived");
    }
    assert_eq!(f.count(), calls);
    assert_eq!(archive(&restarted, ids).await.status, StatusCode::OK);
    assert_eq!(archive_audits(&f.h).await, audit + 1);
    let foreign = case.foreign_instance().await;
    assert_eq!(
        foreign.get(&format!("{VIEW}/operations/{}", first["request_id"].as_str().unwrap())).await.status,
        StatusCode::NOT_FOUND
    );
    assert!(f.h.state.store.audit_verify_durable(f.h.tenant).await.unwrap().passed);
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn independent_instances_archive_with_generation_cas_and_release_full_capacity_without_reusing_ids() {
    let case = mse_inventory_sql_owner::open("mse-archive-capacity").await;
    let f = Fixture::attach(case.h.clone(), false).await;
    success(&f.h, body(1)).await;
    let requests = fill_capacity(&f.h).await;
    let before = snapshot(&f.h).await;
    let assets = asset_view(&f.h).await;
    let mut second = case.second_instance().await;
    integration_completion_support::live(&mut second);
    let ids = requests.iter().take(100).map(|row| row["request_id"].clone()).collect::<Vec<_>>();
    let request = json!({"expected_generation":512,"request_ids":ids});
    let (a, b) = tokio::join!(f.h.post(ARCHIVE, request.clone()), second.post(ARCHIVE, request));
    let statuses = [a.status, b.status];
    assert_eq!(statuses.iter().filter(|status| **status == StatusCode::OK).count(), 1);
    assert_eq!(statuses.iter().filter(|status| **status == StatusCode::CONFLICT).count(), 1);
    assert_eq!(case.rows(ARCHIVES).await.len(), 100);
    assert_eq!(ledger(&f.h).await.unwrap()["runs"].as_object().unwrap().len(), 412);
    assert_eq!(snapshot(&f.h).await, before);
    assert_eq!(asset_view(&f.h).await, assets);
    let calls = f.count();
    assert_eq!(second.post(SYNC, requests[0].clone()).await.json()["status"], "archived");
    assert_eq!(f.count(), calls);
    success(&second, body(1)).await;
    assert_eq!(f.count(), calls + 1);
    f.change(1, false, false, f.settings.clone()).await;
    let old = requests[100]["request_id"].clone();
    assert_eq!(archive(&second, vec![old.clone()]).await.status, StatusCode::OK);
    assert_eq!(second.get(&format!("{VIEW}/operations/{}", old.as_str().unwrap())).await.json()["status"], "archived");
    assert_eq!(second.post(SYNC, requests[100].clone()).await.status, StatusCode::CONFLICT);
    assert_eq!(f.count(), calls + 1);
    assert!(second.state.store.audit_verify_durable(second.tenant).await.unwrap().passed);
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn key_revoked_while_final_asset_write_waits_cannot_publish_snapshot_assets_or_success_audit() {
    let case = mse_inventory_sql_owner::open("mse-final-authority").await;
    let f = Fixture::attach(case.h.clone(), false).await;
    success(&f.h, body(1)).await;
    let id: Id = serde_json::from_value(f.h.get(VIEW).await.json()["items"][0]["assetId"].clone()).unwrap();
    let before = snapshot(&f.h).await;
    let assets = asset_view(&f.h).await;
    let count = publications(&f.h).await;
    let key = f.h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![
            Permission::from_raw("alicloud:read"),
            Permission::from_raw("alicloud:write"),
            Permission::from_raw("assets:write"),
        ],
        ..ApiKeyIssueRequest::named(f.h.tenant, "owned-publication-worker", Timestamp::now())
    });
    f.h.state.store.api_key_create_durable(&key.record).await.unwrap();
    let suffix = Id::new().as_uuid().simple().to_string();
    let function = format!("agf_test_mse_publication_{suffix}");
    let trigger = format!("{function}_trigger");
    let lock_key = format!("owned-mse-publication:{suffix}");
    let create = format!(
        "CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $owned$ BEGIN
        IF NEW.tenant_id='{}'::uuid AND NEW.id='{id}'::uuid THEN
        PERFORM pg_advisory_xact_lock(hashtextextended('{lock_key}',0)); END IF; RETURN NEW; END; $owned$",
        f.h.tenant
    );
    sqlx::query(&create).execute(&case.pool).await.unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER {trigger} BEFORE UPDATE ON assets FOR EACH ROW EXECUTE FUNCTION {function}()"
    ))
    .execute(&case.pool)
    .await
    .unwrap();
    let gate = integration_completion_support::SqlGate::acquire(&case.pool, f.h.tenant, lock_key).await;
    f.replace(vec![page(
        1,
        1,
        vec![json!({"Name":"original-service","GroupName":"owned-group","IpCount":5,"HealthyInstanceCount":4})],
    )]);
    let h = f.h.clone();
    let token = key.plaintext.clone();
    let input = body(1);
    let task = tokio::spawn(async move { h.request("POST", SYNC, Some(&token), Some(input)).await });
    gate.waiting(&case.pool).await;
    // The cloud response and initial authority checks succeeded. This gate is
    // inside the asset UPDATE, after publication has acquired its resource locks.
    let revoked =
        f.h.request("DELETE", &format!("/api/v1/settings/api-keys/{}", key.record.id), Some(&f.h.admin), None).await;
    assert!(revoked.status.is_success(), "{}", revoked.text);
    gate.release().await;
    let result = task.await.unwrap();
    sqlx::query(&format!("DROP TRIGGER {trigger} ON assets")).execute(&case.pool).await.unwrap();
    sqlx::query(&format!("DROP FUNCTION {function}()")).execute(&case.pool).await.unwrap();
    assert_eq!(result.status, StatusCode::FORBIDDEN, "{}", result.text);
    assert_eq!(snapshot(&f.h).await, before);
    assert_eq!(asset_view(&f.h).await, assets);
    assert_eq!(publications(&f.h).await, count);
    assert!(f.h.state.store.audit_verify_durable(f.h.tenant).await.unwrap().passed);
    case.pool.close().await;
}
