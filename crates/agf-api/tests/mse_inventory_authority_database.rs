//! Revocation at the audit INSERT boundary must roll back every explicit MSE mutation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod configuration_audit_support;
mod integration_completion_support;
mod mse_inventory_authority_support;
mod mse_inventory_sql_owner;
mod mse_inventory_support;
use agf_core::ids::Id;
use common::*;
use mse_inventory_authority_support::*;
use mse_inventory_support::*;
use std::sync::atomic::Ordering;

const ARCHIVE: &str = "/api/v1/alicloud/mse/operations/archive";
const ARCHIVES: &str = "mse-inventory-archive";

fn request_id(input: &Value) -> Id {
    serde_json::from_value(input["request_id"].clone()).unwrap()
}
async fn receipt(h: &Harness, id: Id, status: &str) -> Value {
    let response = h.get(&format!("{VIEW}/operations/{id}")).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let value = response.json();
    assert_eq!(value["requestId"], json!(id));
    assert_eq!(value["status"], status);
    assert_eq!(value["archived"], false);
    value
}
async fn intact_chain(h: &Harness) {
    assert!(h.state.store.audit_verify_durable(h.tenant).await.unwrap().passed);
}

#[tokio::test]
#[ignore = "requires an exact owned AGF_TEST_DATABASE_URL and AGF_MSE_DATABASE_OWNER"]
async fn revoked_key_at_final_publication_audit_cannot_publish_assets_snapshot_or_success() {
    let case = mse_inventory_sql_owner::open("mse-publish-audit-auth").await;
    let f = Fixture::attach(case.h.clone(), false).await;
    success(&f.h, body(1)).await;
    let previous = snapshot(&f.h).await;
    let before = assets(&f.h).await;
    let count = publications(&f.h).await;
    f.replace(vec![page(1, 2, vec![service("original-service"), service("new-service")])]);
    let (token, key_id) = key(&f.h).await;
    let input = body(1);
    let id = request_id(&input);
    let pool = case.pool.clone();
    with_gate(&case.pool, f.h.tenant, Target::Publication(id), move |gate| {
        Box::pin(async move {
            let pending = Pending::start(f.h.clone(), SYNC.into(), token, input.clone());
            gate.waiting().await;
            assert_eq!(f.count(), 2, "both complete readonly provider responses precede this gate");
            revoke(&pool, f.h.tenant, key_id).await;
            gate.release().await;
            let rejected = pending.finish().await;
            assert_eq!(rejected.status, StatusCode::FORBIDDEN, "{}", rejected.text);
            assert_eq!(snapshot(&f.h).await, previous);
            assert_eq!(assets(&f.h).await, before);
            assert_eq!(publications(&f.h).await, count);
            assert_eq!(successes(&f.h, RUN_TARGET, id, "execute").await, 0);
            // Internal cleanup can terminate an already claimed run after its Key was revoked.
            let stored = ledger(&f.h).await.unwrap();
            let run = &stored["runs"][id.to_string()];
            assert_eq!(run["status"], "failed");
            assert_eq!(run["published"], false);
            assert!(stored["active"].is_null());
            let calls = f.count();
            assert_eq!(receipt(&f.h, id, "failed").await["published"], false);
            assert_eq!(f.h.post(SYNC, input).await.status, StatusCode::OK);
            assert_eq!(f.count(), calls, "GET and the original UUID only recover the local receipt");
            intact_chain(&f.h).await;
        })
    })
    .await;
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires an exact owned AGF_TEST_DATABASE_URL and AGF_MSE_DATABASE_OWNER"]
async fn revoked_key_at_claim_audit_leaves_no_claim_or_provider_dispatch() {
    let case = mse_inventory_sql_owner::open("mse-claim-audit-authority").await;
    let f = Fixture::attach(case.h.clone(), false).await;
    let before = ledger(&f.h).await;
    let before_assets = assets(&f.h).await;
    let (token, key_id) = key(&f.h).await;
    let input = body(1);
    let id = request_id(&input);
    let pool = case.pool.clone();
    with_gate(&case.pool, f.h.tenant, Target::Claim(id), move |gate| {
        Box::pin(async move {
            let pending = Pending::start(f.h.clone(), SYNC.into(), token, input);
            gate.waiting().await;
            assert_eq!(f.count(), 0);
            revoke(&pool, f.h.tenant, key_id).await;
            gate.release().await;
            let rejected = pending.finish().await;
            assert_eq!(rejected.status, StatusCode::FORBIDDEN, "{}", rejected.text);
            assert_eq!(ledger(&f.h).await, before);
            assert_eq!(assets(&f.h).await, before_assets);
            assert_eq!(successes(&f.h, RUN_TARGET, id, "create").await, 0);
            assert_eq!(f.h.get(&format!("{VIEW}/operations/{id}")).await.status, StatusCode::NOT_FOUND);
            assert_eq!(f.count(), 0, "a rolled-back claim has no receipt and GET never dispatches");
            intact_chain(&f.h).await;
        })
    })
    .await;
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires an exact owned AGF_TEST_DATABASE_URL and AGF_MSE_DATABASE_OWNER"]
async fn revoked_key_at_archive_audit_keeps_original_receipt_generation_and_assets() {
    let case = mse_inventory_sql_owner::open("mse-archive-audit-authority").await;
    let f = Fixture::attach(case.h.clone(), false).await;
    let input = body(1);
    let id = request_id(&input);
    success(&f.h, input.clone()).await;
    let before = ledger(&f.h).await;
    let before_assets = assets(&f.h).await;
    let generation = before.as_ref().unwrap()["generation"].clone();
    let cloud_id = agf_api::integration_store::id(f.h.tenant, "alicloud-mse");
    let (token, key_id) = key(&f.h).await;
    let pool = case.pool.clone();
    with_gate(&case.pool, f.h.tenant, Target::Archive { cloud_id, request: id }, move |gate| {
        Box::pin(async move {
            let pending = Pending::start(
                f.h.clone(),
                ARCHIVE.into(),
                token,
                json!({"expected_generation":generation,"request_ids":[id]}),
            );
            gate.waiting().await;
            revoke(&pool, f.h.tenant, key_id).await;
            gate.release().await;
            let rejected = pending.finish().await;
            assert_eq!(rejected.status, StatusCode::FORBIDDEN, "{}", rejected.text);
            assert_eq!(ledger(&f.h).await, before);
            assert_eq!(assets(&f.h).await, before_assets);
            assert!(f.h.state.configurations.get::<Value>(f.h.tenant, ARCHIVES, id).await.unwrap().is_none());
            assert_eq!(successes(&f.h, KIND, cloud_id, "update").await, 0);
            let calls = f.count();
            assert_eq!(receipt(&f.h, id, "succeeded").await["published"], true);
            assert_eq!(f.h.post(SYNC, input).await.status, StatusCode::OK);
            assert_eq!(f.count(), calls, "failed archive must not remove the permanent dispatch claim");
            intact_chain(&f.h).await;
        })
    })
    .await;
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires an exact owned AGF_TEST_DATABASE_URL and AGF_MSE_DATABASE_OWNER"]
async fn revoked_cancelling_key_at_cancel_audit_preserves_the_running_original_operation() {
    let case = mse_inventory_sql_owner::open("mse-cancel-audit-authority").await;
    let mut f = Fixture::attach(case.h.clone(), false).await;
    success(&f.h, body(1)).await;
    f.wait(1).await; // Drain the completed baseline's provider notification.
    let before_snapshot = snapshot(&f.h).await;
    let before_assets = assets(&f.h).await;
    let (token, key_id) = key(&f.h).await;
    let input = body(1);
    let id = request_id(&input);
    f.blocked.store(1, Ordering::SeqCst);
    let release_provider = ProviderRelease::new(&f);
    // Its authorized initiator remains valid; only the separate cancelling Key is revoked.
    let original = Pending::start(f.h.clone(), SYNC.into(), f.h.admin.clone(), input.clone());
    f.wait(1).await;
    let before = ledger(&f.h).await;
    let pool = case.pool.clone();
    with_gate(&case.pool, f.h.tenant, Target::Cancel(id), move |gate| {
        Box::pin(async move {
            let pending = Pending::start(f.h.clone(), format!("{VIEW}/operations/{id}/cancel"), token, json!({}));
            gate.waiting().await;
            revoke(&pool, f.h.tenant, key_id).await;
            gate.release().await;
            let rejected = pending.finish().await;
            assert_eq!(rejected.status, StatusCode::FORBIDDEN, "{}", rejected.text);
            assert_eq!(ledger(&f.h).await, before);
            assert_eq!(snapshot(&f.h).await, before_snapshot);
            assert_eq!(assets(&f.h).await, before_assets);
            assert_eq!(successes(&f.h, RUN_TARGET, id, "update").await, 0);
            let calls = f.count();
            assert_eq!(receipt(&f.h, id, "running").await["canCancel"], true);
            assert_eq!(f.h.post(SYNC, input).await.json()["status"], "running");
            assert_eq!(f.count(), calls, "reading/replaying the original UUID cannot re-dispatch");
            intact_chain(&f.h).await;
            // Independent authorized cleanup proves the failed cancellation did not poison the run.
            let cleanup = f.h.post(&format!("{VIEW}/operations/{id}/cancel"), json!({})).await;
            assert_eq!(cleanup.status, StatusCode::OK, "{}", cleanup.text);
            assert_eq!(cleanup.json()["status"], "cancelled");
            drop(release_provider);
            assert_eq!(original.finish().await.status, StatusCode::CONFLICT);
            receipt(&f.h, id, "cancelled").await;
            assert_eq!(f.count(), calls);
            assert_eq!(snapshot(&f.h).await, before_snapshot);
            assert_eq!(assets(&f.h).await, before_assets);
            intact_chain(&f.h).await;
        })
    })
    .await;
    case.pool.close().await;
}
