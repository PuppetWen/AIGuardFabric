//! Real SQL, independent API instances, persistent Mock writes and bound SDK enforcement.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod worker_quota_sql_helpers;
use agf_core::{
    asset::Asset,
    enums::{AlertState, AssetKind},
    ids::Id,
};
use common::*;
use futures::FutureExt;
use std::{
    panic::AssertUnwindSafe,
    sync::atomic::{AtomicUsize, Ordering},
};
use worker_quota_sql_helpers::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an owned isolated AGF_TEST_DATABASE_URL"]
async fn independent_instances_commit_only_one_binding_revision() {
    let f = fixture().await;
    let second = instance(f.db.clone()).await;
    for (expected, enabled) in [(0, true), (1, false)] {
        let before = audits(&f, None).await;
        let (a, b) = tokio::join!(bind(&f, &f.h, expected, enabled), bind(&f, &second, expected, enabled));
        assert_eq!(
            [a.status, b.status].iter().filter(|value| **value == StatusCode::OK).count(),
            1,
            "only one expected revision may commit: {} / {}",
            a.text,
            b.text
        );
        assert_eq!([a.status, b.status].iter().filter(|value| **value == StatusCode::CONFLICT).count(), 1);
        let stored = record(&f).await.unwrap();
        assert_eq!(stored["version"], expected + 1);
        assert_eq!(stored["enabled"], enabled);
        assert_eq!(audits(&f, None).await, before + 1, "losing writers cannot append a success audit");
    }
    let restarted = instance(f.db.clone()).await;
    let list = call(&restarted, f.tenant, "GET", BASE, None).await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.text);
    assert_eq!(list.json()["items"][0]["version"], 2);
    assert_eq!(list.json()["items"][0]["state"], "disabled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an owned isolated AGF_TEST_DATABASE_URL"]
async fn one_preview_has_one_cloud_writer_and_mock_readback_survives_a_new_instance() {
    let f = fixture().await;
    assert_eq!(bind(&f, &f.h, 0, true).await.status, StatusCode::OK);
    let second = instance(f.db.clone()).await;
    let preview = Id::new();
    let observed = observe(&f, &f.h, preview).await;
    assert_eq!(observed.status, StatusCode::OK, "{}", observed.text);
    assert_eq!(observed.json()["binding"]["state"], "drift");
    let alert = Id::parse(observed.json()["binding"]["driftAlertId"].as_str().unwrap()).unwrap();
    let left = sync_body(preview, Id::new());
    let right = sync_body(preview, Id::new());
    let (a, b) = tokio::join!(sync(&f, &f.h, left.clone()), sync(&f, &second, right.clone()));
    assert_eq!(
        [a.status, b.status].iter().filter(|value| **value == StatusCode::OK).count(),
        1,
        "{} / {}",
        a.text,
        b.text
    );
    assert_eq!([a.status, b.status].iter().filter(|value| **value == StatusCode::CONFLICT).count(), 1);
    let (winner, retry) = if a.status == StatusCode::OK { (a.json(), left) } else { (b.json(), right) };
    assert_eq!(winner["operation"]["status"], "verified");
    assert_eq!(winner["operation"]["changed"], true);
    assert_eq!(winner["binding"]["observation"]["usageLimit"], 100);
    assert_eq!(winner["binding"]["state"], "in-sync");
    let closed = second.state.store.alert_get_durable(f.tenant, alert).await.unwrap().unwrap();
    assert_eq!(closed.state, AlertState::Closed);
    let restarted = instance(f.db.clone()).await;
    let fresh = observe(&f, &restarted, Id::new()).await;
    assert_eq!(fresh.status, StatusCode::OK, "{}", fresh.text);
    assert_eq!(
        fresh.json()["observation"]["usageLimit"],
        100,
        "GetWorker on a fresh configuration store must read persistent Mock UpdateWorker state"
    );
    assert_eq!(fresh.json()["binding"]["state"], "in-sync");
    let repeated = sync(&f, &restarted, retry).await;
    assert_eq!(repeated.status, StatusCode::OK, "{}", repeated.text);
    assert_eq!(repeated.json()["operation"], winner["operation"]);
    let history =
        agf_api::integration_receipts::history(&restarted.state, f.tenant, "alicloud-agentteams").await.unwrap();
    assert_eq!(history.iter().filter(|run| run["operation"] == "UpdateWorker").count(), 1);
    let isolated = agf_api::tenant_directory::new(format!("worker-isolated-{}", Id::new()), "Quota isolation".into());
    agf_api::tenant_directory::save(&f.h.state, isolated.clone(), true).await.unwrap();
    let empty = call(&restarted, isolated.id, "GET", BASE, None).await;
    assert_eq!(empty.status, StatusCode::OK, "{}", empty.text);
    assert_eq!(empty.json()["items"], json!([]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an owned isolated AGF_TEST_DATABASE_URL"]
async fn actual_sdk_tokens_and_429_survive_restart_and_rules_refresh_between_instances() {
    let f = fixture().await;
    assert_eq!(bind(&f, &f.h, 0, true).await.status, StatusCode::OK);
    let endpoint = call(
        &f.h,
        f.tenant,
        "POST",
        "/api/v1/gateway/endpoints",
        Some(json!({"name":"worker-sdk",
        "provider":"mock","model":"worker-model","base_url":"http://mock.invalid","local_deployment":true})),
    )
    .await;
    assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
    let token = sdk_key(&f, f.asset, "worker-sdk").await;
    let second = instance(f.db.clone()).await;
    let mut spent = 0;
    let mut rejected = false;
    for index in 0..100 {
        let h = if index % 2 == 0 { &f.h } else { &second };
        let response = chat(h, &token).await;
        if response.status == StatusCode::TOO_MANY_REQUESTS {
            rejected = true;
            break;
        }
        assert_eq!(response.status, StatusCode::OK, "{}", response.text);
        spent += response.json()["usage"]["total_tokens"].as_i64().unwrap();
    }
    assert!(rejected && spent > 0, "real bound SDK requests must exhaust the Worker quota");
    for h in [&f.h, &second] {
        assert_eq!(agf_api::runtime_quota::usage(&h.state, f.tenant).await.unwrap()[&f.quota], spent);
        assert_eq!(chat(h, &token).await.status, StatusCode::TOO_MANY_REQUESTS);
    }
    let restarted = instance(f.db.clone()).await;
    assert_eq!(agf_api::runtime_quota::usage(&restarted.state, f.tenant).await.unwrap()[&f.quota], spent);
    assert_eq!(chat(&restarted, &token).await.status, StatusCode::TOO_MANY_REQUESTS);
    let lowered = quota(&second, f.tenant, f.asset, 1, 1).await;
    assert_eq!(lowered.status, StatusCode::OK, "{}", lowered.text);
    let loaded = agf_api::quota_definitions::list_versioned(&f.h.state, f.tenant).await.unwrap();
    assert_eq!(loaded[0].version, 2);
    assert_eq!(loaded[0].quota.limit, 1);
    assert_eq!(
        chat(&f.h, &token).await.status,
        StatusCode::TOO_MANY_REQUESTS,
        "the first instance must enforce another instance's updated definition"
    );
    let increased = quota(&second, f.tenant, f.asset, 2, 1000).await;
    assert_eq!(increased.status, StatusCode::OK, "{}", increased.text);
    let after = chat(&f.h, &token).await;
    assert_eq!(after.status, StatusCode::OK, "{}", after.text);
    spent += after.json()["usage"]["total_tokens"].as_i64().unwrap();
    assert_eq!(
        agf_api::runtime_quota::usage(&restarted.state, f.tenant).await.unwrap()[&f.quota],
        spent,
        "raising the limit must preserve consumption under the same quota identity"
    );
    let other = Asset::new(f.tenant, AssetKind::Agent, "other-sql-worker", format!("other-sql-{}", Id::new()));
    let mut tx = f.db.db().begin_tenant(f.tenant).await.unwrap();
    agf_storage::AssetRepo::upsert(&mut tx, &other).await.unwrap();
    tx.commit().await.unwrap();
    let other_key = sdk_key(&f, other.id, "other-worker-sdk").await;
    let other_response = chat(&restarted, &other_key).await;
    assert_eq!(other_response.status, StatusCode::OK, "{}", other_response.text);
    assert_eq!(
        agf_api::runtime_quota::usage(&restarted.state, f.tenant).await.unwrap()[&f.quota],
        spent,
        "a different bound Worker must not consume the selected Worker's counter"
    );
    let isolated = agf_api::tenant_directory::new(format!("sdk-isolated-{}", Id::new()), "SDK isolation".into());
    agf_api::tenant_directory::save(&f.h.state, isolated.clone(), true).await.unwrap();
    let isolated_asset =
        Asset::new(isolated.id, AssetKind::Agent, "isolated-worker", format!("isolated-{}", Id::new()));
    let mut tx = f.db.db().begin_tenant(isolated.id).await.unwrap();
    agf_storage::AssetRepo::upsert(&mut tx, &isolated_asset).await.unwrap();
    tx.commit().await.unwrap();
    let endpoint = call(
        &f.h,
        isolated.id,
        "POST",
        "/api/v1/gateway/endpoints",
        Some(json!({"name":"isolated-sdk",
        "provider":"mock","model":"worker-model","base_url":"http://mock.invalid","local_deployment":true})),
    )
    .await;
    assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
    let saved = quota(&f.h, isolated.id, isolated_asset.id, 0, 1000).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let isolated_quota = Id::parse(saved.json()["quota"]["id"].as_str().unwrap()).unwrap();
    let isolated = Fixture {
        h: f.h.clone(),
        db: f.db.clone(),
        tenant: isolated.id,
        asset: isolated_asset.id,
        quota: isolated_quota,
    };
    let isolated_key = sdk_key(&isolated, isolated.asset, "isolated-sdk").await;
    let response = chat(&restarted, &isolated_key).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(
        agf_api::runtime_quota::usage(&restarted.state, isolated.tenant).await.unwrap()[&isolated.quota],
        response.json()["usage"]["total_tokens"].as_i64().unwrap()
    );
    assert_eq!(agf_api::runtime_quota::usage(&restarted.state, f.tenant).await.unwrap()[&f.quota], spent);
}

#[tokio::test]
#[ignore = "requires an owned isolated AGF_TEST_DATABASE_URL"]
async fn binding_and_observation_publication_roll_back_with_audit_or_alert_failures() {
    let f = fixture().await;
    let predicate = format!("tenant_id='{}'::uuid AND target->>'kind'='{KIND}'", f.tenant);
    fault(&f, "audit_logs", predicate.clone(), async {
        let rejected = bind(&f, &f.h, 0, true).await;
        assert!(!rejected.status.is_success(), "{}", rejected.text);
        assert!(record(&f).await.is_none());
        assert_eq!(audits(&f, None).await, 0);
    })
    .await;
    assert_eq!(bind(&f, &f.h, 0, true).await.status, StatusCode::OK);
    let before = record(&f).await.unwrap();
    fault(&f, "audit_logs", predicate, async {
        let rejected = bind(&f, &f.h, 1, false).await;
        assert!(!rejected.status.is_success(), "{}", rejected.text);
        assert_eq!(record(&f).await.unwrap(), before);
        assert_eq!(audits(&f, None).await, 1);
    })
    .await;
    for (table, predicate) in [
        (
            "audit_logs",
            format!("tenant_id='{}'::uuid AND target->>'kind'='{KIND}' AND note LIKE '只读核对 Worker%'", f.tenant),
        ),
        ("alerts", format!("tenant_id='{}'::uuid AND title='Worker 配额限制冲突 (quota-drift)'", f.tenant)),
    ] {
        let count = audits(&f, None).await;
        let request = Id::new();
        let mut expected = before.clone();
        expected["observation_request_id"] = json!(request);
        fault(&f, table, predicate, async {
            let rejected = observe(&f, &f.h, request).await;
            assert!(!rejected.status.is_success(), "{table}: {}", rejected.text);
            assert_eq!(
                record(&f).await.unwrap(),
                expected,
                "only the start transaction's pending request marker may survive failed publication"
            );
            assert_eq!(alerts(&f).await, 0, "no drift alert may escape rollback");
            assert_eq!(audits(&f, None).await, count + 1, "only the committed start-of-observation audit survives");
            assert_eq!(audits(&f, Some("只读核对 Worker%")).await, 0);
        })
        .await;
    }
    let retried = observe(&f, &f.h, Id::new()).await;
    assert_eq!(retried.status, StatusCode::OK, "{}", retried.text);
    assert_eq!(retried.json()["binding"]["state"], "drift");
    assert_eq!(alerts(&f).await, 1);
}

#[tokio::test]
#[ignore = "requires an owned isolated AGF_TEST_DATABASE_URL"]
async fn external_write_is_uncertain_when_local_result_or_alert_publication_rolls_back() {
    for table in ["audit_logs", "alerts"] {
        // Each fault owns a different tenant; no shared constraint can block the other scenario.
        let f = fixture().await;
        assert_eq!(bind(&f, &f.h, 0, true).await.status, StatusCode::OK);
        let preview = Id::new();
        let observed = observe(&f, &f.h, preview).await;
        assert_eq!(observed.status, StatusCode::OK, "{}", observed.text);
        let alert = Id::parse(observed.json()["binding"]["driftAlertId"].as_str().unwrap()).unwrap();
        let alert_before = f.h.state.store.alert_get_durable(f.tenant, alert).await.unwrap().unwrap();
        let body = sync_body(preview, Id::new());
        let predicate = if table == "audit_logs" {
            format!(
                "tenant_id='{}'::uuid AND target->>'kind'='{KIND}' AND note LIKE 'Worker 云限制已回读核对%'",
                f.tenant
            )
        } else {
            format!("tenant_id='{}'::uuid AND id='{}'::uuid AND state='closed'", f.tenant, alert)
        };
        fault(&f, table, predicate, async {
            let result = sync(&f, &f.h, body.clone()).await;
            assert_eq!(result.status, StatusCode::OK, "{table}: {}", result.text);
            assert_eq!(
                result.json()["operation"]["status"],
                "uncertain",
                "a rolled-back local result must never advertise verified cloud enforcement"
            );
            assert_eq!(
                result.json()["operation"]["changed"],
                true,
                "Mock accepted the cloud write before local failure"
            );
            assert_ne!(result.json()["binding"]["state"], "in-sync");
            let row = record(&f).await.unwrap();
            assert_eq!(row["observation"]["cloud"]["usage_limit"], observed.json()["observation"]["usageLimit"]);
            assert_eq!(row["observation"]["preview_usable"], false);
            let run = Id::parse(row["last_operation"].as_str().unwrap()).unwrap();
            let stored: Value = f.h.state.configurations.get(f.tenant, RUNS, run).await.unwrap().unwrap();
            assert_eq!(stored["status"], "uncertain");
            let unchanged = f.h.state.store.alert_get_durable(f.tenant, alert).await.unwrap().unwrap();
            assert_eq!(serde_json::to_value(unchanged).unwrap(), serde_json::to_value(&alert_before).unwrap());
            assert_eq!(audits(&f, Some("Worker 云限制已回读核对%")).await, 0);
        })
        .await;
        let restarted = instance(f.db.clone()).await;
        let repeated = sync(&f, &restarted, body).await;
        assert_eq!(repeated.status, StatusCode::OK, "{}", repeated.text);
        assert_eq!(repeated.json()["operation"]["status"], "uncertain");
        let fresh = observe(&f, &restarted, Id::new()).await;
        // Failed publication retains the active lease. Expire only this test-owned interrupted row
        // before the explicit follow-up read, as a real process must wait for its lease deadline.
        if fresh.status == StatusCode::CONFLICT {
            f.h.state
                .configurations
                .mutate::<Value, _>(f.tenant, KIND, f.asset, |row| {
                    row["active"]["expires_at"] = json!(Timestamp::now().offset_secs(-1));
                    Ok(())
                })
                .await
                .unwrap();
        } else {
            assert_eq!(fresh.status, StatusCode::OK, "{}", fresh.text);
        }
        let fresh = observe(&f, &restarted, Id::new()).await;
        assert_eq!(fresh.status, StatusCode::OK, "{}", fresh.text);
        assert_eq!(
            fresh.json()["observation"]["usageLimit"],
            100,
            "the external write survives a failed local transaction"
        );
        assert_eq!(fresh.json()["binding"]["state"], "in-sync");
        assert_eq!(
            restarted.state.store.alert_get_durable(f.tenant, alert).await.unwrap().unwrap().state,
            AlertState::Closed
        );
        let history =
            agf_api::integration_receipts::history(&restarted.state, f.tenant, "alicloud-agentteams").await.unwrap();
        assert_eq!(
            history.iter().filter(|run| run["operation"] == "UpdateWorker").count(),
            1,
            "a failed local publication and its retries must never replay cloud writes"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an owned isolated AGF_TEST_DATABASE_URL"]
async fn finished_receipt_cannot_be_overwritten_by_a_parallel_retry_started_snapshot() {
    use agf_api::integration_receipts::{self, Run};
    let f = fixture().await;
    let request = Id::new();
    let id = agf_core::ids::deterministic_id("agf.integration.run", &format!("{}:receipt-sql:{request}", f.tenant));
    let run = Run {
        id,
        request_id: request,
        adapter: "receipt-sql".into(),
        operation: "GetWorker".into(),
        configuration_version: 1,
        request_hash: format!("receipt-sql-{request}"),
        actor: "sql-test".into(),
        started_at: Timestamp::now(),
        finished_at: None,
        status: "started".into(),
        mocked: true,
        result: None,
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let (claimed_tx, claimed_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let state = f.h.state.clone();
    let tenant = f.tenant;
    let original = run.clone();
    let count = calls.clone();
    let mut first = tokio::spawn(async move {
        integration_receipts::execute(&state, tenant, original, &BTreeMap::new(), false, async {
            count.fetch_add(1, Ordering::SeqCst);
            claimed_tx.send(()).unwrap();
            release_rx.await.unwrap();
            Ok(json!({"mocked":true,"response":{"only_execution":true}}))
        })
        .await
    });
    let mut retry = None;
    let outcome = AssertUnwindSafe(async {
        tokio::time::timeout(std::time::Duration::from_secs(10), claimed_rx).await.unwrap().unwrap();
        let lock_key = format!("{}:integration-operation:{id}", f.tenant);
        let hash: i64 = sqlx::query_scalar("SELECT hashtextextended($1,0)")
            .bind(&lock_key)
            .fetch_one(f.db.db().pool())
            .await
            .unwrap();
        retry = Some(f.db.db().begin_tenant(f.tenant).await.unwrap());
        let tx = retry.as_mut().unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(hash).execute(&mut **tx).await.unwrap();
        // This is the real retry mutation's paused point: it owns the claim lock and
        // has already read Started, but has not written that snapshot back yet.
        let started: Value = sqlx::query_scalar(
            "SELECT payload FROM console_configurations
            WHERE tenant_id=$1 AND kind='integration-operation' AND id=$2 AND deleted_at IS NULL",
        )
        .bind(f.tenant.as_uuid())
        .bind(id.as_uuid())
        .fetch_one(&mut **tx)
        .await
        .unwrap();
        assert_eq!(started["status"], "started");
        release_tx.send(()).unwrap();
        wait_for_receipt_lock(&f, &first, hash).await;
        sqlx::query(
            "UPDATE console_configurations SET payload=$3,updated_at=now()
            WHERE tenant_id=$1 AND kind='integration-operation' AND id=$2 AND deleted_at IS NULL",
        )
        .bind(f.tenant.as_uuid())
        .bind(id.as_uuid())
        .bind(started)
        .execute(&mut **tx)
        .await
        .unwrap();
        retry.take().unwrap().commit().await.unwrap();
        let finished =
            tokio::time::timeout(std::time::Duration::from_secs(10), &mut first).await.unwrap().unwrap().unwrap();
        assert_eq!(finished["status"], "succeeded");
        let saved: Run = f.h.state.configurations.get(f.tenant, "integration-operation", id).await.unwrap().unwrap();
        assert_eq!(saved.status, "succeeded");
        assert!(saved.finished_at.is_some() && saved.result.is_some());
        let restarted = instance(f.db.clone()).await;
        let cached = integration_receipts::execute(&restarted.state, f.tenant, run, &BTreeMap::new(), false, async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(json!({"response":{"should_not_execute":true}}))
        })
        .await
        .unwrap();
        assert_eq!(cached, finished, "a fresh instance must decrypt the completed durable receipt");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "a replay must never execute the upstream future again");
    })
    .catch_unwind()
    .await;
    // Release only this test-owned transaction and task before propagating any failure.
    let rollback = if let Some(tx) = retry.take() { tx.rollback().await } else { Ok(()) };
    if !first.is_finished() {
        first.abort();
        let _ = first.await;
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
    rollback.unwrap();
}
