//! Dedicated SQL faults preserve original claims and known, recoverable outcomes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod configuration_audit_support;
mod integration_completion_support;
use agf_api::integration_receipts::Run;
use common::*;
use configuration_audit_support::SqlCase;
use integration_completion_support::*;

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn audit_failure_persists_pending_and_fresh_instances_recover_once_after_configuration_disabled() {
    for cloud in [false, true] {
        let mut case = SqlCase::open("completion-rollback").await;
        live(&mut case.h);
        let server = Loopback::new(false).await;
        configure(&case.h, cloud, false, &server.endpoint).await;
        let body = body(cloud);
        let run = claim(&case.h, cloud, &body);
        let endpoint = format!("{}/operations", base(cloud));
        let constraint =
            fault(&case.pool, case.h.tenant, "audit_logs", "target->>'kind'='integration-operation'").await;
        let failed = case.h.post(&endpoint, body).await;
        assert!(failed.status.is_server_error(), "{}", failed.text);
        assert_eq!(server.count(), 1);
        let stored: Run = case.h.state.configurations.get(case.h.tenant, RUNS, run.id).await.unwrap().unwrap();
        assert_eq!(stored.status, "started");
        assert!(stored.finished_at.is_none() && stored.result.is_none());
        assert_eq!(stored.request_hash, run.request_hash);
        let pending = rows(&case.h, PENDING).await;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0]["run"]["status"], "succeeded");
        assert!(!pending[0].to_string().contains("owned-signing-secret"));
        assert!(operation_audits(&case.h, run.id).await.is_empty());
        let fresh = case.second_instance().await;
        let receipt = format!("{endpoint}/{}", run.id);
        let before = (rows(&fresh, RUNS).await, rows(&fresh, PENDING).await, case.audit_stats().await);
        for _ in 0..2 {
            let read = fresh.get(&receipt).await;
            assert_eq!(read.status, StatusCode::OK, "{}", read.text);
            assert_eq!(read.json()["status"], "uncertain");
            assert_eq!(read.json()["provider_status"], "succeeded");
            assert_eq!(read.json()["completion_state"], "pending_audit");
        }
        assert_eq!((rows(&fresh, RUNS).await, rows(&fresh, PENDING).await, case.audit_stats().await), before);
        unfault(&case.pool, "audit_logs", &constraint).await;
        let settings = if cloud { json!({"endpoint":server.endpoint,"region_id":"cn-hangzhou"}) } else { json!({}) };
        let disabled = case
            .h
            .request(
                "PUT",
                &configuration_path(cloud),
                Some(&case.h.admin),
                Some(json!({
            "expected_version":1,"enabled":false,"mock":false,"settings":settings,"secrets":{}})),
            )
            .await;
        assert_eq!(disabled.status, StatusCode::OK, "{}", disabled.text);
        let other = case.second_instance().await;
        let recover = format!("{receipt}/recover");
        let responses: [_; 2] = tokio::join!(
            fresh.request("POST", &recover, Some(&fresh.admin), None),
            other.request("POST", &recover, Some(&other.admin), None)
        )
        .into();
        for response in responses {
            assert_eq!(response.status, StatusCode::OK, "{}", response.text);
            assert_eq!(response.json()["status"], "succeeded");
            assert_eq!(response.json()["configuration_version"], 1, "recovery must preserve original configuration");
        }
        assert_eq!(server.count(), 1, "local recovery must not send provider/STS traffic");
        assert!(rows(&fresh, PENDING).await.is_empty());
        let complete: Run = fresh.state.configurations.get(fresh.tenant, RUNS, run.id).await.unwrap().unwrap();
        assert_eq!(complete.started_at, stored.started_at);
        assert_eq!(complete.actor, stored.actor);
        let audits = operation_audits(&fresh, run.id).await;
        assert_eq!(audits.len(), 1);
        assert_safe_audit(&audits[0], &complete);
        assert!(fresh.state.store.audit_verify_durable(fresh.tenant).await.unwrap().passed);
        case.pool.close().await;
    }
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn same_post_recovers_pending_without_repeating_live_delivery_or_audit() {
    let mut case = SqlCase::open("completion-post-resume").await;
    live(&mut case.h);
    let server = Loopback::new(false).await;
    configure(&case.h, false, false, &server.endpoint).await;
    let body = body(false);
    let run = claim(&case.h, false, &body);
    let endpoint = format!("{VENDOR}/operations");
    let constraint = fault(&case.pool, case.h.tenant, "audit_logs", "target->>'kind'='integration-operation'").await;
    assert!(case.h.post(&endpoint, body.clone()).await.status.is_server_error());
    assert_eq!(server.count(), 1);
    unfault(&case.pool, "audit_logs", &constraint).await;
    let mut fresh = case.second_instance().await;
    live(&mut fresh);
    let resumed = fresh.post(&endpoint, body.clone()).await;
    assert_eq!(resumed.status, StatusCode::OK, "{}", resumed.text);
    assert_eq!(resumed.json()["completion_state"], "complete");
    assert_eq!(fresh.post(&endpoint, body).await.json(), resumed.json());
    assert_eq!(server.count(), 1);
    assert_eq!(operation_audits(&fresh, run.id).await.len(), 1);
    assert!(rows(&fresh, PENDING).await.is_empty());
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn cancelling_the_parent_during_local_stage_or_audit_publish_does_not_cancel_completion() {
    for stage in [false, true] {
        let mut case = SqlCase::open("completion-cancel").await;
        live(&mut case.h);
        let server = Loopback::new(false).await;
        configure(&case.h, false, false, &server.endpoint).await;
        let body = body(false);
        let run = claim(&case.h, false, &body);
        let key = if stage {
            format!("{}:{PENDING}:{}", case.h.tenant, run.id)
        } else {
            format!("{}:audit-chain", case.h.tenant)
        };
        let gate = SqlGate::acquire(&case.pool, case.h.tenant, key).await;
        let h = case.h.clone();
        let task = tokio::spawn(async move { h.post(&format!("{VENDOR}/operations"), body).await });
        server.observed(1).await;
        gate.waiting(&case.pool).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        gate.release().await;
        let complete = wait_complete(&case.h, run.id).await;
        assert_eq!(complete.status, "succeeded");
        assert_eq!(server.count(), 1);
        assert_eq!(operation_audits(&case.h, run.id).await.len(), 1);
        assert!(rows(&case.h, PENDING).await.is_empty());
        let recover =
            case.h.request("POST", &format!("{VENDOR}/operations/{}/recover", run.id), Some(&case.h.admin), None).await;
        assert_eq!(recover.status, StatusCode::OK, "{}", recover.text);
        assert_eq!(operation_audits(&case.h, run.id).await.len(), 1);
        case.pool.close().await;
    }
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn failed_pending_stage_preserves_claim_and_prohibits_blind_provider_resend() {
    let mut case = SqlCase::open("completion-stage-fault").await;
    live(&mut case.h);
    let server = Loopback::new(false).await;
    configure(&case.h, false, false, &server.endpoint).await;
    let body = body(false);
    let run = claim(&case.h, false, &body);
    let constraint = fault(&case.pool, case.h.tenant, "console_configurations", "kind='integration-completion'").await;
    let endpoint = format!("{VENDOR}/operations");
    assert!(case.h.post(&endpoint, body.clone()).await.status.is_server_error());
    assert_eq!(server.count(), 1);
    unfault(&case.pool, "console_configurations", &constraint).await;
    assert!(rows(&case.h, PENDING).await.is_empty());
    assert_eq!(rows(&case.h, RUNS).await.len(), 1);
    assert_eq!(case.h.post(&endpoint, body).await.status, StatusCode::CONFLICT);
    assert_eq!(
        case.h.request("POST", &format!("{endpoint}/{}/recover", run.id), Some(&case.h.admin), None).await.status,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(server.count(), 1);
    assert!(operation_audits(&case.h, run.id).await.is_empty());
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn pending_cleanup_failure_cannot_turn_a_committed_completion_into_http_failure() {
    let mut case = SqlCase::open("completion-cleanup-fault").await;
    live(&mut case.h);
    let server = Loopback::new(false).await;
    configure(&case.h, false, false, &server.endpoint).await;
    let body = body(false);
    let run = claim(&case.h, false, &body);
    let constraint = fault(
        &case.pool,
        case.h.tenant,
        "console_configurations",
        "kind='integration-completion' AND deleted_at IS NOT NULL",
    )
    .await;
    let response = case.h.post(&format!("{VENDOR}/operations"), body).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.json()["completion_state"], "complete");
    assert_eq!(response.json()["status"], "succeeded");
    assert_eq!(rows(&case.h, PENDING).await.len(), 1, "only cleanup should have failed");
    let fresh = case.second_instance().await;
    let recovered =
        fresh.request("POST", &format!("{VENDOR}/operations/{}/recover", run.id), Some(&fresh.admin), None).await;
    assert_eq!(recovered.status, StatusCode::OK, "{}", recovered.text);
    assert_eq!(recovered.json(), response.json());
    assert_eq!(server.count(), 1);
    assert_eq!(operation_audits(&fresh, run.id).await.len(), 1);
    unfault(&case.pool, "console_configurations", &constraint).await;
    fresh.state.configurations.delete(fresh.tenant, PENDING, run.id).await.unwrap();
    assert_eq!(rows(&fresh, RUNS).await.len(), 1);
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn corrupt_persisted_completion_is_rejected_on_restart_without_audit_or_claim_change() {
    let case = SqlCase::open("completion-corrupt").await;
    let (run, _) = seed_pending(&case.h, true, "succeeded").await;
    let mut pending = rows(&case.h, PENDING).await.remove(0);
    pending["run"]["result"]["aad"] = json!(agf_storage::crypto::FieldCipher::make_aad(&TenantId::new(), &run.id));
    case.h.state.configurations.put(case.h.tenant, PENDING, run.id, &pending).await.unwrap();
    let fresh = case.second_instance().await;
    let before = (rows(&fresh, RUNS).await, rows(&fresh, PENDING).await, case.audit_stats().await);
    let endpoint = format!("{CLOUD}/operations/{}", run.id);
    assert!(fresh.get(&endpoint).await.status.is_server_error());
    assert!(
        fresh.request("POST", &format!("{endpoint}/recover"), Some(&fresh.admin), None).await.status.is_server_error()
    );
    assert_eq!((rows(&fresh, RUNS).await, rows(&fresh, PENDING).await, case.audit_stats().await), before);
    case.pool.close().await;
}
