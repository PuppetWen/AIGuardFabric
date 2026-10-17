//! Actual owned PostgreSQL routes. These definitions never authorize a real vendor call.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod scheduler_managed_jobs_database_support;
mod scheduler_managed_jobs_support;
use common::*;
use scheduler_managed_jobs_database_support::*;
use scheduler_managed_jobs_support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact owner-checked Scheduler native PostgreSQL"]
async fn two_states_same_uuid_commit_one_mock_job_and_terminal_audit_then_restart_reads_without_writes() {
    let case = Case::open("managed-once").await.unwrap();
    config(&case.h, 0, true).await.unwrap();
    let observed = observe(&case.h).await.unwrap();
    let prepared = preview(&case.h, &observed, create("report"), None).await.unwrap();
    let other = case.second().await.unwrap();
    let request = agf_core::ids::Id::new();
    let body = apply_input(&prepared);
    let path = receipt(request);
    let (a, b) = tokio::join!(
        case.h.request("PUT", &path, Some(&case.h.admin), Some(body.clone())),
        other.request("PUT", &path, Some(&other.admin), Some(body.clone()))
    );
    assert_eq!(a.status, StatusCode::OK);
    assert_eq!(b.status, StatusCode::OK);
    assert_eq!(a.json()["jobId"], b.json()["jobId"]);
    assert_eq!(a.json()["completionState"], "complete");
    assert_eq!(terminal_count(&case.h, request).await.unwrap(), 1);
    let fresh = case.second().await.unwrap();
    let before = digest(&fresh).await.unwrap();
    let read = get(&fresh, &receipt(request)).await.unwrap();
    assert_eq!(read["jobId"], a.json()["jobId"]);
    safe(&read);
    let replay = fresh.request("PUT", &receipt(request), Some(&fresh.admin), Some(body)).await;
    assert_eq!(replay.status, StatusCode::OK);
    assert_eq!(digest(&fresh).await.unwrap(), before);
    let state = get(&fresh, BASE).await.unwrap();
    assert_eq!(state["definitions"].as_array().unwrap().len(), 1);
    let foreign = case.foreign().await.unwrap();
    assert_eq!(foreign.get(&receipt(request)).await.status, StatusCode::NOT_FOUND);
    assert!(fresh.state.store.audit_verify_durable(fresh.tenant).await.unwrap().passed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact owner-checked Scheduler native PostgreSQL"]
async fn mock_terminal_audit_failure_rolls_back_job_index_preview_claim_and_journal() {
    let case = Case::open("managed-audit").await.unwrap();
    config(&case.h, 0, true).await.unwrap();
    let observed = observe(&case.h).await.unwrap();
    let prepared = preview(&case.h, &observed, create("report"), None).await.unwrap();
    let request = agf_core::ids::Id::new();
    let before = digest(&case.h).await.unwrap();
    let call_h = case.h.clone();
    let call_prepared = prepared.clone();
    fault::with_gate(&case.owner, case.h.tenant, request, fault::Mode::Reject, move |_| {
        Box::pin(async move {
            let reply =
                call_h.request("PUT", &receipt(request), Some(&call_h.admin), Some(apply_input(&call_prepared))).await;
            assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
            Ok(())
        })
    })
    .await
    .unwrap();
    assert_eq!(digest(&case.h).await.unwrap(), before);
    assert_eq!(case.h.get(&receipt(request)).await.status, StatusCode::NOT_FOUND);
    let row = get(&case.h, &format!("{BASE}/previews/{}", prepared["id"].as_str().unwrap())).await.unwrap();
    assert!(row["operationId"].is_null());
    assert_eq!(row["canApply"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact owner-checked Scheduler native PostgreSQL"]
async fn original_user_grant_revoked_at_success_audit_wait_rolls_back_mock_control() {
    let case = Case::open("managed-grant").await.unwrap();
    authority::revoke_wait(&case).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact owner-checked Scheduler native PostgreSQL"]
async fn original_signed_jwt_expires_at_success_audit_wait_rolls_back_mock_control() {
    let case = Case::open("managed-expiry").await.unwrap();
    authority::expiry_wait(&case).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact owner-checked Scheduler native PostgreSQL and its signed literal-loopback provider"]
async fn known_actual_update_ack_survives_terminal_audit_failure_and_disabled_configuration_local_recovery() {
    let case = Case::open("managed-known").await.unwrap();
    let engine = provider::Engine::new(false).await.unwrap();
    let h = provider::attach(case.h.clone(), &engine).unwrap();
    provider::configure(&h, &engine, 0, true).await.unwrap();
    let observed = provider::observe(&h).await.unwrap();
    let prepared = preview(
        &h,
        &observed,
        json!({"action":"update_schedule",
        "patch":{"time_expression":"0 0/7 * * * ?"}}),
        Some(provider::JOB),
    )
    .await
    .unwrap();
    let request = agf_core::ids::Id::new();
    let call_h = h.clone();
    let call_prepared = prepared.clone();
    fault::with_gate(&case.owner, h.tenant, request, fault::Mode::Reject, move |_| {
        Box::pin(async move {
            let reply =
                call_h.request("PUT", &receipt(request), Some(&call_h.admin), Some(apply_input(&call_prepared))).await;
            assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
            Ok(())
        })
    })
    .await
    .unwrap();
    assert_eq!(engine.writes().unwrap(), 1);
    let row = get(&h, &receipt(request)).await.unwrap();
    assert_eq!(row["completionState"], "pending_audit");
    assert_eq!(row["originalWrite"]["status"], "accepted");
    assert_eq!(terminal_count(&h, request).await.unwrap(), 0);
    safe(&row);
    provider::configure(&h, &engine, 1, false).await.unwrap();
    let fresh = case.second().await.unwrap();
    let recovered = post(&fresh, &format!("{}/recover", receipt(request)), json!({})).await.unwrap();
    assert_eq!(recovered["completionState"], "complete");
    assert_eq!(recovered["originalWrite"], row["originalWrite"]);
    assert_eq!(recovered["configurationVersion"], 1);
    assert_eq!(engine.writes().unwrap(), 1);
    assert_eq!(terminal_count(&fresh, request).await.unwrap(), 1);
    let before = digest(&fresh).await.unwrap();
    get(&fresh, &receipt(request)).await.unwrap();
    post(&fresh, &format!("{}/recover", receipt(request)), json!({})).await.unwrap();
    assert_eq!(digest(&fresh).await.unwrap(), before);
    assert!(fresh.state.store.audit_verify_durable(fresh.tenant).await.unwrap().passed);
    assert_eq!(engine.reads().unwrap(), 6);
    engine.verify().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact owner-checked Scheduler native PostgreSQL and its signed literal-loopback provider"]
async fn actual_response_loss_is_unknown_and_same_uuid_never_reissues_update_or_upgrades_after_matching_readback() {
    let case = Case::open("managed-lost").await.unwrap();
    let engine = provider::Engine::new(true).await.unwrap();
    let h = provider::attach(case.h.clone(), &engine).unwrap();
    provider::configure(&h, &engine, 0, true).await.unwrap();
    let observed = provider::observe(&h).await.unwrap();
    let prepared = preview(
        &h,
        &observed,
        json!({"action":"update_schedule",
        "patch":{"time_expression":"0 0/7 * * * ?"}}),
        Some(provider::JOB),
    )
    .await
    .unwrap();
    let request = agf_core::ids::Id::new();
    let row = apply(&h, &prepared, request).await.unwrap();
    assert_eq!(row["completionState"], "complete");
    assert_eq!(row["originalWrite"]["status"], "unknown");
    assert_eq!(engine.writes().unwrap(), 1);
    let before = digest(&h).await.unwrap();
    let reads = engine.reads().unwrap();
    get(&h, &receipt(request)).await.unwrap();
    apply(&h, &prepared, request).await.unwrap();
    assert_eq!(digest(&h).await.unwrap(), before);
    assert_eq!(engine.reads().unwrap(), reads);
    assert_eq!(engine.writes().unwrap(), 1);
    let readback = post(&h, &format!("{}/observe", receipt(request)), json!({})).await.unwrap();
    assert_eq!(readback["readback"], "matched");
    assert_eq!(readback["originalWrite"], row["originalWrite"]);
    assert_eq!(readback["status"], "uncertain");
    assert_eq!(engine.writes().unwrap(), 1);
    assert_eq!(terminal_count(&h, request).await.unwrap(), 1);
    assert_eq!(engine.reads().unwrap(), 8);
    engine.verify().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact owner-checked Scheduler native PostgreSQL"]
async fn valid_shape_preview_aad_tamper_and_foreign_sealed_copy_fail_closed_with_pure_get() {
    let case = Case::open("managed-crypto").await.unwrap();
    config(&case.h, 0, true).await.unwrap();
    let observed = observe(&case.h).await.unwrap();
    let a = preview(&case.h, &observed, create("report"), None).await.unwrap();
    let b = preview(&case.h, &observed, create("archive"), None).await.unwrap();
    let a_id = id(&a, "id").unwrap();
    let b_id = id(&b, "id").unwrap();
    crypto::corrupt_then_restore(&case, a_id).await.unwrap();
    crypto::copy_then_restore(&case, a_id, b_id).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact owner-checked Scheduler native PostgreSQL and its signed literal-loopback provider"]
async fn valid_shape_known_pending_tamper_never_recovers_or_emits_terminal_audit() {
    let case = Case::open("managed-pending").await.unwrap();
    let engine = provider::Engine::new(false).await.unwrap();
    let h = provider::attach(case.h.clone(), &engine).unwrap();
    provider::configure(&h, &engine, 0, true).await.unwrap();
    let observed = provider::observe(&h).await.unwrap();
    let prepared = preview(
        &h,
        &observed,
        json!({"action":"update_schedule",
        "patch":{"time_expression":"0 0/7 * * * ?"}}),
        Some(provider::JOB),
    )
    .await
    .unwrap();
    let request = agf_core::ids::Id::new();
    let call_h = h.clone();
    let call_prepared = prepared.clone();
    fault::with_gate(&case.owner, h.tenant, request, fault::Mode::Reject, move |_| {
        Box::pin(async move {
            assert_eq!(
                call_h
                    .request("PUT", &receipt(request), Some(&call_h.admin), Some(apply_input(&call_prepared)))
                    .await
                    .status,
                StatusCode::SERVICE_UNAVAILABLE
            );
            Ok(())
        })
    })
    .await
    .unwrap();
    crypto::pending(&case, &h, request).await.unwrap();
    assert_eq!(engine.writes().unwrap(), 1);
    assert_eq!(terminal_count(&h, request).await.unwrap(), 0);
    engine.verify().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact owner-checked Scheduler native PostgreSQL and its signed literal-loopback provider"]
async fn changed_unverified_account_label_cannot_escape_unknown_same_resource_risk_fence() {
    let case = Case::open("managed-risk").await.unwrap();
    let engine = provider::Engine::new(true).await.unwrap();
    let h = provider::attach(case.h.clone(), &engine).unwrap();
    provider::configure(&h, &engine, 0, true).await.unwrap();
    let observed = provider::observe(&h).await.unwrap();
    let change = json!({"action":"update_schedule","patch":{"time_expression":"0 0/7 * * * ?"}});
    let prepared = preview(&h, &observed, change.clone(), Some(provider::JOB)).await.unwrap();
    let request = agf_core::ids::Id::new();
    let original = apply(&h, &prepared, request).await.unwrap();
    assert_eq!(original["originalWrite"]["status"], "unknown");
    assert_eq!(engine.writes().unwrap(), 1);
    let mut settings = get(&h, CONFIG).await.unwrap();
    settings["settings"]["account_id"] = json!("changed-unverified-account-label");
    let saved = h
        .request(
            "PUT",
            CONFIG,
            Some(&h.admin),
            Some(json!({"expected_version":1,
        "enabled":true,"mock":false,"settings":settings["settings"],"secrets":{
        "access_key_id":"agf-owned-scheduler-key-no-cloud",
        "access_key_secret":"agf-owned-scheduler-signing-secret-no-cloud"}})),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK);
    assert_eq!(saved.json()["version"], 2);
    let new_observed = post(
        &h,
        &format!("{NATIVE}/observe"),
        json!({"request_id":agf_core::ids::Id::new(),
        "configuration_version":2,"initialize_mock_fixture":false,"confirm_live":false}),
    )
    .await
    .unwrap();
    let old_scope: agf_core::ids::Id = serde_json::from_value(observed["originalTarget"]["scopeId"].clone()).unwrap();
    let new_scope: agf_core::ids::Id =
        serde_json::from_value(new_observed["originalTarget"]["scopeId"].clone()).unwrap();
    assert_ne!(new_scope, old_scope);
    assert_eq!(observed["originalTarget"]["configurationVersion"], 1);
    assert_eq!(new_observed["originalTarget"]["configurationVersion"], 2);
    assert_eq!(new_observed["originalTarget"]["accountIdentityVerified"], false);
    assert_eq!(new_observed["originalTarget"]["configuredAccountId"], "changed-unverified-account-label");
    assert_eq!(new_observed["available"], true);
    let mut draft = input(&h, &new_observed, change, Some(provider::JOB), agf_core::ids::Id::new()).await.unwrap();
    draft["configuration_version"] = json!(2);
    let new_preview = post(&h, &format!("{BASE}/previews"), draft).await.unwrap();
    let before = digest(&h).await.unwrap();
    for confirmed in [false, true] {
        let mut body = apply_input(&new_preview);
        body["confirm_unknown_overlap"] = json!(confirmed);
        let refused = h.request("PUT", &receipt(agf_core::ids::Id::new()), Some(&h.admin), Some(body)).await;
        assert_eq!(refused.status, StatusCode::PRECONDITION_FAILED);
    }
    assert_eq!(digest(&h).await.unwrap(), before);
    assert_eq!(engine.writes().unwrap(), 1);
    assert_eq!(get(&h, &receipt(request)).await.unwrap()["originalWrite"], original["originalWrite"]);
    assert_eq!(terminal_count(&h, request).await.unwrap(), 1);
    engine.verify().await.unwrap();
}
