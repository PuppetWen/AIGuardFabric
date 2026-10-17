//! Permanent caller key → authenticated server attempt, with real SQL/HTTP counts.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
// These shared fixture modules contain helpers unused by this narrow target.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod agentteams_quota_scope_support;
#[allow(clippy::unwrap_used)]
mod configuration_audit_support;
mod gateway_admission_idempotency_database_support;
use agentteams_quota_scope_support::{Loopback, configure, live};
use agf_core::error::DomainResult;
use common::*;
use gateway_admission_idempotency_database_support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned gateway settlement PostgreSQL; actual priced HTTP loopback only"]
async fn two_instances_share_one_admission_and_both_aliases_cannot_escape_original_key() -> DomainResult<()> {
    let owned = Owned::open("gw-key-concurrent").await?;
    let h = live(owned.case.h.clone());
    let provider = Loopback::start().await;
    let identities = configure(&h, &provider).await;
    let second = live(owned.case.second_instance().await);
    provider.block();
    let first = Pending::start(h.clone(), identities[0].key.clone(), "owned-concurrent", body("original"));
    provider.arrived().await;
    let original = lookup(&second, &identities[0].key, "owned-concurrent").await;
    assert_eq!(original.status, StatusCode::OK);
    assert_eq!(original.json()["state"], "reserved");
    let id = original.json()["attemptId"].as_str().ok_or_else(invalid)?.to_owned();
    let before = rows(&owned).await?;
    let audits = owned.case.audit_stats().await;
    for (path, input) in [
        ("/v1/chat/completions", body("original")),
        ("/api/v1/chat/completions", body("original")),
        ("/v1/chat/completions", body("changed")),
    ] {
        let replay = post(&second, &identities[0].key, "owned-concurrent", path, input).await;
        assert_eq!(replay.status, StatusCode::CONFLICT);
        assert_eq!(replay.header("x-agf-attempt-id"), id);
        assert!(!replay.text.contains("owned-response"), "receipt is not a fabricated model reply");
    }
    assert_eq!(rows(&owned).await?, before);
    assert_eq!(owned.case.audit_stats().await, audits);
    assert_eq!(provider.calls(), 1);
    provider.release();
    let accepted = first.finish().await;
    assert_eq!(accepted.status, StatusCode::OK);
    assert_eq!(accepted.header("x-agf-attempt-id"), id);
    assert_eq!(terminal_count(&h, attempt(&accepted)?).await?, 1);
    let stable = rows(&owned).await?;
    let tail = owned.case.audit_stats().await;
    let replay = post(&h, &identities[0].key, "owned-concurrent", "/v1/chat/completions", body("original")).await;
    assert_eq!(replay.status, StatusCode::CONFLICT, "durable lookup precedes successful process-body replay");
    assert_eq!(replay.header("x-agf-attempt-id"), id);
    assert_eq!(rows(&owned).await?, stable);
    assert_eq!(owned.case.audit_stats().await, tail);
    assert_eq!(provider.calls(), 1);
    owned.chain().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned gateway settlement PostgreSQL; actual priced HTTP loopback only"]
async fn caller_losing_entire_first_response_can_lookup_original_key_without_reentering_vendor() -> DomainResult<()> {
    let owned = Owned::open("gw-key-lost-response").await?;
    let h = live(owned.case.h.clone());
    let provider = Loopback::start().await;
    let identities = configure(&h, &provider).await;
    provider.block();
    let first = Pending::start(h.clone(), identities[0].key.clone(), "owned-lost", body("lost"));
    provider.arrived().await;
    first.cancel().await;
    provider.release();
    let second = live(owned.case.second_instance().await);
    let original = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            let response = lookup(&second, &identities[0].key, "owned-lost").await;
            assert_eq!(response.status, StatusCode::OK);
            if response.json()["state"] == "settled" {
                break response;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| invalid())?;
    let id = original.json()["attemptId"].as_str().ok_or_else(invalid)?.to_owned();
    assert_eq!(original.json()["mayExecute"], false);
    let before = rows(&owned).await?;
    let audits = owned.case.audit_stats().await;
    let retry = post(&second, &identities[0].key, "owned-lost", "/v1/chat/completions", body("lost")).await;
    assert_eq!(retry.status, StatusCode::CONFLICT);
    assert_eq!(retry.header("x-agf-attempt-id"), id);
    assert_eq!(rows(&owned).await?, before);
    assert_eq!(owned.case.audit_stats().await, audits);
    assert_eq!(provider.calls(), 1);
    owned.chain().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact-owned gateway settlement PostgreSQL; actual priced HTTP loopback only"]
async fn admission_fault_rolls_back_index_capacity_fact_and_both_reservations_before_vendor() -> DomainResult<()> {
    let owned = Owned::open("gw-key-claim-fault").await?;
    let h = live(owned.case.h.clone());
    let provider = Loopback::start().await;
    let identities = configure(&h, &provider).await;
    assert_eq!(h.get("/api/v1/policies").await.status, StatusCode::OK);
    assert_eq!(h.get("/api/v1/quotas").await.status, StatusCode::OK);
    let before = rows(&owned).await?;
    let audits = owned.case.audit_stats().await;
    let fault = AuditFault::install(&owned, "gateway-admission", "configure").await?;
    with_fault(fault, async {
        let response =
            post(&h, &identities[0].key, "owned-claim-fault", "/v1/chat/completions", body("claim-fault")).await;
        assert!(response.status.is_server_error());
        assert!(response.header("x-agf-attempt-id").is_empty());
        assert_eq!(rows(&owned).await?, before);
        assert_eq!(owned.case.audit_stats().await, audits);
        assert_eq!(provider.calls(), 0);
        Ok(())
    })
    .await?;
    assert_eq!(lookup(&h, &identities[0].key, "owned-claim-fault").await.status, StatusCode::NOT_FOUND);
    owned.chain().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact-owned gateway settlement PostgreSQL; actual priced HTTP loopback only"]
async fn terminal_fault_keeps_original_index_and_known_result_for_explicit_local_recovery() -> DomainResult<()> {
    let owned = Owned::open("gw-key-final-fault").await?;
    let h = live(owned.case.h.clone());
    let provider = Loopback::start().await;
    let identities = configure(&h, &provider).await;
    let fault = AuditFault::install(&owned, "gateway-attempt", "execute").await?;
    let id = with_fault(fault, async {
        let response =
            post(&h, &identities[0].key, "owned-final-fault", "/v1/chat/completions", body("final-fault")).await;
        assert_eq!(response.status, StatusCode::PRECONDITION_FAILED);
        let id = attempt(&response)?;
        let original = lookup(&h, &identities[0].key, "owned-final-fault").await;
        assert_eq!(original.status, StatusCode::OK);
        assert_eq!(original.json()["state"], "pending-audit");
        assert_eq!(original.json()["attemptId"], json!(id));
        assert_eq!(terminal_count(&h, id).await?, 0);
        assert_eq!(provider.calls(), 1);
        Ok(id)
    })
    .await?;
    let second = live(owned.case.second_instance().await);
    let recovery = by_key(&second, &identities[0].key, "POST", id, Some(json!({}))).await;
    assert_eq!(recovery.status, StatusCode::OK);
    assert_eq!(recovery.json()["state"], "settled");
    assert_eq!(terminal_count(&second, id).await?, 1);
    let before = rows(&owned).await?;
    let audits = owned.case.audit_stats().await;
    assert_eq!(lookup(&second, &identities[0].key, "owned-final-fault").await.json(), recovery.json());
    assert_eq!(
        post(&second, &identities[0].key, "owned-final-fault", "/v1/chat/completions", body("final-fault"))
            .await
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(rows(&owned).await?, before);
    assert_eq!(owned.case.audit_stats().await, audits);
    assert_eq!(provider.calls(), 1);
    owned.chain().await?;
    Ok(())
}

#[path = "gateway_admission_idempotency_database/authority.rs"]
mod authority;
#[path = "gateway_admission_idempotency_database/integrity.rs"]
mod integrity;
