//! Dedicated PostgreSQL plus owned Mock/127.0.0.1 effects. No external credentials or cloud calls.
mod apig_policy_publication_database_support;
mod common;
use agf_core::{
    audit::{AuditAction, AuditOutcome},
    error::DomainResult,
    ids::Id,
};
use apig_policy_publication_database_support::*;
use apig_policy_publication_database_support::{
    gate::{Mode, Target, with_gate},
    wire::Pending,
};
use common::*;

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_APIG_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn durable_mock_receipt_and_provider_counters_survive_new_process_locks_without_resending() -> DomainResult<()> {
    let case = SqlCase::open("apig-restart").await?;
    let f = Fixture::with_harness(case.h.clone()).await?;
    let preview = f.ready().await?;
    let request = Id::new();
    let original = f.apply(&preview, request).await?;
    assert_verified(&original);
    let provider_before = provider(&f.h).await?;
    assert_eq!(provider_before.calls("UpdatePolicy"), 1);
    let before = snapshot(&f.h).await?;
    let second = case.second_instance().await?;
    assert_eq!(read(&second, &receipt_path(request)).await?, original);
    assert_eq!(post(&second, &format!("{BASE}/operations"), apply_input(&preview, request)?).await?, original);
    assert_eq!(post(&second, &format!("{}/recover", receipt_path(request)), json!({})).await?, original);
    assert_eq!(provider(&second).await?.row, provider_before.row);
    assert_eq!(snapshot(&second).await?, before);
    let mut changed = apply_input(&preview, request)?;
    changed["confirm_live"] = json!(true);
    assert_eq!(second.post(&format!("{BASE}/operations"), changed).await.status, StatusCode::CONFLICT);
    assert_eq!(snapshot(&second).await?, before);
    let foreign = case.foreign_instance().await?;
    let foreign_before = snapshot(&foreign).await?;
    assert_eq!(foreign.get(&receipt_path(request)).await.status, StatusCode::NOT_FOUND);
    assert_eq!(snapshot(&foreign).await?, foreign_before);
    assert_eq!(snapshot(&second).await?, before);
    assert_eq!(audits(&second, request, "apig-policy-publication-claim").await?.len(), 1);
    assert_eq!(audits(&second, request, "apig-policy-publication").await?.len(), 1);
    chain(&second).await?;
    case.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_APIG_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn two_sql_instances_and_two_current_actors_consume_one_preview_with_one_actual_put() -> DomainResult<()> {
    let case = SqlCase::open("apig-preview-race").await?;
    let engine = Engine::start().await?;
    let f = loopback(case.h.clone(), &engine).await?;
    let preview = f.ready().await?;
    let second = route(case.second_instance().await?, engine.address)?;
    let (token, _) = key(&second).await?;
    let winner = Id::new();
    let loser = Id::new();
    let (gate, _release) = engine.hold("PUT", 1)?;
    let pending =
        Pending::start(f.h.clone(), format!("{BASE}/operations"), f.h.admin.clone(), apply_input(&preview, winner)?);
    gate.wait_entered().await?;
    let refused =
        second.request("POST", &format!("{BASE}/operations"), Some(&token), Some(apply_input(&preview, loser)?)).await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.text);
    gate.release();
    let accepted = pending.finish().await?;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.text);
    assert_eq!(accepted.json()["status"], "verified");
    assert_eq!(accepted.json()["target"]["transportMode"], "loopback-test");
    assert_eq!(accepted.json()["target"]["mocked"], false);
    assert_eq!(engine.counts()?, (9, 1));
    assert_eq!(read(&second, &receipt_path(winner)).await?, accepted.json());
    assert_eq!(second.get(&receipt_path(loser)).await.status, StatusCode::NOT_FOUND);
    for kind in ["apig-policy-publication-claim", "apig-policy-publication"] {
        assert_eq!(audits(&second, winner, kind).await?.len(), 1);
        assert!(audits(&second, loser, kind).await?.is_empty());
    }
    chain(&second).await?;
    case.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_APIG_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn claim_audit_failure_preserves_all_candidates_and_never_reaches_the_provider() -> DomainResult<()> {
    let case = SqlCase::open("apig-claim-fault").await?;
    let f = Fixture::with_harness(case.h.clone()).await?;
    let preview = f.ready().await?;
    let request = Id::new();
    let before = snapshot(&f.h).await?;
    with_gate(
        &case.pool,
        f.h.tenant,
        Target { kind: "apig-policy-publication-claim", id: request, action: "configure" },
        Mode::Reject,
        move |_| {
            Box::pin(async move {
                assert!(
                    f.h.post(&format!("{BASE}/operations"), apply_input(&preview, request)?)
                        .await
                        .status
                        .is_server_error()
                );
                assert_eq!(snapshot(&f.h).await?, before);
                assert_eq!(provider(&f.h).await?.calls("UpdatePolicy"), 0);
                assert_eq!(f.h.get(&receipt_path(request)).await.status, StatusCode::NOT_FOUND);
                chain(&f.h).await
            })
        },
    )
    .await?;
    case.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_APIG_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn preview_audit_failure_publishes_no_fact_ciphertext_or_index() -> DomainResult<()> {
    let case = SqlCase::open("apig-preview-fault").await?;
    let f = Fixture::with_harness(case.h.clone()).await?;
    let observed = f.observe(true).await?;
    let state = f.state().await?;
    let input = preview_input(&observed, selection(&f.policy)?, number(&state, "stateVersion")?)?;
    let request = identifier(&input, "request_id")?;
    let before = snapshot(&f.h).await?;
    with_gate(
        &case.pool,
        f.h.tenant,
        Target { kind: "apig-policy-publication-preview", id: request, action: "configure" },
        Mode::Reject,
        move |_| {
            Box::pin(async move {
                assert!(f.h.post(&format!("{BASE}/previews"), input).await.status.is_server_error());
                assert_eq!(snapshot(&f.h).await?, before);
                chain(&f.h).await
            })
        },
    )
    .await?;
    case.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_APIG_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn dispatch_audit_failure_keeps_the_claim_but_publishes_a_not_attempted_terminal_once() -> DomainResult<()> {
    let case = SqlCase::open("apig-dispatch-fault").await?;
    let f = Fixture::with_harness(case.h.clone()).await?;
    let preview = f.ready().await?;
    let request = Id::new();
    let cloud_before = provider(&f.h).await?.row;
    with_gate(
        &case.pool,
        f.h.tenant,
        Target { kind: "apig-policy-publication-dispatch", id: request, action: "configure" },
        Mode::Reject,
        move |_| {
            Box::pin(async move {
                let result = f.apply(&preview, request).await?;
                assert_eq!(result["status"], "failed");
                assert_eq!(result["cloudWrite"]["status"], "not_attempted");
                assert_eq!(result["completionState"], "complete");
                assert_eq!(result["consumerApplied"], Value::Null);
                assert_eq!(provider(&f.h).await?.row, cloud_before);
                assert!(audits(&f.h, request, "apig-policy-publication-dispatch").await?.is_empty());
                let terminal = audits(&f.h, request, "apig-policy-publication").await?;
                assert_eq!(terminal.len(), 1);
                assert_eq!(terminal[0].action, AuditAction::Execute);
                assert_eq!(terminal[0].outcome, AuditOutcome::Failure);
                let committed = snapshot(&f.h).await?;
                assert_eq!(f.apply(&preview, request).await?, result);
                assert_eq!(snapshot(&f.h).await?, committed);
                chain(&f.h).await
            })
        },
    )
    .await?;
    case.pool.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_APIG_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn a_changed_quota_during_real_http_preflight_prevents_put_and_preserves_original_source_evidence()
-> DomainResult<()> {
    let case = SqlCase::open("apig-quota-preflight").await?;
    let engine = Engine::start().await?;
    let f = loopback(case.h.clone(), &engine).await?;
    let preview = f.ready().await?;
    let request = Id::new();
    let (gate, _release) = engine.hold("GET", 4)?;
    let pending =
        Pending::start(f.h.clone(), format!("{BASE}/operations"), f.h.admin.clone(), apply_input(&preview, request)?);
    gate.wait_entered().await?;
    save_quota(&f.h, quota_body(&text(&f.quota, "name")?, 1, 1400)).await?;
    gate.release();
    let response = pending.finish().await?;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let result = response.json();
    assert_eq!(result["cloudWrite"]["status"], "not_attempted");
    assert_eq!(result["status"], "conflict");
    assert_eq!(result["completionState"], "pending_audit");
    assert_eq!(engine.counts()?.1, 0);
    let second = route(case.second_instance().await?, engine.address)?;
    let recovered = post(&second, &format!("{}/recover", receipt_path(request)), json!({})).await?;
    assert_eq!(recovered["cloudWrite"]["status"], "not_attempted");
    assert_eq!(recovered["sourcePolicyVersions"], preview["sourcePolicyVersions"]);
    assert_eq!(engine.counts()?.1, 0);
    chain(&second).await?;
    case.pool.close().await;
    Ok(())
}
