//! Exact audit-tail waits test fresh durable authority, without making a revocation audit wait on itself.
use super::{
    gate::{Mode, Target, with_gate},
    wire::Pending,
    *,
};
use agf_core::{error::DomainResult, ids::Id};

#[tokio::test]
#[ignore = "requires exact owned AGF_TEST_DATABASE_URL and AGF_APIG_POLICY_PUBLICATION_DATABASE_OWNER"]
async fn revoked_key_after_claim_audit_wait_rolls_back_claim_preview_consumption_and_every_index() -> DomainResult<()> {
    let case = SqlCase::open("apig-claim-revoke").await?;
    let f = Fixture::with_harness(case.h.clone()).await?;
    let preview = f.ready().await?;
    let request = Id::new();
    let (token, key) = key(&f.h).await?;
    let before = snapshot(&f.h).await?;
    let pool = case.pool.clone();
    with_gate(
        &case.pool,
        f.h.tenant,
        Target { kind: "apig-policy-publication-claim", id: request, action: "configure" },
        Mode::Wait,
        move |gate| {
            Box::pin(async move {
                let pending =
                    Pending::start(f.h.clone(), format!("{BASE}/operations"), token, apply_input(&preview, request)?);
                gate.waiting().await?;
                revoke(&pool, f.h.tenant, key, false).await?;
                gate.release().await?;
                let response = pending.finish().await?;
                assert_eq!(response.status, StatusCode::FORBIDDEN);
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
async fn removing_only_write_scope_after_dispatch_audit_wait_prevents_provider_entry() -> DomainResult<()> {
    let case = SqlCase::open("apig-dispatch-scope").await?;
    let f = Fixture::with_harness(case.h.clone()).await?;
    let preview = f.ready().await?;
    let request = Id::new();
    let (token, key) = key(&f.h).await?;
    let pool = case.pool.clone();
    let before_provider = provider(&f.h).await?.row;
    with_gate(
        &case.pool,
        f.h.tenant,
        Target { kind: "apig-policy-publication-dispatch", id: request, action: "configure" },
        Mode::Wait,
        move |gate| {
            Box::pin(async move {
                let pending =
                    Pending::start(f.h.clone(), format!("{BASE}/operations"), token, apply_input(&preview, request)?);
                gate.waiting().await?;
                let before = snapshot(&f.h).await?;
                revoke(&pool, f.h.tenant, key, true).await?;
                gate.release().await?;
                assert_eq!(pending.finish().await?.status, StatusCode::FORBIDDEN);
                // Cancellation-safe local staging may add PENDING, but the dispatch transaction must roll back.
                assert_eq!(provider(&f.h).await?.row, before_provider);
                assert!(audits(&f.h, request, "apig-policy-publication-dispatch").await?.is_empty());
                assert!(audits(&f.h, request, "apig-policy-publication").await?.is_empty());
                let visible = read(&f.h, &receipt_path(request)).await?;
                assert_eq!(visible["cloudWrite"]["status"], "not_attempted");
                assert_eq!(visible["completionState"], "pending_audit");
                let committed = configurations(&f.h).await?;
                // Main/Fact remain the original claimed state; only the independent local completion may be staged.
                for kind in [MAIN, FACT, DETAIL, PREVIEW, "signed-policy-registry", "quota-definitions"] {
                    assert_eq!(committed[kind], before.configurations[kind]);
                }
                let recovered = post(&f.h, &format!("{}/recover", receipt_path(request)), json!({})).await?;
                assert_eq!(recovered["cloudWrite"]["status"], "not_attempted");
                assert_eq!(recovered["completionState"], "complete");
                assert_eq!(provider(&f.h).await?.row, before_provider);
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
async fn revoked_original_key_during_terminal_audit_wait_keeps_accepted_pending_and_no_success_audit()
-> DomainResult<()> {
    let case = SqlCase::open("apig-terminal-revoke").await?;
    let f = Fixture::with_harness(case.h.clone()).await?;
    let preview = f.ready().await?;
    let request = Id::new();
    let (token, key) = key(&f.h).await?;
    let pool = case.pool.clone();
    with_gate(
        &case.pool,
        f.h.tenant,
        Target { kind: "apig-policy-publication", id: request, action: "execute" },
        Mode::Wait,
        move |gate| {
            Box::pin(async move {
                let pending =
                    Pending::start(f.h.clone(), format!("{BASE}/operations"), token, apply_input(&preview, request)?);
                gate.waiting().await?;
                assert_eq!(provider(&f.h).await?.calls("UpdatePolicy"), 1);
                let before = snapshot(&f.h).await?;
                revoke(&pool, f.h.tenant, key, false).await?;
                gate.release().await?;
                assert_eq!(pending.finish().await?.status, StatusCode::FORBIDDEN);
                assert_eq!(snapshot(&f.h).await?, before);
                let visible = read(&f.h, &receipt_path(request)).await?;
                assert_eq!(visible["cloudWrite"]["status"], "accepted");
                assert_eq!(visible["readback"]["status"], "matched");
                assert_eq!(visible["status"], "uncertain");
                assert_eq!(visible["completionState"], "pending_audit");
                assert!(audits(&f.h, request, "apig-policy-publication").await?.is_empty());
                let recovered = post(&f.h, &format!("{}/recover", receipt_path(request)), json!({})).await?;
                assert_verified(&recovered);
                assert_eq!(provider(&f.h).await?.calls("UpdatePolicy"), 1);
                assert_eq!(audits(&f.h, request, "apig-policy-publication").await?.len(), 1);
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
async fn revoked_key_after_archive_audit_wait_leaves_original_fact_ciphertext_and_counts_untouched() -> DomainResult<()>
{
    let case = SqlCase::open("apig-archive-revoke").await?;
    let f = Fixture::with_harness(case.h.clone()).await?;
    let preview = f.ready().await?;
    let request = Id::new();
    f.apply(&preview, request).await?;
    let (token, key) = key(&f.h).await?;
    let state = f.state().await?;
    let before = snapshot(&f.h).await?;
    let pool = case.pool.clone();
    let main = agf_api::integration_store::id(f.h.tenant, "alicloud-apig");
    with_gate(
        &case.pool,
        f.h.tenant,
        Target { kind: "apig-policy-publication-archive", id: main, action: "update" },
        Mode::Wait,
        move |gate| {
            Box::pin(async move {
                let pending = Pending::start(
                    f.h.clone(),
                    format!("{BASE}/operations/archive"),
                    token,
                    json!({"expected_generation":number(&state,"generation")?,"request_ids":[request]}),
                );
                gate.waiting().await?;
                revoke(&pool, f.h.tenant, key, false).await?;
                gate.release().await?;
                assert_eq!(pending.finish().await?.status, StatusCode::FORBIDDEN);
                assert_eq!(snapshot(&f.h).await?, before);
                assert_verified(&read(&f.h, &receipt_path(request)).await?);
                assert!(audits(&f.h, main, "apig-policy-publication-archive").await?.is_empty());
                chain(&f.h).await
            })
        },
    )
    .await?;
    case.pool.close().await;
    Ok(())
}
