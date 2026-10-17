//! Additional actual protected SQL entry cases; the original eight assertions stay in the parent.
use super::*;

const MODEL: &str = "owned-stream-settlement";

async fn unchanged_charge(owned: &Owned, fixture: &Fixture) -> DomainResult<()> {
    assert_eq!(fixture.used(&fixture.h, "requests").await?, 0);
    assert_eq!(fixture.used(&fixture.h, "concurrency").await?, 0);
    assert_eq!(fixture.used(&fixture.h, "cost").await?, 0);
    assert!(agf_api::gateway_quota::usage(&fixture.h.state, fixture.h.tenant).await?.is_empty());
    owned.chain().await
}

async fn refusal(owned: &Owned, fixture: &Fixture, response: &Resp, status: StatusCode) -> DomainResult<Id> {
    assert_eq!(response.status, status);
    let id = attempt(response)?;
    let original = fixture.receipt(&fixture.h, id, false).await;
    assert_eq!(original.status, StatusCode::OK);
    let receipt = original.json();
    assert_eq!(receipt["attemptId"], json!(id));
    assert_eq!(receipt["state"], "settled");
    assert_eq!(receipt["outcomeEvidence"], "not-sent");
    assert!(receipt["chargeState"].is_null());
    assert_eq!(receipt["mayExecute"], false);
    let audits = owned.audit(id).await?;
    assert_eq!(audits.len(), 1);
    assert_eq!(serde_json::to_value(audits[0].outcome)?, json!("failure"));
    assert!(owned.body(&fixture.h, id, FACT).await?["charge"].is_null());
    unchanged_charge(owned, fixture).await?;
    pure_restart(owned, fixture, id, &receipt).await?;
    Ok(id)
}

async fn grow_sources(owned: &Owned, fixture: &Fixture, count: usize, padding: usize) -> DomainResult<()> {
    owned.verify().await?;
    let rows: Vec<Value> = fixture.h.state.configurations.list(fixture.h.tenant, "model-endpoint").await?;
    let original = rows.iter().find(|row| row["endpoint"]["model"] == MODEL).ok_or_else(invalid)?;
    for index in 0..count {
        owned.verify().await?;
        // Existing valid endpoint and its credential reference are preserved. Only a new local
        // endpoint identity/name and optional inert unknown metadata vary; no provider is called.
        let mut row = original.clone();
        let id = Id::new();
        row["endpoint"]["id"] = json!(id);
        row["endpoint"]["name"] = json!(format!("owned-capacity-{index}"));
        if padding > 0 {
            row["legacyMetadata"] = json!("x".repeat(padding));
        }
        fixture.h.state.configurations.put(fixture.h.tenant, "model-endpoint", id, &row).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned gateway stream SQL; only literal127 provider"]
async fn complete_source_count_exhaustion_refuses_without_any_legacy_post() -> DomainResult<()> {
    let owned = Owned::open("gw-source-count").await?;
    let provider = Provider::start(Reply::Known).await?;
    let fixture = Fixture::new(&owned, &[&provider]).await?;
    grow_sources(&owned, &fixture, 513, 0).await?;
    let response = fixture.call(stream(), "owned-count-refusal").await?;
    refusal(&owned, &fixture, &response, StatusCode::PRECONDITION_FAILED).await?;
    assert_eq!(provider.calls(), 0);
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned gateway stream SQL; only literal127 provider"]
async fn complete_source_encoded_bytes_refuse_without_loading_a_prefix_or_posting() -> DomainResult<()> {
    let owned = Owned::open("gw-source-bytes").await?;
    let provider = Provider::start(Reply::Known).await?;
    let fixture = Fixture::new(&owned, &[&provider]).await?;
    grow_sources(&owned, &fixture, 9, 1024 * 1024).await?;
    let response = fixture.call(complete(), "owned-bytes-refusal").await?;
    refusal(&owned, &fixture, &response, StatusCode::PRECONDITION_FAILED).await?;
    assert_eq!(provider.calls(), 0);
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned gateway stream SQL; only literal127 provider"]
async fn empty_or_long_session_and_long_model_do_not_escape_into_legacy_accounting() -> DomainResult<()> {
    let owned = Owned::open("gw-request-limit").await?;
    let provider = Provider::start(Reply::Known).await?;
    let fixture = Fixture::new(&owned, &[&provider]).await?;
    for (index, session, model) in [
        (0, String::new(), MODEL.to_owned()),
        (1, "s".repeat(257), MODEL.to_owned()),
        (2, "owned-session".to_owned(), "m".repeat(257)),
    ] {
        let response =
            fixture.limited_call(complete(), &format!("owned-field-limit-{index}"), &session, &model).await?;
        refusal(&owned, &fixture, &response, StatusCode::BAD_REQUEST).await?;
    }
    assert_eq!(provider.calls(), 0);
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned gateway stream SQL; only literal127 provider"]
async fn nine_eligible_endpoints_produce_a_not_sent_failure_without_trying_fallback() -> DomainResult<()> {
    let owned = Owned::open("gw-chain-limit").await?;
    let provider = Provider::start(Reply::Known).await?;
    let fixture = Fixture::new(&owned, &[&provider; 9]).await?;
    let response = fixture.call(stream(), "owned-chain-refusal").await?;
    refusal(&owned, &fixture, &response, StatusCode::BAD_REQUEST).await?;
    assert_eq!(provider.calls(), 0);
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned gateway stream SQL; only literal127 provider"]
async fn capacity_failure_audit_fault_rolls_back_facts_usage_and_both_ledgers() -> DomainResult<()> {
    let owned = Owned::open("gw-capacity-audit").await?;
    let provider = Provider::start(Reply::Known).await?;
    let fixture = Fixture::new(&owned, &[&provider; 9]).await?;
    let before = owned.rows().await?;
    let audit = owned.case.audit_stats().await;
    let fault = Fault::terminal(&owned).await?;
    with_fault(fault, async {
        let response = fixture.call(complete(), "owned-capacity-fault").await?;
        assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(response.headers.get("x-agf-attempt-id").is_none());
        assert!(owned.rows().await? == before, "Failed refusal audit changed full accounting snapshot");
        assert_eq!(owned.case.audit_stats().await, audit);
        assert_eq!(provider.calls(), 0);
        unchanged_charge(&owned, &fixture).await
    })
    .await?;
    owned.case.pool.close().await;
    Ok(())
}
