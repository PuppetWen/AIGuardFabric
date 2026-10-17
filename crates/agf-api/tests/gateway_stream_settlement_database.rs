//! Actual SQL+HTTP/SSE, never an external target. Every test starts behind the unique owner guard.
mod common;
#[allow(clippy::unwrap_used)]
mod configuration_audit_support;
mod gateway_stream_settlement_database_support;
use agf_core::{error::DomainResult, ids::Id};
use common::*;
use gateway_stream_settlement_database_support::*;

fn stream() -> RequestBody {
    RequestBody { stream: true, max_tokens: 64 }
}
fn complete() -> RequestBody {
    RequestBody { stream: false, max_tokens: 64 }
}
async fn invariant(owned: &Owned, fixture: &Fixture, id: Id, evidence: &str) -> DomainResult<Value> {
    let receipt = fixture.receipt(&fixture.h, id, false).await;
    assert!(receipt.status == StatusCode::OK, "Original receipt read failed");
    let value = receipt.json();
    assert_eq!(value["state"], "settled");
    assert_eq!(value["outcomeEvidence"], evidence);
    assert_eq!(value["mayExecute"], false);
    assert_eq!(fixture.used(&fixture.h, "requests").await?, 1);
    assert_eq!(fixture.used(&fixture.h, "concurrency").await?, 0);
    assert_eq!(owned.audit(id).await?.len(), 1);
    owned.chain().await?;
    Ok(value)
}
async fn pure_restart(owned: &Owned, fixture: &Fixture, id: Id, receipt: &Value) -> DomainResult<()> {
    let rows = owned.rows().await?;
    let audit = owned.case.audit_stats().await;
    let second = fixture.restart(owned).await?;
    for h in [&fixture.h, &second] {
        assert!(fixture.receipt(h, id, false).await.json() == *receipt, "Restart GET changed original evidence");
        assert!(fixture.receipt(h, id, true).await.json() == *receipt, "Local recovery changed immutable evidence");
    }
    assert!(owned.rows().await? == rows, "Pure GET/recovery changed complete business snapshot");
    assert_eq!(owned.case.audit_stats().await, audit);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned gateway stream SQL; only literal127 provider"]
async fn real_stream_finishes_only_after_one_atomic_paid_usage_and_terminal_audit() -> DomainResult<()> {
    let owned = Owned::open("gw-stream-complete").await?;
    let provider = Provider::start(Reply::Known).await?;
    let fixture = Fixture::new(&owned, &[&provider]).await?;
    let response = fixture.call(stream(), "owned-complete").await?;
    assert_eq!(response.status, StatusCode::OK);
    assert!(response.text.contains("[DONE]"));
    assert!(!response.text.contains("\"api_error\""));
    let id = attempt(&response)?;
    let receipt = invariant(&owned, &fixture, id, "sent-usage-known").await?;
    assert_eq!(fixture.used(&fixture.h, "cost").await?, 100);
    let rows = agf_api::gateway_quota::usage(&fixture.h.state, fixture.h.tenant).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].prompt_tokens, rows[0].completion_tokens, rows[0].cost_micro), (96, 4, 100));
    assert_eq!(serde_json::to_value(owned.audit(id).await?[0].outcome)?, json!("success"));
    pure_restart(&owned, &fixture, id, &receipt).await?;
    assert_eq!(provider.calls(), 1);
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned gateway stream SQL; only literal127 provider"]
async fn eof_with_partial_usage_keeps_actual_lower_bound_and_never_fakes_done_or_fallback() -> DomainResult<()> {
    let owned = Owned::open("gw-stream-partial").await?;
    let left = Provider::start(Reply::Partial).await?;
    let right = Provider::start(Reply::Known).await?;
    let fixture = Fixture::new(&owned, &[&left, &right]).await?;
    let response = fixture.call(stream(), "owned-partial").await?;
    assert_eq!(response.status, StatusCode::OK);
    assert!(!response.text.contains("[DONE]"));
    assert!(response.text.contains("api_error"));
    let id = attempt(&response)?;
    let receipt = invariant(&owned, &fixture, id, "sent-usage-partial").await?;
    let fact = owned.body(&fixture.h, id, FACT).await?;
    let estimated = fact["charge"]["chats"][0]["cost"].as_i64().ok_or_else(invalid)?;
    assert_eq!(fixture.used(&fixture.h, "cost").await?, estimated.max(43));
    let rows = agf_api::gateway_quota::usage(&fixture.h.state, fixture.h.tenant).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].prompt_tokens, rows[0].completion_tokens, rows[0].cost_micro), (40, 3, 43));
    assert_eq!(receipt["chargeState"], "conservative");
    assert_eq!(receipt["components"][0]["evidence"], "not-sent");
    assert_eq!(serde_json::to_value(owned.audit(id).await?[0].outcome)?, json!("failure"));
    pure_restart(&owned, &fixture, id, &receipt).await?;
    assert_eq!((left.calls(), right.calls()), (1, 0));
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned gateway stream SQL; only literal127 provider"]
async fn eof_without_usage_charges_original_estimate_and_does_not_invent_a_usage_row() -> DomainResult<()> {
    let owned = Owned::open("gw-stream-unknown").await?;
    let provider = Provider::start(Reply::Unknown).await?;
    let fixture = Fixture::new(&owned, &[&provider]).await?;
    let response = fixture.call(stream(), "owned-unknown").await?;
    let id = attempt(&response)?;
    assert!(!response.text.contains("[DONE]"));
    assert!(response.text.contains("api_error"));
    let receipt = invariant(&owned, &fixture, id, "sent-usage-unknown").await?;
    let fact = owned.body(&fixture.h, id, FACT).await?;
    assert_eq!(
        fixture.used(&fixture.h, "cost").await?,
        fact["charge"]["gateway"]["cost"].as_i64().ok_or_else(invalid)?
    );
    assert!(agf_api::gateway_quota::usage(&fixture.h.state, fixture.h.tenant).await?.is_empty());
    pure_restart(&owned, &fixture, id, &receipt).await?;
    assert_eq!(provider.calls(), 1);
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned gateway stream SQL; only literal127 provider"]
async fn real_fallback_accounts_unknown_first_and_paid_second_under_one_permanent_request() -> DomainResult<()> {
    let owned = Owned::open("gw-paid-fallback").await?;
    let left = Provider::start(Reply::HttpFailure).await?;
    let right = Provider::start(Reply::Known).await?;
    let fixture = Fixture::new(&owned, &[&left, &right]).await?;
    let response = fixture.call(complete(), "owned-fallback").await?;
    assert_eq!(response.status, StatusCode::OK);
    let id = attempt(&response)?;
    let receipt = invariant(&owned, &fixture, id, "sent-usage-unknown").await?;
    let fact = owned.body(&fixture.h, id, FACT).await?;
    let reserved = fact["charge"]["chats"][0]["cost"].as_i64().ok_or_else(invalid)?;
    assert_eq!(fixture.used(&fixture.h, "cost").await?, reserved + 100);
    assert_eq!(receipt["components"][0]["evidence"], "sent-usage-known");
    assert_eq!(receipt["components"][0]["costMicro"], 100);
    let pending = owned.body(&fixture.h, id, PENDING).await?;
    assert_eq!(pending["outcome"]["rejection"]["reason"], "provider");
    assert_eq!(serde_json::to_value(owned.audit(id).await?[0].outcome)?, json!("failure"));
    let rows = agf_api::gateway_quota::usage(&fixture.h.state, fixture.h.tenant).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(json!(rows[0].id), receipt["components"][0]["usageId"]);
    assert_ne!(receipt["usageId"], receipt["components"][0]["usageId"]);
    let snapshot = owned.rows().await?;
    let audit = owned.case.audit_stats().await;
    let second = fixture.restart(&owned).await?;
    // A second API instance must reject the same permanent admission before a physical POST.
    let replay = fixture.call_on(&second, complete(), "owned-fallback").await?;
    assert_eq!(replay.status, StatusCode::CONFLICT);
    assert_eq!(attempt(&replay)?, id);
    assert!(fixture.receipt(&second, id, false).await.json() == receipt, "Restart lost fallback evidence");
    assert!(owned.rows().await? == snapshot, "Duplicate admission changed settled state");
    assert_eq!(owned.case.audit_stats().await, audit);
    pure_restart(&owned, &fixture, id, &receipt).await?;
    assert_eq!((left.calls(), right.calls()), (1, 1));
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned gateway stream SQL; only literal127 provider"]
async fn audit_failure_withholds_stream_success_and_restart_recovery_never_reconnects() -> DomainResult<()> {
    let owned = Owned::open("gw-stream-audit").await?;
    let provider = Provider::start(Reply::Known).await?;
    let fixture = Fixture::new(&owned, &[&provider]).await?;
    let fault = Fault::terminal(&owned).await?;
    let id = with_fault(fault, async {
        let response = fixture.call(stream(), "owned-stream-audit").await?;
        let id = attempt(&response)?;
        assert!(!response.text.contains("[DONE]"));
        assert!(!response.text.contains("\"finish_reason\":\"stop\""));
        assert!(response.text.contains("api_error"));
        assert_eq!(owned.audit(id).await?.len(), 0);
        assert!(agf_api::gateway_quota::usage(&fixture.h.state, fixture.h.tenant).await?.is_empty());
        assert_eq!(fixture.used(&fixture.h, "concurrency").await?, 1);
        let pending = owned.body(&fixture.h, id, PENDING).await?;
        assert_eq!(pending["outcome"]["evidence"], "sent-usage-known");
        let before = owned.rows().await?;
        let audit = owned.case.audit_stats().await;
        assert_eq!(fixture.receipt(&fixture.h, id, false).await.json()["state"], "pending-audit");
        assert!(owned.rows().await? == before, "Pending GET mutated business records");
        assert_eq!(owned.case.audit_stats().await, audit);
        Ok(id)
    })
    .await?;
    let second = fixture.restart(&owned).await?;
    let recovered = fixture.receipt(&second, id, true).await;
    assert_eq!(recovered.status, StatusCode::OK);
    assert_eq!(fixture.used(&second, "cost").await?, 100);
    assert_eq!(fixture.used(&second, "concurrency").await?, 0);
    pure_restart(&owned, &fixture, id, &recovered.json()).await?;
    assert_eq!(provider.calls(), 1);
    owned.chain().await?;
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned gateway stream SQL; only literal127 provider"]
async fn dropping_actual_sse_body_stops_polling_and_all_later_fallback_but_preserves_fee_evidence() -> DomainResult<()>
{
    let owned = Owned::open("gw-stream-cancel").await?;
    let left = Provider::start(Reply::HeldPartial).await?;
    let right = Provider::start(Reply::Known).await?;
    let fixture = Fixture::new(&owned, &[&left, &right]).await?;
    let response = fixture.response(stream(), "owned-cancel").await?;
    let id = response
        .headers()
        .get("x-agf-attempt-id")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(invalid)?
        .parse::<Id>()
        .map_err(|_| invalid())?;
    left.framed().await?;
    drop(response);
    left.release();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while owned.audit(id).await?.len() != 1 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        Ok::<_, agf_core::error::DomainError>(())
    })
    .await
    .map_err(|_| invalid())??;
    let pending = owned.body(&fixture.h, id, PENDING).await?;
    // Cancellation may win before or after the parser sees the already emitted numeric frame.
    // Both are honest durable classifications; a separate journal test waits for parsed Partial.
    assert!(matches!(pending["outcome"]["evidence"].as_str(), Some("sent-usage-partial" | "sent-usage-unknown")));
    assert_eq!(pending["outcome"]["rejection"]["reason"], "cancelled");
    assert_eq!(fixture.used(&fixture.h, "concurrency").await?, 0);
    assert_eq!(fixture.used(&fixture.h, "requests").await?, 1);
    let fact = owned.body(&fixture.h, id, FACT).await?;
    let lower = pending["outcome"]["usage"]["cost_micro"].as_i64().unwrap_or(0);
    let estimate = fact["charge"]["chats"][0]["cost"].as_i64().ok_or_else(invalid)?;
    assert_eq!(fixture.used(&fixture.h, "cost").await?, lower.max(estimate));
    let receipt = fixture.receipt(&fixture.h, id, false).await.json();
    pure_restart(&owned, &fixture, id, &receipt).await?;
    assert_eq!((left.calls(), right.calls()), (1, 0));
    owned.chain().await?;
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned gateway stream SQL; only literal127 provider"]
async fn original_key_revoked_during_exact_terminal_audit_wait_preserves_pending_and_recovery_is_local()
-> DomainResult<()> {
    let owned = Arc::new(Owned::open("gw-stream-authority").await?);
    let provider = Arc::new(Provider::start(Reply::HeldPartial).await?);
    let fixture = Arc::new(Fixture::new(&owned, &[&provider]).await?);
    let response = fixture.response(stream(), "owned-stream-authority").await?;
    let id = response
        .headers()
        .get("x-agf-attempt-id")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(invalid)?
        .parse::<Id>()
        .map_err(|_| invalid())?;
    provider.framed().await?;
    let local_owned = owned.clone();
    let local_provider = provider.clone();
    let local_fixture = fixture.clone();
    with_gate(&owned, id, move |gate| {
        Box::pin(async move {
            let reading = Reading::start(response);
            local_provider.release();
            gate.waiting().await?;
            gate.revoke(local_fixture.key_id).await?;
            gate.release().await?;
            let text = reading.finish().await?;
            assert!(!text.contains("[DONE]"));
            assert!(text.contains("api_error"));
            assert!(local_owned.audit(id).await?.is_empty());
            assert!(agf_api::gateway_quota::usage(&local_fixture.h.state, local_fixture.h.tenant).await?.is_empty());
            assert_eq!(local_fixture.used(&local_fixture.h, "concurrency").await?, 1);
            let pending = local_owned.body(&local_fixture.h, id, PENDING).await?;
            assert_eq!(pending["outcome"]["evidence"], "sent-usage-partial");
            let snapshot = local_owned.rows().await?;
            let audit = local_owned.case.audit_stats().await;
            for recover in [false, true] {
                assert_eq!(local_fixture.receipt(&local_fixture.h, id, recover).await.status, StatusCode::UNAUTHORIZED);
            }
            assert!(local_owned.rows().await? == snapshot, "Revoked Key changed original pending evidence");
            assert_eq!(local_owned.case.audit_stats().await, audit);
            Ok(())
        })
    })
    .await?; // Finally removes only owned gate and restores this exact fixture Key.
    let second = fixture.restart(&owned).await?;
    let recovered = fixture.receipt(&second, id, true).await;
    assert_eq!(recovered.status, StatusCode::OK);
    let receipt = invariant(&owned, &fixture, id, "sent-usage-partial").await?;
    assert!(receipt == recovered.json(), "Fresh local recovery changed immutable evidence");
    assert_eq!(provider.calls(), 1);
    pure_restart(&owned, &fixture, id, &receipt).await?;
    owned.chain().await?;
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned gateway stream SQL; only literal127 provider"]
async fn combined_fallback_reservation_refusal_is_real_failure_audit_and_zero_dispatch_or_charge() -> DomainResult<()> {
    let owned = Owned::open("gw-chain-quota").await?;
    let left = Provider::start(Reply::Known).await?;
    let right = Provider::start(Reply::Known).await?;
    let fixture = Fixture::with_cost(&owned, &[&left, &right], 1).await?;
    let response = fixture.call(complete(), "owned-chain-quota").await?;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    let id = attempt(&response)?;
    assert_eq!((left.calls(), right.calls()), (0, 0));
    for dimension in ["cost", "requests", "concurrency"] {
        assert_eq!(fixture.used(&fixture.h, dimension).await?, 0);
    }
    assert!(agf_api::gateway_quota::usage(&fixture.h.state, fixture.h.tenant).await?.is_empty());
    let receipt = fixture.receipt(&fixture.h, id, false).await.json();
    assert_eq!(receipt["state"], "settled");
    assert_eq!(receipt["outcomeEvidence"], "not-sent");
    assert_eq!(receipt["mayExecute"], false);
    let pending = owned.body(&fixture.h, id, PENDING).await?;
    assert_eq!(pending["outcome"]["rejection"]["reason"], "quota");
    let audits = owned.audit(id).await?;
    assert_eq!(audits.len(), 1);
    assert_eq!(json!(audits[0].outcome), "failure");
    pure_restart(&owned, &fixture, id, &receipt).await?;
    assert_eq!((left.calls(), right.calls()), (0, 0));
    owned.chain().await?;
    owned.case.pool.close().await;
    Ok(())
}

#[path = "gateway_stream_settlement_database/delivery.rs"]
mod delivery;
#[path = "gateway_stream_settlement_database/limits.rs"]
mod limits;
