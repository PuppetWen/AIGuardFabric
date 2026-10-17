//! Candidate-only real gateway HTTP and atomic PostgreSQL settlement. No live cloud or global env mutation.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod agentteams_quota_scope_support;
mod common;
#[allow(clippy::unwrap_used)]
mod configuration_audit_support;
mod gateway_settlement_database_support;
use agentteams_quota_scope_support::*;
use agf_core::{error::DomainResult, ids::Id};
use common::*;
use gateway_settlement_database_support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an exact-owned gateway settlement SQL database; real literal127 provider only"]
async fn paid_result_commits_usage_both_ledgers_and_one_audit_then_restart_recovery_is_pure() -> DomainResult<()> {
    let owned = Owned::open("gw-atomic-paid").await?;
    let h = live(owned.case.h.clone());
    let provider = Loopback::start().await;
    let identities = configure(&h, &provider).await;
    let cost = quota(&h, "tenant", "cost", "total", 1_000_000).await;
    let requests = quota(&h, "tenant", "requests", "total", 10).await;
    let concurrency = quota(&h, "tenant", "concurrency", "total", 2).await;
    let response = call(&h, &identities[0], "owned-settlement").await;
    accepted(&response);
    let id = response.header("x-agf-attempt-id").parse::<Id>().map_err(|_| invalid())?;
    assert_eq!(provider.calls(), 1);
    assert_eq!(settled_cost(&h).await?, 100);
    assert_eq!(used(&h, &cost).await, 100);
    assert_eq!(used(&h, &requests).await, 1);
    assert_eq!(used(&h, &concurrency).await, 0);
    assert_settled(&h, &identities[0], "owned-settlement").await;
    let restarted = live(owned.case.second_instance().await);
    let snapshot = owned.rows().await?;
    let audit = owned.case.audit_stats().await;
    for instance in [&h, &restarted] {
        let original = by_key(instance, &identities[0].key, "GET", id, None).await;
        assert_eq!(original.status, StatusCode::OK);
        assert_eq!(original.json()["state"], "settled");
        assert_eq!(original.json()["mayExecute"], false);
        let replay = by_key(instance, &identities[0].key, "POST", id, Some(json!({}))).await;
        assert_eq!(replay.status, StatusCode::OK);
        assert_eq!(replay.json(), original.json());
        assert_eq!(terminal_count(instance, id).await?, 1);
        let usage = agf_api::gateway_quota::usage(&instance.state, instance.tenant).await?;
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].cost_micro, 100);
    }
    assert_eq!(provider.calls(), 1);
    assert_eq!(owned.rows().await?, snapshot);
    assert_eq!(owned.case.audit_stats().await, audit);
    owned.chain().await?;
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an exact-owned gateway settlement SQL database; real literal127 provider only"]
async fn actual_output_limit_retains_paid_usage_and_commits_failure_in_the_same_transaction() -> DomainResult<()> {
    let owned = Owned::open("gw-atomic-output").await?;
    let h = live(owned.case.h.clone());
    let unused_provider = Loopback::start().await;
    let identities = configure(&h, &unused_provider).await;
    let provider = OverLimitReply::start().await?;
    provider.configure(&h).await?;
    let cost = quota(&h, "tenant", "cost", "total", 1_000_000).await;
    let requests = quota(&h, "tenant", "requests", "total", 10).await;
    let concurrency = quota(&h, "tenant", "concurrency", "total", 2).await;
    let fault = AuditFault::install(&owned, "gateway-attempt", "execute").await?;
    let id = with_fault(fault, async {
        let response = over_limit_call(&h, &identities[0]).await?;
        assert_eq!(response.status, StatusCode::PRECONDITION_FAILED);
        assert_eq!(provider.calls(), 1);
        assert_eq!(unused_provider.calls(), 0);
        let id = owned.attempt().await?;
        assert_eq!(response.header("x-agf-attempt-id"), id.to_string());
        assert_eq!(terminal_count(&h, id).await?, 0);
        assert!(h.state.configurations.get::<Value>(h.tenant, REJECTION, id).await?.is_none());
        assert!(agf_api::gateway_quota::usage(&h.state, h.tenant).await?.is_empty());
        assert_eq!(used(&h, &concurrency).await, 1);
        Ok(id)
    })
    .await?;
    let restarted = live(owned.case.second_instance().await);
    let receipt = by_key(&restarted, &identities[0].key, "POST", id, Some(json!({}))).await;
    assert_eq!(receipt.status, StatusCode::OK);
    assert_eq!(receipt.json()["outcomeEvidence"], "sent-usage-known");
    assert_eq!(settled_cost(&restarted).await?, 100);
    assert_eq!(used(&restarted, &cost).await, 100);
    assert_eq!(used(&restarted, &requests).await, 1);
    assert_eq!(used(&restarted, &concurrency).await, 0);
    let usage = agf_api::gateway_quota::usage(&restarted.state, h.tenant).await?;
    assert_eq!(usage.len(), 1);
    assert_eq!(usage[0].cost_micro, 100);
    assert_eq!(usage[0].completion_tokens, 5);
    let rejection: Value = restarted.state.configurations.get(h.tenant, REJECTION, id).await?.ok_or_else(invalid)?;
    assert_eq!(rejection["rejection"]["stage"], "response-screen");
    assert_eq!(rejection["rejection"]["reason"], "output-limit");
    assert_eq!(rejection["rejection"]["rule_ids"], json!(["gateway-output-limit"]));
    let chain = restarted.state.store.audit_chain_durable(h.tenant, 0, i64::MAX).await?;
    let audit = chain.iter().find(|row| json!(row.id) == rejection["audit_id"]).ok_or_else(invalid)?;
    assert_eq!(json!(audit.outcome), "failure");
    assert_eq!(audit.target.kind, "gateway-attempt");
    assert!(!json!(audit).to_string().contains(PROVIDER_TEXT));
    assert_eq!(terminal_count(&restarted, id).await?, 1);
    assert_eq!(provider.calls(), 1);
    assert_eq!(h.state.meter.snapshot().total.calls, 0);
    assert_eq!(restarted.state.meter.snapshot().total.calls, 1);
    // A separate explicit fresh request reaches the real provider again, even
    // though these identical zero-temperature inputs are otherwise cacheable.
    let repeated = over_limit_call(&restarted, &identities[0]).await?;
    assert_eq!(repeated.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!repeated.text.contains(PROVIDER_TEXT));
    assert_eq!(provider.calls(), 2);
    assert_eq!(settled_cost(&restarted).await?, 200);
    assert_eq!(used(&restarted, &cost).await, 200);
    assert_eq!(used(&restarted, &requests).await, 2);
    assert_eq!(used(&restarted, &concurrency).await, 0);
    owned.chain().await?;
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an exact-owned gateway settlement SQL database; real literal127 provider only"]
async fn admission_audit_failure_rolls_back_both_reservations_and_attempt_before_any_provider_request()
-> DomainResult<()> {
    let owned = Owned::open("gw-atomic-claim").await?;
    let h = live(owned.case.h.clone());
    let provider = Loopback::start().await;
    let identities = configure(&h, &provider).await;
    quota(&h, "tenant", "cost", "total", 1_000_000).await;
    // Initialize legitimate existing policy/quota owners before the fault snapshot.
    assert_eq!(h.get("/api/v1/policies").await.status, StatusCode::OK);
    let before = owned.rows().await?;
    let audits = owned.case.audit_stats().await;
    let fault = AuditFault::install(&owned, "gateway-admission", "configure").await?;
    with_fault(fault, async {
        let response = call(&h, &identities[0], "owned-claim-fault").await;
        assert!(response.status.is_server_error());
        assert_eq!(provider.calls(), 0);
        assert_eq!(owned.rows().await?, before);
        assert_eq!(owned.case.audit_stats().await, audits);
        Ok(())
    })
    .await?;
    // A live authenticated reader may publish a fixed permission Failure without
    // gaining the models:write permission that was just denied.
    let key = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":"owned-model-reader","scopes":["models:read"],"expires_in_secs":3600}),
        )
        .await;
    assert_eq!(key.status, StatusCode::CREATED);
    let bearer = format!("Bearer {}", key.json()["plaintext"].as_str().ok_or_else(invalid)?);
    let ledgers = owned.rows().await?;
    let audits = owned.case.audit_stats().await;
    let fault = AuditFault::install(&owned, "gateway-attempt", "execute").await?;
    with_fault(fault, async {
        let denied = h
            .request_with(
                "POST",
                "/v1/chat/completions",
                &[("authorization", bearer.as_str())],
                Some(json!({"model":MODEL,"messages":[{"role":"user","content":"owned-denial"}]})),
            )
            .await;
        assert_eq!(denied.status, StatusCode::FORBIDDEN);
        assert_eq!(owned.rows().await?, ledgers);
        assert_eq!(owned.case.audit_stats().await, audits);
        Ok(())
    })
    .await?;
    let denied = h
        .request_with(
            "POST",
            "/v1/chat/completions",
            &[("authorization", bearer.as_str())],
            Some(json!({"model":MODEL,"messages":[{"role":"user","content":"owned-denial"}]})),
        )
        .await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    assert_eq!(provider.calls(), 0);
    let id = owned.attempt().await?;
    let rejection: Value = h.state.configurations.get(h.tenant, REJECTION, id).await?.ok_or_else(invalid)?;
    let chain = h.state.store.audit_chain_durable(h.tenant, 0, i64::MAX).await?;
    let failure = chain.iter().find(|row| json!(row.id) == rejection["audit_id"]).ok_or_else(invalid)?;
    assert_eq!(json!(failure.outcome), "failure");
    assert_eq!(failure.target.kind, "gateway-attempt");
    assert_eq!(failure.target.id.as_deref(), Some(id.to_string().as_str()));
    assert_eq!(failure.after.as_ref().ok_or_else(invalid)?["reason"], "permission");
    assert!(agf_api::gateway_quota::usage(&h.state, h.tenant).await?.is_empty());
    let key = agf_api::model_routes::tenant_record_id(h.tenant);
    for kind in ["gateway-ledger", "runtime-quota-ledger"] {
        assert!(h.state.configurations.get::<Value>(h.tenant, kind, key).await?.is_none());
    }
    owned.chain().await?;
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an exact-owned gateway settlement SQL database; real literal127 provider only"]
async fn terminal_audit_failure_retains_authenticated_known_pending_and_two_instances_recover_once() -> DomainResult<()>
{
    let owned = Owned::open("gw-atomic-final").await?;
    let h = live(owned.case.h.clone());
    let provider = Loopback::start().await;
    let identities = configure(&h, &provider).await;
    let cost = quota(&h, "tenant", "cost", "total", 1_000_000).await;
    let requests = quota(&h, "tenant", "requests", "total", 10).await;
    let concurrency = quota(&h, "tenant", "concurrency", "total", 2).await;
    let fault = AuditFault::install(&owned, "gateway-attempt", "execute").await?;
    let id = with_fault(fault, async {
        let response = call(&h, &identities[0], "owned-known-pending").await;
        assert_eq!(response.status, StatusCode::PRECONDITION_FAILED);
        assert_eq!(provider.calls(), 1);
        let id = owned.attempt().await?;
        assert_eq!(response.header("x-agf-attempt-id"), id.to_string());
        assert_eq!(terminal_count(&h, id).await?, 0);
        assert!(agf_api::gateway_quota::usage(&h.state, h.tenant).await?.is_empty());
        assert_eq!(used(&h, &concurrency).await, 1);
        let before = owned.rows().await?;
        let audits = owned.case.audit_stats().await;
        let get = by_key(&h, &identities[0].key, "GET", id, None).await;
        assert_eq!(get.status, StatusCode::OK);
        assert_eq!(get.json()["state"], "pending-audit");
        assert_eq!(get.json()["mayExecute"], false);
        assert_eq!(get.json()["outcomeEvidence"], "sent-usage-known");
        assert_eq!(owned.rows().await?, before);
        assert_eq!(owned.case.audit_stats().await, audits);
        Ok(id)
    })
    .await?;
    let restarted = live(owned.case.second_instance().await);
    let (left, right) = tokio::join!(
        by_key(&h, &identities[0].key, "POST", id, Some(json!({}))),
        by_key(&restarted, &identities[0].key, "POST", id, Some(json!({})))
    );
    assert_eq!(left.status, StatusCode::OK);
    assert_eq!(right.status, StatusCode::OK);
    assert_eq!(left.json(), right.json());
    assert_eq!(left.json()["state"], "settled");
    assert_eq!(terminal_count(&h, id).await?, 1);
    assert_eq!(provider.calls(), 1);
    assert_eq!(settled_cost(&restarted).await?, 100);
    assert_eq!(used(&restarted, &cost).await, 100);
    assert_eq!(used(&restarted, &requests).await, 1);
    assert_eq!(used(&restarted, &concurrency).await, 0);
    assert_eq!(agf_api::gateway_quota::usage(&restarted.state, h.tenant).await?.len(), 1);
    assert_eq!(h.state.meter.snapshot().total.calls, 1);
    assert_eq!(restarted.state.meter.snapshot().total.calls, 1);
    owned.chain().await?;
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an exact-owned gateway settlement SQL database; real literal127 provider only"]
async fn known_recovery_cannot_change_original_actor_tenant_aad_or_request_body() -> DomainResult<()> {
    let owned = Owned::open("gw-atomic-identity").await?;
    let h = live(owned.case.h.clone());
    let provider = Loopback::start().await;
    let identities = configure(&h, &provider).await;
    let fault = AuditFault::install(&owned, "gateway-attempt", "execute").await?;
    let id = with_fault(fault, async {
        let response = call(&h, &identities[0], "owned-identity").await;
        assert_eq!(response.status, StatusCode::PRECONDITION_FAILED);
        let id = owned.attempt().await?;
        assert_eq!(response.header("x-agf-attempt-id"), id.to_string());
        Ok(id)
    })
    .await?;
    let snapshot = owned.rows().await?;
    let audits = owned.case.audit_stats().await;
    assert_eq!(by_key(&h, &identities[1].key, "POST", id, Some(json!({}))).await.status, StatusCode::FORBIDDEN);
    assert_eq!(
        by_key(&h, &identities[0].key, "POST", id, Some(json!({"retry":true}))).await.status,
        StatusCode::BAD_REQUEST
    );
    let foreign = owned.case.foreign_instance().await;
    assert_eq!(foreign.get(&format!("/api/v1/gateway/attempts/{id}")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(owned.rows().await?, snapshot);
    assert_eq!(owned.case.audit_stats().await, audits);
    owned.ownership.verify(&owned.case.pool).await?;
    let original: Value = h.state.configurations.get(h.tenant, PENDING, id).await?.ok_or_else(invalid)?;
    let mut corrupt = original.clone();
    corrupt["aad"] = json!("another-owned-identity");
    h.state.configurations.put(h.tenant, PENDING, id, &corrupt).await?;
    let corrupted = owned.rows().await?;
    assert!(by_key(&h, &identities[0].key, "POST", id, Some(json!({}))).await.status.is_server_error());
    assert!(by_key(&h, &identities[0].key, "GET", id, None).await.status.is_server_error());
    assert_eq!(owned.rows().await?, corrupted);
    assert_eq!(owned.case.audit_stats().await, audits);
    assert_eq!(provider.calls(), 1);
    h.state.configurations.put(h.tenant, PENDING, id, &original).await?;
    assert_eq!(by_key(&h, &identities[0].key, "POST", id, Some(json!({}))).await.status, StatusCode::OK);
    assert_eq!(terminal_count(&h, id).await?, 1);
    assert_eq!(provider.calls(), 1);
    owned.chain().await?;
    owned.case.pool.close().await;
    Ok(())
}
