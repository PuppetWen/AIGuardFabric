//! Genuine paid HTTP components and one shared PostgreSQL terminal transaction.
use super::{
    embedding::{self, Embedding, Fixture},
    *,
};
use crate::agentteams_quota_scope_support::{Loopback, quota, used};
use agf_core::error::DomainResult;

async fn usage(h: &Harness, chat_fee: u64, embedding_fee: u64) -> DomainResult<()> {
    let rows = agf_api::gateway_quota::usage(&h.state, h.tenant).await?;
    assert_eq!(rows.len(), 2);
    let main = rows.iter().find(|row| row.model == crate::agentteams_quota_scope_support::MODEL).ok_or_else(invalid)?;
    let paid = rows.iter().find(|row| row.model == "owned-settlement-embedding").ok_or_else(invalid)?;
    assert_ne!(main.id, paid.id);
    assert_eq!(main.cost_micro, chat_fee);
    assert_eq!(paid.cost_micro, embedding_fee);
    assert!(!paid.mocked && !paid.cache_hit);
    assert_eq!(paid.completion_tokens, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned gateway SQL and default-off test-loopback-transport"]
async fn paid_embedding_miss_then_semantic_hit_keeps_actual_fee_and_durable_bounded_checkpoint() -> DomainResult<()> {
    let owned = Owned::open("gw-semantic-hit").await?;
    let chat = Loopback::start().await;
    let embedding = Embedding::start().await?;
    let fixture = Fixture::new(owned.case.h.clone(), &chat, &embedding).await?;
    let cost = quota(&fixture.h, "tenant", "cost", "total", 1_000_000).await;
    let requests = quota(&fixture.h, "tenant", "requests", "total", 10).await;
    let first = fixture.call("hello paid semantic one").await?;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.header("x-agf-cached"), "false");
    let first_id = embedding::attempt(&first)?;
    assert_eq!((chat.calls(), embedding.calls()), (1, 1));
    usage(&fixture.h, 100, 2).await?;
    assert_eq!(embedding::cache_count(&owned).await?, 1);
    let second = fixture.call("hello paid semantic two").await?;
    assert_eq!(second.status, StatusCode::OK);
    assert_eq!(second.header("x-agf-cached"), "true");
    assert_ne!(embedding::attempt(&second)?, first_id);
    // Different wire inputs prevent an exact-cache shortcut from proving semantic lookup.
    assert_eq!((chat.calls(), embedding.calls()), (1, 2));
    assert_eq!(settled_cost(&fixture.h).await?, 104);
    assert_eq!(used(&fixture.h, &cost).await, 104);
    assert_eq!(used(&fixture.h, &requests).await, 2);
    assert_eq!(fixture.h.state.meter.snapshot().total.cost_micro, 104);
    assert_eq!(fixture.h.state.meter.snapshot().total.calls, 4);
    assert_eq!(embedding::cache_count(&owned).await?, 1);
    let restarted = fixture.restart(&owned, &embedding).await?;
    let before = owned.rows().await?;
    let audit = owned.case.audit_stats().await;
    let replay = by_key(&restarted, &fixture.identity.key, "POST", first_id, Some(json!({}))).await;
    assert_eq!(replay.status, StatusCode::OK);
    assert_eq!(restarted.state.meter.snapshot().total.cost_micro, 104);
    assert_eq!(restarted.state.meter.snapshot().total.calls, 4);
    assert_eq!(owned.rows().await?, before);
    assert_eq!(owned.case.audit_stats().await, audit);
    assert_eq!((chat.calls(), embedding.calls()), (1, 2));
    owned.chain().await?;
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned gateway SQL and default-off test-loopback-transport"]
async fn cache_usage_both_ledgers_checkpoint_and_failure_audit_are_one_recoverable_transaction() -> DomainResult<()> {
    let owned = Owned::open("gw-semantic-tx").await?;
    let chat = Loopback::start().await;
    let embedding = Embedding::start().await?;
    let fixture = Fixture::new(owned.case.h.clone(), &chat, &embedding).await?;
    let concurrency = quota(&fixture.h, "tenant", "concurrency", "total", 2).await;
    let fault = AuditFault::install(&owned, "gateway-attempt", "execute").await?;
    let id = with_fault(fault, async {
        let response = fixture.call("hello paid rollback").await?;
        assert_eq!(response.status, StatusCode::PRECONDITION_FAILED);
        let id = embedding::attempt(&response)?;
        assert_eq!(id, owned.attempt().await?);
        assert_eq!((chat.calls(), embedding.calls()), (1, 1));
        assert_eq!(embedding::cache_count(&owned).await?, 0);
        assert!(agf_api::gateway_quota::usage(&fixture.h.state, fixture.h.tenant).await?.is_empty());
        assert_eq!(fixture.h.state.meter.snapshot().total.calls, 0);
        assert_eq!(used(&fixture.h, &concurrency).await, 1);
        assert!(
            fixture
                .h
                .state
                .configurations
                .list::<Value>(fixture.h.tenant, "gateway-meter-checkpoint-v1")
                .await?
                .is_empty()
        );
        assert_eq!(terminal_count(&fixture.h, id).await?, 0);
        let snapshot = owned.rows().await?;
        let audits = owned.case.audit_stats().await;
        let read = by_key(&fixture.h, &fixture.identity.key, "GET", id, None).await;
        assert_eq!(read.status, StatusCode::OK);
        assert_eq!(read.json()["state"], "pending-audit");
        assert_eq!(read.json()["components"][0]["costMicro"], 2);
        assert_eq!(owned.rows().await?, snapshot);
        assert_eq!(owned.case.audit_stats().await, audits);
        Ok(id)
    })
    .await?;
    let restarted = fixture.restart(&owned, &embedding).await?;
    let (left, right) = tokio::join!(
        by_key(&fixture.h, &fixture.identity.key, "POST", id, Some(json!({}))),
        by_key(&restarted, &fixture.identity.key, "POST", id, Some(json!({})))
    );
    assert_eq!(left.status, StatusCode::OK);
    assert_eq!(right.status, StatusCode::OK);
    assert_eq!(left.json(), right.json());
    usage(&restarted, 100, 2).await?;
    assert_eq!(settled_cost(&restarted).await?, 102);
    assert_eq!(used(&restarted, &concurrency).await, 0);
    assert_eq!(embedding::cache_count(&owned).await?, 1);
    assert_eq!(terminal_count(&restarted, id).await?, 1);
    for h in [&fixture.h, &restarted] {
        assert_eq!(h.state.meter.snapshot().total.cost_micro, 102);
    }
    assert_eq!((chat.calls(), embedding.calls()), (1, 1));
    owned.chain().await?;
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned gateway SQL and default-off test-loopback-transport"]
async fn paid_embedding_then_original_key_revocation_never_dispatches_chat_and_preserves_failure_evidence()
-> DomainResult<()> {
    let owned = Owned::open("gw-semantic-revoke").await?;
    let chat = Loopback::start().await;
    let embedding = Embedding::start().await?;
    let fixture = Fixture::new(owned.case.h.clone(), &chat, &embedding).await?;
    embedding.block();
    let mut pending = RequestTask::start(&fixture.h, &fixture.identity, "hello paid revoke");
    embedding.arrived().await?;
    let revoked = fixture
        .h
        .request("DELETE", &format!("/api/v1/settings/api-keys/{}", fixture.key_id), Some(&fixture.h.admin), None)
        .await;
    assert_eq!(revoked.status, StatusCode::OK);
    embedding.release();
    let response = pending.finish().await?;
    assert_eq!(response.status, StatusCode::PRECONDITION_FAILED);
    let id = embedding::attempt(&response)?;
    assert_eq!((chat.calls(), embedding.calls()), (0, 1));
    assert_eq!(terminal_count(&fixture.h, id).await?, 0);
    assert_eq!(embedding::cache_count(&owned).await?, 0);
    // Exact-owned fault restoration creates no new execution permit; recovery remains publication-only.
    owned.ownership.verify(&owned.case.pool).await?;
    let restored = sqlx::query("UPDATE api_keys SET revoked=false,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND revoked AND deleted_at IS NULL")
        .bind(fixture.h.tenant.as_uuid()).bind(fixture.key_id.as_uuid()).execute(&owned.case.pool).await.map_err(|error|sql(&error))?;
    assert_eq!(restored.rows_affected(), 1);
    let restarted = fixture.restart(&owned, &embedding).await?;
    let read = by_key(&restarted, &fixture.identity.key, "GET", id, None).await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.json()["outcomeEvidence"], "not-sent");
    assert_eq!(read.json()["components"][0]["evidence"], "sent-usage-known");
    let recover = by_key(&restarted, &fixture.identity.key, "POST", id, Some(json!({}))).await;
    assert_eq!(recover.status, StatusCode::OK);
    assert_eq!(settled_cost(&restarted).await?, 2);
    let rejection: Value =
        restarted.state.configurations.get(restarted.tenant, REJECTION, id).await?.ok_or_else(invalid)?;
    assert_eq!(rejection["rejection"]["reason"], "authority-changed");
    let chain = restarted.state.store.audit_chain_durable(restarted.tenant, 0, i64::MAX).await?;
    let audit = chain.iter().find(|row| json!(row.id) == rejection["audit_id"]).ok_or_else(invalid)?;
    assert_eq!(json!(audit.outcome), "failure");
    assert_eq!((chat.calls(), embedding.calls()), (0, 1));
    owned.chain().await?;
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned gateway SQL and default-off test-loopback-transport"]
async fn known_embedding_usage_over_reservation_is_charged_and_forbids_any_next_chat_post() -> DomainResult<()> {
    let owned = Owned::open("gw-semantic-overage").await?;
    let chat = Loopback::start().await;
    let embedding = Embedding::start().await?;
    embedding.tokens(65);
    let fixture = Fixture::new(owned.case.h.clone(), &chat, &embedding).await?;
    let response = fixture.call("hello bounded overage").await?;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    let id = embedding::attempt(&response)?;
    assert_eq!((chat.calls(), embedding.calls()), (0, 1));
    assert_eq!(settled_cost(&fixture.h).await?, 65);
    let rows = agf_api::gateway_quota::usage(&fixture.h.state, fixture.h.tenant).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].prompt_tokens, 65);
    assert_eq!(rows[0].cost_micro, 65);
    assert_eq!(fixture.h.state.meter.snapshot().total.cost_micro, 65);
    assert_eq!(embedding::cache_count(&owned).await?, 0);
    let rejection: Value =
        fixture.h.state.configurations.get(fixture.h.tenant, REJECTION, id).await?.ok_or_else(invalid)?;
    assert_eq!(rejection["rejection"]["reason"], "quota");
    assert_eq!(terminal_count(&fixture.h, id).await?, 1);
    let old = owned.rows().await?;
    let audit = owned.case.audit_stats().await;
    assert_eq!(by_key(&fixture.h, &fixture.identity.key, "POST", id, Some(json!({}))).await.status, StatusCode::OK);
    assert_eq!(owned.rows().await?, old);
    assert_eq!(owned.case.audit_stats().await, audit);
    assert_eq!((chat.calls(), embedding.calls()), (0, 1));
    owned.chain().await?;
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned gateway SQL and default-off test-loopback-transport"]
async fn cancelling_after_paid_embedding_keeps_its_usage_and_never_starts_a_later_chat() -> DomainResult<()> {
    let owned = Owned::open("gw-semantic-cancel").await?;
    let chat = Loopback::start().await;
    let embedding = Embedding::start().await?;
    let fixture = Fixture::new(owned.case.h.clone(), &chat, &embedding).await?;
    // The first chat has genuinely arrived after the paid embedding; cancellation
    // discards that read future and prohibits any new component or retry.
    chat.block();
    let task = RequestTask::start(&fixture.h, &fixture.identity, "hello paid cancellation");
    chat.arrived().await;
    assert_eq!((chat.calls(), embedding.calls()), (1, 1));
    task.cancel().await?;
    chat.release();
    let id = owned.attempt().await?;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while terminal_count(&fixture.h, id).await? != 1 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        Ok::<(), agf_core::error::DomainError>(())
    })
    .await
    .map_err(|_| invalid())??;
    let rows = agf_api::gateway_quota::usage(&fixture.h.state, fixture.h.tenant).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].model, "owned-settlement-embedding");
    assert_eq!(rows[0].cost_micro, 2);
    let read = by_key(&fixture.h, &fixture.identity.key, "GET", id, None).await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.json()["outcomeEvidence"], "sent-usage-unknown");
    assert_eq!(read.json()["components"][0]["costMicro"], 2);
    assert_eq!(embedding::cache_count(&owned).await?, 0);
    assert!(settled_cost(&fixture.h).await? > 2, "Unknown dispatched chat must retain its own estimate");
    let before = owned.rows().await?;
    let audits = owned.case.audit_stats().await;
    assert_eq!(by_key(&fixture.h, &fixture.identity.key, "POST", id, Some(json!({}))).await.status, StatusCode::OK);
    assert_eq!(owned.rows().await?, before);
    assert_eq!(owned.case.audit_stats().await, audits);
    assert_eq!((chat.calls(), embedding.calls()), (1, 1));
    owned.chain().await?;
    owned.case.pool.close().await;
    Ok(())
}

struct RequestTask(Option<tokio::task::JoinHandle<DomainResult<Resp>>>);
impl RequestTask {
    fn start(h: &Harness, identity: &crate::agentteams_quota_scope_support::Identity, text: &str) -> Self {
        let h = h.clone();
        let identity = identity.clone();
        let text = text.to_string();
        Self(Some(tokio::spawn(async move { embedding::call(&h, &identity, &text).await })))
    }
    async fn cancel(mut self) -> DomainResult<()> {
        let task = self.0.take().ok_or_else(invalid)?;
        task.abort();
        match task.await {
            Err(error) if error.is_cancelled() => Ok(()),
            _ => Err(invalid()),
        }
    }
    async fn finish(&mut self) -> DomainResult<Resp> {
        let task = self.0.as_mut().ok_or_else(invalid)?;
        let response = tokio::time::timeout(std::time::Duration::from_secs(20), task)
            .await
            .map_err(|_| invalid())?
            .map_err(|_| invalid())??;
        self.0.take();
        Ok(response)
    }
}
impl Drop for RequestTask {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}
