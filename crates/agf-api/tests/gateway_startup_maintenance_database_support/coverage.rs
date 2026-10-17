//! Intentional coverage cases only; copied helpers register no original C tests.
use super::*;
use crate::agentteams_quota_scope_support::{Loopback, accepted, call, configure, live};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "exact-owned SQL; a legitimate current checkpoint plus an explicit legacy Usage row"]
async fn legacy_usage_outside_checkpoint_is_incomplete_without_rewriting_history_or_charging_again() -> DomainResult<()>
{
    let _serial = crate::gateway_startup_maintenance_database_support::serial().await;
    let owned = Owned::open("gw-start-legacy").await?;
    let h = live(owned.case.h.clone());
    let provider = Loopback::start().await;
    let identities = configure(&h, &provider).await;
    let response = call(&h, &identities[0], "owned-startup-legacy").await;
    accepted(&response);
    let id = Id::parse(&response.header("x-agf-attempt-id"))?;
    let mut legacy = agf_api::gateway_quota::usage(&h.state, h.tenant).await?.into_iter().next().ok_or_else(invalid)?;
    legacy.id = Id::new();
    legacy.cost_micro = 17;
    legacy.model = "owned-pre-atomic-legacy-usage".into();
    // Only test-owned data, not a fabricated settled Fact or business execution.
    owned.ownership.verify(&owned.case.pool).await?;
    h.state.configurations.put(h.tenant, "model-usage", legacy.id, &legacy).await?;
    let result = AssertUnwindSafe(async {
        let rows = owned.rows().await?;
        let audit = owned.case.audit_stats().await;
        let fresh = live(owned.case.second_instance().await);
        let worker = agf_api::start_gateway_maintenance(fresh.state.clone()).await;
        let snapshot = fresh.state.meter.snapshot();
        assert!(snapshot.committed_projection_incomplete);
        assert_eq!((snapshot.total.calls, snapshot.total.cost_micro), (1, 100));
        let usage = agf_api::gateway_quota::usage(&fresh.state, h.tenant).await?;
        assert_eq!(usage.len(), 2);
        assert_eq!(usage.iter().map(|row| row.cost_micro).sum::<u64>(), 117);
        assert_eq!(by_key(&fresh, &identities[0].key, "GET", id, None).await.status, StatusCode::OK);
        worker.shutdown().await;
        assert_eq!(provider.calls(), 1);
        assert_eq!(owned.rows().await?, rows);
        assert_eq!(owned.case.audit_stats().await, audit);
        Ok::<(), DomainError>(())
    })
    .catch_unwind()
    .await;
    owned.ownership.verify(&owned.case.pool).await?;
    h.state.configurations.delete(h.tenant, "model-usage", legacy.id).await?;
    owned.chain().await?;
    owned.case.pool.close().await;
    match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[cfg(feature = "test-loopback-transport")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "exact-owned SQL; actual priced embedding plus chat, two component UsageRows"]
async fn complete_paid_embedding_and_chat_checkpoint_counts_components_and_startup_get_is_pure() -> DomainResult<()> {
    let _serial = crate::gateway_startup_maintenance_database_support::serial().await;
    let owned = Owned::open("gw-start-components").await?;
    let chat = Loopback::start().await;
    let embedding = super::embedding::Embedding::start().await?;
    let fixture = super::embedding::Fixture::new(owned.case.h.clone(), &chat, &embedding).await?;
    let first = fixture.call("owned fresh component coverage").await?;
    assert_eq!(first.status, StatusCode::OK);
    let id = super::embedding::attempt(&first)?;
    let usage = agf_api::gateway_quota::usage(&fixture.h.state, fixture.h.tenant).await?;
    assert_eq!(usage.len(), 2);
    assert_eq!(usage.iter().filter(|row| row.completion_tokens == 0).count(), 1);
    assert_eq!(usage.iter().map(|row| row.cost_micro).sum::<u64>(), 102);
    let rows = owned.rows().await?;
    let audit = owned.case.audit_stats().await;
    let fresh = fixture.restart(&owned, &embedding).await?;
    let worker = agf_api::start_gateway_maintenance(fresh.state.clone()).await;
    let snapshot = fresh.state.meter.snapshot();
    assert!(!snapshot.committed_projection_incomplete);
    assert_eq!((snapshot.total.calls, snapshot.total.cost_micro), (2, 102));
    assert_eq!(by_key(&fresh, &fixture.identity.key, "GET", id, None).await.status, StatusCode::OK);
    worker.shutdown().await;
    assert_eq!((chat.calls(), embedding.calls()), (1, 1));
    assert_eq!(owned.rows().await?, rows);
    assert_eq!(owned.case.audit_stats().await, audit);
    owned.chain().await?;
    owned.case.pool.close().await;
    Ok(())
}
