//! Real SQL startup and conservative maintenance; test-owned loopback never contacts a cloud provider.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod agentteams_quota_scope_support;
mod common;
#[allow(clippy::unwrap_used)]
mod configuration_audit_support;
// Only no-test owner/fault helpers are copied; original C feature tests remain in their own target.
#[allow(dead_code)]
#[path = "gateway_startup_maintenance_database_support/owned.rs"]
mod gateway_settlement_database_support;
mod gateway_startup_maintenance_database_support;
use agentteams_quota_scope_support::*;
use agf_core::{error::DomainResult, ids::Id};
use common::*;
use gateway_settlement_database_support::*;
use gateway_startup_maintenance_database_support::*;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "exact-owned gateway settlement SQL database; actual priced loopback only"]
async fn startup_restores_committed_totals_before_any_chat_and_get_is_pure() -> DomainResult<()> {
    let _serial = serial().await;
    let owned = Owned::open("gw-start-paid").await?;
    let h = live(owned.case.h.clone());
    let provider = Loopback::start().await;
    let identities = configure(&h, &provider).await;
    let response = call(&h, &identities[0], "owned-startup-paid").await;
    accepted(&response);
    let id = response.header("x-agf-attempt-id").parse::<Id>().map_err(|_| invalid())?;
    let rows = owned.rows().await?;
    let audit = owned.case.audit_stats().await;
    let fresh = live(owned.case.second_instance().await);
    assert_eq!(fresh.state.meter.snapshot().total.calls, 0);
    let worker = agf_api::start_gateway_maintenance(fresh.state.clone()).await;
    assert_eq!(fresh.state.meter.snapshot().total.calls, 1);
    assert_eq!(fresh.state.meter.snapshot().total.cost_micro, 100);
    assert!(!fresh.state.meter.snapshot().committed_projection_incomplete);
    // A second service startup must absorb the same durable revision, not add it twice.
    let second = agf_api::start_gateway_maintenance(fresh.state.clone()).await;
    assert_eq!(fresh.state.meter.snapshot().total.calls, 1);
    let receipt = by_key(&fresh, &identities[0].key, "GET", id, None).await;
    assert_eq!(receipt.status, StatusCode::OK);
    assert_eq!(receipt.json()["mayExecute"], false);
    assert_eq!(by_key(&fresh, &identities[0].key, "GET", Id::new(), None).await.status, StatusCode::NOT_FOUND);
    worker.shutdown().await;
    second.shutdown().await;
    assert_eq!(provider.calls(), 1);
    assert_eq!(owned.rows().await?, rows);
    assert_eq!(owned.case.audit_stats().await, audit);
    owned.chain().await?;
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "exact-owned gateway settlement SQL database; authenticated AEAD fault only"]
async fn corrupt_checkpoint_never_initializes_or_repairs_a_false_authoritative_zero() -> DomainResult<()> {
    let _serial = serial().await;
    let owned = Owned::open("gw-start-crypto").await?;
    let h = live(owned.case.h.clone());
    let provider = Loopback::start().await;
    let identities = configure(&h, &provider).await;
    accepted(&call(&h, &identities[0], "owned-startup-crypto").await);
    Box::pin(with_corrupt_checkpoint(&owned, async {
        let rows = owned.rows().await?;
        let audit = owned.case.audit_stats().await;
        let fresh = owned.case.second_instance().await;
        let worker = agf_api::start_gateway_maintenance(fresh.state.clone()).await;
        assert!(fresh.state.meter.snapshot().committed_projection_incomplete);
        assert_eq!(fresh.state.meter.snapshot().total.calls, 0);
        worker.shutdown().await;
        assert_eq!(owned.rows().await?, rows);
        assert_eq!(owned.case.audit_stats().await, audit);
        assert_eq!(provider.calls(), 1);
        Ok(())
    }))
    .await?;
    owned.chain().await?;
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "exact-owned SQL lock; bounded 10-second startup and cancellable maintenance"]
async fn a_locked_checkpoint_does_not_block_startup_indefinitely_and_shutdown_cancels_sql_waits() -> DomainResult<()> {
    let _serial = serial().await;
    let owned = Owned::open("gw-start-stop").await?;
    let rows = owned.rows().await?;
    let audit = owned.case.audit_stats().await;
    let fresh = owned.case.second_instance().await;
    with_table_lock(&owned, async {
        let started = tokio::time::Instant::now();
        let worker = agf_api::start_gateway_maintenance(fresh.state.clone()).await;
        assert!(started.elapsed() < Duration::from_secs(13));
        assert!(fresh.state.meter.snapshot().committed_projection_incomplete);
        let stopping = tokio::time::Instant::now();
        worker.shutdown().await;
        assert!(stopping.elapsed() < Duration::from_secs(3));
        Ok(())
    })
    .await?;
    assert_eq!(owned.rows().await?, rows);
    assert_eq!(owned.case.audit_stats().await, audit);
    owned.chain().await?;
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "SLOW: original real 900-second reservation, two instances, retired tenant; no synthetic clock"]
async fn restarted_instances_expire_a_real_retired_tenant_reservation_once_without_settling_known_pending()
-> DomainResult<()> {
    let _serial = serial().await;
    let owned = Owned::open("gw-start-expire").await?;
    let h = live(owned.case.h.clone());
    let provider = Loopback::start().await;
    let identities = configure(&h, &provider).await;
    quota(&h, "tenant", "concurrency", "total", 2).await;
    let fault = AuditFault::install(&owned, "gateway-attempt", "execute").await?;
    let id = with_fault(fault, async {
        let response = call(&h, &identities[0], "owned-startup-expire").await;
        assert!(!response.status.is_success());
        assert_eq!(provider.calls(), 1);
        assert_eq!(concurrency(&ledger(&h, "runtime-quota-ledger").await?)?, 1);
        owned.attempt().await
    })
    .await?;
    let pending = h.state.configurations.get::<Value>(h.tenant, PENDING, id).await?.ok_or_else(invalid)?;
    let original = ledger(&h, "gateway-ledger").await?;
    let reservation = &original["reservations"][id.to_string()];
    let expires = reservation["expires"].as_i64().ok_or_else(invalid)?;
    let cost = reservation["cost"].as_u64().ok_or_else(invalid)?;
    let tokens = reservation["tokens"].as_u64().ok_or_else(invalid)?;
    Box::pin(with_retired_tenant(&owned, async {
        let a = owned.case.second_instance().await;
        let b = owned.case.second_instance().await;
        let wa = agf_api::start_gateway_maintenance(a.state.clone()).await;
        let wb = agf_api::start_gateway_maintenance(b.state.clone()).await;
        let wait = (expires - Timestamp::now().unix_secs() + 1).max(0);
        assert!(wait <= 901);
        tokio::time::sleep(Duration::from_secs(u64::try_from(wait).map_err(|_| invalid())?)).await;
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                if concurrency(&ledger(&h, "runtime-quota-ledger").await?)? == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Ok::<(), agf_core::error::DomainError>(())
        })
        .await
        .map_err(|_| invalid())??;
        wa.shutdown().await;
        wb.shutdown().await;
        assert_eq!(provider.calls(), 1);
        assert_eq!(expiry_count(&h, id).await?, 1);
        assert_eq!(terminal_count(&h, id).await?, 0);
        assert_eq!(ledger(&h, "gateway-ledger").await?["totals"], json!({"tokens":tokens,"cost":cost}));
        assert_eq!(h.state.configurations.get::<Value>(h.tenant, PENDING, id).await?, Some(pending.clone()));
        Ok(())
    }))
    .await?;
    let rows = owned.rows().await?;
    let audit = owned.case.audit_stats().await;
    let receipt = by_key(&h, &identities[0].key, "GET", id, None).await;
    assert_eq!(receipt.status, StatusCode::OK);
    assert_eq!(receipt.json()["state"], "conservatively-settled");
    assert_eq!(receipt.json()["mayExecute"], false);
    assert_eq!(owned.rows().await?, rows);
    assert_eq!(owned.case.audit_stats().await, audit);
    owned.chain().await?;
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "exact-owned SQL; actual committed paid usage with retired checkpoint"]
async fn lost_checkpoint_with_committed_usage_is_incomplete_and_pure_get_does_not_repair_it() -> DomainResult<()> {
    let _serial = serial().await;
    let owned = Owned::open("gw-start-missing").await?;
    let h = live(owned.case.h.clone());
    let provider = Loopback::start().await;
    let identities = configure(&h, &provider).await;
    let response = call(&h, &identities[0], "owned-startup-missing").await;
    accepted(&response);
    let id = response.header("x-agf-attempt-id").parse::<Id>().map_err(|_| invalid())?;
    Box::pin(with_deleted_checkpoint(&owned, async {
        let rows = owned.rows().await?;
        let audit = owned.case.audit_stats().await;
        let fresh = owned.case.second_instance().await;
        let worker = agf_api::start_gateway_maintenance(fresh.state.clone()).await;
        assert!(fresh.state.meter.snapshot().committed_projection_incomplete);
        assert_eq!(fresh.state.meter.snapshot().total.calls, 0);
        let receipt = by_key(&fresh, &identities[0].key, "GET", id, None).await;
        assert_eq!(receipt.status, StatusCode::OK);
        assert_eq!(receipt.json()["state"], "settled");
        worker.shutdown().await;
        assert_eq!(owned.rows().await?, rows);
        assert_eq!(owned.case.audit_stats().await, audit);
        assert_eq!(provider.calls(), 1);
        Ok(())
    }))
    .await?;
    owned.chain().await?;
    owned.case.pool.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "exact-owned SQL; real disabled and deleted tenant remains only a reconciliation identity"]
async fn retired_tenant_checkpoint_hydrates_without_reenabling_it_or_granting_execution() -> DomainResult<()> {
    let _serial = serial().await;
    let owned = Owned::open("gw-start-retired").await?;
    let h = live(owned.case.h.clone());
    let provider = Loopback::start().await;
    let identities = configure(&h, &provider).await;
    accepted(&call(&h, &identities[0], "owned-startup-retired").await);
    Box::pin(with_retired_tenant(&owned, async {
        let rows = owned.rows().await?;
        let audit = owned.case.audit_stats().await;
        let fresh = owned.case.second_instance().await;
        let worker = agf_api::start_gateway_maintenance(fresh.state.clone()).await;
        assert_eq!(fresh.state.meter.snapshot().total.calls, 1);
        assert_eq!(fresh.state.meter.snapshot().total.cost_micro, 100);
        assert!(!fresh.state.meter.snapshot().committed_projection_incomplete);
        worker.shutdown().await;
        let retired: bool =
            sqlx::query_scalar("SELECT NOT enabled AND deleted_at IS NOT NULL FROM tenants WHERE id=$1")
                .bind(h.tenant.as_uuid())
                .fetch_one(&owned.case.pool)
                .await
                .map_err(|error| agf_storage::map_sqlx_err("owned_gateway_retired_read", &error))?;
        assert!(retired);
        assert_eq!(provider.calls(), 1);
        assert_eq!(owned.rows().await?, rows);
        assert_eq!(owned.case.audit_stats().await, audit);
        Ok(())
    }))
    .await?;
    owned.chain().await?;
    owned.case.pool.close().await;
    Ok(())
}
