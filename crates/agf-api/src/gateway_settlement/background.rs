//! One bounded service-owned reconciliation loop; never a provider, caller, or execution grant.
use super::{background_tenants, maintenance, meter_projection};
use crate::AppState;
use agf_core::{error::DomainResult, ids::TenantId};
use std::time::Duration;
use tokio::{sync::watch, task::JoinHandle, time::Instant};

const STARTUP_PAGES: usize = 16;
const TENANT_ATTEMPTS: usize = 4;
const TICK_ATTEMPTS: usize = 32;
const CYCLE_BUDGET: Duration = Duration::from_secs(10);
const TENANT_BUDGET: Duration = Duration::from_secs(2);

/// An owned service task. Dropping it cancels SQL waits rather than orphaning a background loop.
#[derive(Debug)]
pub struct GatewayMaintenance {
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl GatewayMaintenance {
    /// Stop without a new provider call; cancelling a local SQL future rolls its transaction back.
    pub async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        if let Some(mut task) = self.task.take()
            && tokio::time::timeout(TENANT_BUDGET, &mut task).await.is_err()
        {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for GatewayMaintenance {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

/// Hydrate before serving HTTP, then own exactly one maintenance task for this server instance.
/// Absence requires no contrary usage/tombstone evidence. Errors or bounds remain explicit.
pub async fn start_gateway_maintenance(state: AppState) -> GatewayMaintenance {
    let (stop, receiver) = watch::channel(false);
    if !state.store.has_database() {
        return GatewayMaintenance { stop, task: None };
    }
    if !matches!(tokio::time::timeout(CYCLE_BUDGET, hydrate_startup(&state)).await, Ok(Ok(()))) {
        incomplete(&state);
    }
    let task = tokio::spawn(run(state, receiver));
    GatewayMaintenance { stop, task: Some(task) }
}

async fn hydrate_startup(state: &AppState) -> DomainResult<()> {
    let mut cursor = None;
    for _ in 0..STARTUP_PAGES {
        let page = background_tenants::page(state, cursor).await?;
        for tenant in page.tenants {
            // The existing revision checks prevent double counting or accepting an older replica.
            meter_projection::hydrate(state, tenant).await?;
            cursor = Some(tenant);
        }
        if !page.more {
            return Ok(());
        }
    }
    Err(super::store::missing()) // At most 512 tenants; never describe truncated totals as complete.
}

fn incomplete(state: &AppState) {
    state.meter.mark_committed_projection_incomplete();
    tracing::warn!("Gateway committed projection or conservative maintenance is incomplete");
}

#[derive(Default)]
struct ScanCursor {
    tenant: Option<TenantId>,
    round: u16,
}

async fn run(state: AppState, mut stop: watch::Receiver<bool>) {
    let mut cursor = ScanCursor::default();
    let mut ticker = tokio::time::interval(Duration::from_secs(15));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        if *stop.borrow() {
            return;
        }
        tokio::select! {
            _ = stop.changed() => return,
            _ = ticker.tick() => {}
        }
        tokio::select! {
            _ = stop.changed() => return,
            result = tick(&state, &mut cursor) => {
                if result.is_err() { incomplete(&state); }
            }
        }
    }
}

async fn tick(state: &AppState, cursor: &mut ScanCursor) -> DomainResult<()> {
    let deadline = Instant::now() + CYCLE_BUDGET;
    tokio::time::timeout_at(deadline, tick_inner(state, cursor, deadline))
        .await
        .map_err(|_| agf_core::error::DomainError::Timeout("Local gateway maintenance budget expired".into()))?
}

async fn tick_inner(state: &AppState, cursor: &mut ScanCursor, deadline: Instant) -> DomainResult<()> {
    let page = background_tenants::page(state, cursor.tenant).await?;
    let mut attempts = 0;
    let mut completed_page = true;
    for tenant in page.tenants {
        if attempts >= TICK_ATTEMPTS {
            completed_page = false;
            break; // Preserve the last actual tenant so the next tick starts with the untouched tenant.
        }
        if Instant::now() >= deadline {
            return Err(super::store::missing());
        }
        // Advance after choosing actual work, including failed tenants, to avoid starvation.
        cursor.tenant = Some(tenant);
        let tenant_deadline = deadline.min(Instant::now() + TENANT_BUDGET);
        let result = tokio::time::timeout_at(tenant_deadline, async {
            if meter_projection::hydrate(state, tenant).await.is_err() {
                incomplete(state);
            }
            if attempts >= TICK_ATTEMPTS {
                return Ok(());
            }
            let ids = maintenance::due_rotated(
                state,
                tenant,
                TENANT_ATTEMPTS.min(TICK_ATTEMPTS - attempts),
                usize::from(cursor.round) * TENANT_ATTEMPTS,
            )
            .await?;
            for id in ids {
                attempts += 1;
                // Do not call publish_known or obtain current model permission on behalf of the old actor.
                if maintenance::expire(state, tenant, id).await.is_err() {
                    incomplete(state);
                }
            }
            Ok::<(), agf_core::error::DomainError>(())
        })
        .await;
        if !matches!(result, Ok(Ok(()))) {
            incomplete(state);
        }
    }
    if completed_page && !page.more {
        cursor.tenant = None;
        cursor.round = cursor.round.wrapping_add(1);
    }
    Ok(())
}
