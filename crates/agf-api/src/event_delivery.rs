//! Durable event publication for console ingestion and native receivers sharing the database.
use crate::state::AppState;
use agf_ingest::bus::{EventOutbox, JetStreamEventBus};
use std::time::Duration;

pub async fn run_loop(state: AppState) {
    if !state.config.nats.enabled {
        return;
    }
    let Some(store) = state.ingest_sink.database() else { return };
    let mut bus = None;
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut prune_at = tokio::time::Instant::now();
    loop {
        interval.tick().await;
        if bus.is_none() {
            match JetStreamEventBus::connect(&state.config.nats.url, &state.config.nats.stream, "agf.events").await {
                Ok(connected) => bus = Some(connected),
                Err(error) => {
                    tracing::warn!(%error, "Event broker unavailable; SQL delivery queue retained");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            }
        }
        let tenants = match crate::tenant_directory::list(&state).await {
            Ok(tenants) => tenants,
            Err(error) => {
                tracing::warn!(%error, "Event delivery tenant lookup failed");
                continue;
            }
        };
        let prune = tokio::time::Instant::now() >= prune_at;
        for tenant in tenants.into_iter().filter(|entry| entry.enabled) {
            let Some(connected) = &bus else { break };
            let outbox = EventOutbox::new(store.clone(), tenant.id);
            match outbox.drain_once(connected).await {
                Ok(report) if report.failed > 0 => {
                    tracing::warn!(tenant=%tenant.id, failed=report.failed, "Event publication will retry");
                    bus = None;
                }
                Ok(report) => {
                    if report.delivered > 0 {
                        interval.reset_immediately();
                    }
                }
                Err(error) => tracing::warn!(tenant=%tenant.id, %error, "Event queue processing failed"),
            }
            if prune {
                if let Err(error) = outbox.prune().await {
                    tracing::warn!(%error, "Event receipt cleanup failed");
                }
            }
        }
        if prune {
            prune_at = tokio::time::Instant::now() + Duration::from_hours(1);
        }
    }
}
