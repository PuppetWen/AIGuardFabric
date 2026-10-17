//! Native receivers keep committed events in SQL while JetStream is unavailable.
use agf_core::ids::TenantId;
use agf_ingest::bus::{EventOutbox, JetStreamEventBus};
use std::{sync::Arc, time::Duration};

pub(crate) async fn run_loop(store: Arc<agf_storage::Store>, tenant: TenantId) {
    let outbox = EventOutbox::new(store, tenant);
    let url = super::env_or("AGF_NATS_URL", "nats://127.0.0.1:4222");
    let stream = super::env_or("AGF_NATS_STREAM", "AGF_EVENTS");
    let mut bus = None;
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut prune_at = tokio::time::Instant::now();
    loop {
        interval.tick().await;
        if bus.is_none() {
            match JetStreamEventBus::connect(&url, &stream, "agf.events").await {
                Ok(connected) => bus = Some(connected),
                Err(error) => {
                    tracing::warn!(%error, "Event delivery unavailable; committed SQL queue retained");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            }
        }
        if let Some(connected) = &bus {
            match outbox.drain_once(connected).await {
                Ok(report) if report.failed > 0 => {
                    tracing::warn!(failed = report.failed, "Event delivery scheduled for retry");
                    bus = None;
                }
                Ok(report) => {
                    if report.delivered > 0 {
                        interval.reset_immediately();
                    }
                }
                Err(error) => tracing::warn!(%error, "Event delivery queue could not be processed"),
            }
        }
        if tokio::time::Instant::now() >= prune_at {
            if let Err(error) = outbox.prune().await {
                tracing::warn!(%error, "Event receipt cleanup failed");
            }
            prune_at = tokio::time::Instant::now() + Duration::from_hours(1);
        }
    }
}
