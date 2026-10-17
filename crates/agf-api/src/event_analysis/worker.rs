//! Broker delivery plus a SQL recovery sweep for events committed while NATS was disabled.
use super::{AppState, database, process};
use agf_core::{
    error::{DomainError, DomainResult},
    event::Event,
    ids::TenantId,
};
use agf_ingest::bus::JetStreamEventBus;
use futures::StreamExt;
use std::time::Duration;

pub async fn run_loop(state: AppState) {
    if database(&state).is_err() {
        return;
    }
    if state.config.nats.enabled {
        tokio::select! {
            () = sweep_loop(&state) => {},
            () = broker_loop(&state, "agf.events") => {},
        }
    } else {
        sweep_loop(&state).await;
    }
}

/// Recover one bounded batch and its notification jobs, including broker-disabled deployments.
pub async fn recover_pending(state: &AppState, tenant: TenantId) -> DomainResult<(usize, usize)> {
    if !crate::tenant_directory::get(state, tenant).await?.enabled {
        return Err(DomainError::Forbidden("Event tenant is disabled".into()));
    }
    let processed = sweep(state, tenant).await?;
    let notified = super::notifications::drain(state, tenant).await?;
    Ok((processed, notified))
}

async fn sweep_loop(state: &AppState) {
    loop {
        let mut more = false;
        match crate::tenant_directory::list(state).await {
            Ok(tenants) => {
                for tenant in tenants.into_iter().filter(|t| t.enabled) {
                    match sweep(state, tenant.id).await {
                        Ok(count) => more |= count == 16,
                        Err(error) => tracing::warn!(tenant=%tenant.id, %error, "Event analysis sweep will retry"),
                    }
                    match super::notifications::drain(state, tenant.id).await {
                        Ok(count) => more |= count == 32,
                        Err(error) => {
                            tracing::warn!(tenant=%tenant.id, %error, "Automatic alert notifications will retry");
                        }
                    }
                }
            }
            Err(error) => tracing::warn!(%error, "Event analysis tenant lookup will retry"),
        }
        if !more {
            tokio::time::sleep(Duration::from_secs(2)).await;
        } else {
            tokio::task::yield_now().await;
        }
    }
}

async fn sweep(state: &AppState, tenant: TenantId) -> DomainResult<usize> {
    let rows: Vec<(uuid::Uuid, serde_json::Value)> = database(state)?
        .with_tenant(tenant, |tx| {
            Box::pin(async move {
                sqlx::query_as(
                    "SELECT e.id,to_jsonb(e) FROM events e WHERE NOT EXISTS
            (SELECT 1 FROM event_analysis_receipts r WHERE r.event_id=e.id)
            AND NOT EXISTS (SELECT 1 FROM event_analysis_retries f WHERE f.event_id=e.id AND f.resolved_at IS NULL AND (f.available_at>now() OR f.paused OR f.attempts>=8))
            ORDER BY ingested_at,id LIMIT 16",
                )
                .fetch_all(&mut **tx)
                .await
                .map_err(|e| agf_storage::map_sqlx_err("analysis_pending", &e))
            })
        })
        .await?;
    let events: Result<Vec<Event>, _> = rows.iter().map(|(_, value)| serde_json::from_value(value.clone())).collect();
    if let Ok(events) = events
        && let Ok(Ok(Some(results))) =
            tokio::time::timeout(Duration::from_secs(30), super::try_empty_batch(state, &events, false)).await
    {
        return Ok(results.len());
    }
    let mut count = 0;
    for (id, value) in rows {
        let event: Event = match serde_json::from_value(value) {
            Ok(event) => event,
            Err(_) => {
                super::retry::record(
                    state,
                    tenant,
                    agf_core::ids::Id::from_uuid(id),
                    &DomainError::Parse("Invalid stored event".into()),
                )
                .await?;
                tracing::warn!(tenant=%tenant, event_id=%id, "Stored event schema needs repair; later events will continue");
                continue;
            }
        };
        // A failing event does not prevent the other records in this batch from being processed.
        if let Err(error) = bounded_process(state, &event).await {
            super::retry::record(state, tenant, event.id, &error).await?;
            tracing::warn!(tenant=%tenant,event_id=%event.id,%error,"Event analysis retained for retry");
        } else {
            count += 1;
        }
    }
    Ok(count)
}

async fn bounded_process(state: &AppState, event: &Event) -> DomainResult<super::AnalysisResult> {
    tokio::time::timeout(Duration::from_secs(30), process(state, event)).await.map_err(|_| {
        DomainError::DependencyUnavailable { dependency: "event-analysis".into(), cause: "Processing timed out".into() }
    })?
}

async fn broker_loop(state: &AppState, prefix: &str) {
    loop {
        if let Err(error) = Box::pin(broker_session(state, prefix)).await {
            tracing::warn!(%error, "Event consumer reconnecting; unacknowledged messages retained");
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn broker_session(state: &AppState, prefix: &str) -> DomainResult<()> {
    let bus = JetStreamEventBus::connect(&state.config.nats.url, &state.config.nats.stream, prefix).await?;
    let consumer = bus.consumer("agf-correlation-v1").await?;
    loop {
        let mut messages = consumer
            .batch()
            .max_messages(1)
            .expires(Duration::from_secs(5))
            .messages()
            .await
            .map_err(|_| broker_error())?;
        while let Some(message) = messages.next().await {
            let message = message.map_err(|_| broker_error())?;
            let mut ready = vec![message];
            // fetch() is no_wait: it returns only server-ready items, never waits to fill 31.
            // Exhaust it before processing so every delivered item is covered by Progress.
            let mut available = consumer
                .fetch()
                .max_messages(super::context::BATCH_LIMIT - 1)
                .expires(Duration::from_secs(5))
                .messages()
                .await
                .map_err(|_| broker_error())?;
            while let Some(message) = available.next().await {
                ready.push(message.map_err(|_| broker_error())?);
            }
            Box::pin(super::worker_batch::handle_ready(state, prefix, ready)).await?;
        }
    }
}

/// `Some` means analyzed; `None` means SQL owns retry. Only either successful outcome permits broker ACK.
pub async fn process_or_defer_delivery(
    state: &AppState,
    prefix: &str,
    subject: &str,
    payload: &[u8],
) -> DomainResult<Option<super::AnalysisResult>> {
    match process_delivery(state, prefix, subject, payload).await {
        Ok(result) => Ok(Some(result)),
        Err(error) => {
            if let Ok(event) = serde_json::from_slice::<Event>(payload)
                && subject == format!("{prefix}.{}.{}", event.tenant_id, event.severity.as_str())
                && super::retry::handoff(state, &event, &error).await?
            {
                tracing::warn!(tenant=%event.tenant_id,event_id=%event.id,"Event analysis recovery transferred to SQL");
                return Ok(None);
            }
            Err(error)
        }
    }
}

/// Validate routing before using the broker reference to load the canonical SQL record.
pub async fn process_delivery(
    state: &AppState,
    prefix: &str,
    subject: &str,
    payload: &[u8],
) -> DomainResult<super::AnalysisResult> {
    let event: Event = serde_json::from_slice(payload)?;
    if subject != format!("{prefix}.{}.{}", event.tenant_id, event.severity.as_str()) {
        return Err(DomainError::Forbidden("Event subject does not match its tenant and severity".into()));
    }
    tokio::time::timeout(Duration::from_secs(30), super::process_broker(state, &event)).await.map_err(|_| {
        DomainError::DependencyUnavailable { dependency: "event-analysis".into(), cause: "Processing timed out".into() }
    })?
}

fn broker_error() -> DomainError {
    DomainError::DependencyUnavailable { dependency: "event-consumer".into(), cause: "Broker operation failed".into() }
}
