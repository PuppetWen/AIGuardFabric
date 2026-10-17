//! One ready pull, ordered effects, and progress only for unfinished deliveries.
use super::AppState;
use agf_core::{
    error::{DomainError, DomainResult},
    event::Event,
};
use async_nats::jetstream::{AckKind, Message};
use futures::future::try_join_all;
use std::{
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

struct Pending {
    message: Message,
    finished: AtomicBool,
}

fn broker_error() -> DomainError {
    DomainError::DependencyUnavailable { dependency: "event-consumer".into(), cause: "Broker operation failed".into() }
}

pub(super) async fn handle_ready(state: &AppState, prefix: &str, messages: Vec<Message>) -> DomainResult<()> {
    if messages.len() > super::context::BATCH_LIMIT {
        return Err(broker_error());
    }
    // Match the original consumer's metadata validation before any SQL effects.
    for message in &messages {
        message.info().map_err(|_| broker_error())?;
    }
    let pending: Vec<_> =
        messages.into_iter().map(|message| Pending { message, finished: AtomicBool::new(false) }).collect();
    // No task is spawned: cancellation drops work/transaction and sends no final acknowledgement.
    Box::pin(wait_with_progress(
        ordered(state, prefix, &pending),
        || async {
            tokio::time::timeout(
                Duration::from_secs(5),
                try_join_all(
                    pending
                        .iter()
                        .filter(|item| !item.finished.load(Ordering::Acquire))
                        .map(|item| item.message.ack_with(AckKind::Progress)),
                ),
            )
            .await
            .map_err(|_| broker_error())?
            .map_err(|_| broker_error())?;
            Ok(())
        },
        Duration::from_secs(10),
    ))
    .await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    #[tokio::test]
    async fn slow_ordered_work_is_renewed_until_durable_completion() {
        let renewals = AtomicUsize::new(0);
        let committed = AtomicBool::new(false);
        let result = wait_with_progress(
            async {
                let mut order = Vec::new();
                for id in 0..3 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    order.push(id);
                }
                committed.store(true, Ordering::Release);
                Ok(order)
            },
            || async {
                assert!(!committed.load(Ordering::Acquire));
                renewals.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
            Duration::from_millis(1),
        )
        .await
        .unwrap();
        assert_eq!(result, [0, 1, 2]);
        assert!(committed.load(Ordering::Acquire));
        assert!(renewals.load(Ordering::Relaxed) > 0);
    }

    #[tokio::test]
    async fn progress_failure_drops_unfinished_work_without_final_ack() {
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let final_ack = AtomicBool::new(false);
        let guard = Dropped(dropped.clone());
        let result: DomainResult<()> = wait_with_progress(
            async {
                let _guard = guard;
                std::future::pending::<()>().await;
                final_ack.store(true, Ordering::Release);
                Ok(())
            },
            || async { Err(broker_error()) },
            Duration::from_millis(1),
        )
        .await;
        assert!(result.is_err());
        assert!(dropped.load(Ordering::Acquire));
        assert!(!final_ack.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn cancellation_leaves_no_background_renewal_or_final_ack() {
        let renewals = AtomicUsize::new(0);
        let final_ack = AtomicBool::new(false);
        let outcome = tokio::time::timeout(
            Duration::from_millis(10),
            wait_with_progress(
                async {
                    std::future::pending::<()>().await;
                    final_ack.store(true, Ordering::Release);
                    Ok(())
                },
                || async {
                    renewals.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                },
                Duration::from_millis(1),
            ),
        )
        .await;
        assert!(outcome.is_err());
        let count = renewals.load(Ordering::Relaxed);
        assert!(count > 0);
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(renewals.load(Ordering::Relaxed), count);
        assert!(!final_ack.load(Ordering::Acquire));
    }
}

async fn ordered(state: &AppState, prefix: &str, pending: &[Pending]) -> DomainResult<()> {
    let references: Vec<Option<Event>> = pending
        .iter()
        .map(|item| {
            serde_json::from_slice::<Event>(&item.message.payload).ok().filter(|event| {
                item.message.subject.as_str() == format!("{prefix}.{}.{}", event.tenant_id, event.severity.as_str())
            })
        })
        .collect();
    let mut index = 0;
    while index < pending.len() {
        let mut end = index + 1;
        if let Some(first) = &references[index] {
            while end < pending.len()
                && references[end].as_ref().is_some_and(|event| event.tenant_id == first.tenant_id)
            {
                end += 1;
            }
        }
        if end - index > 1 {
            let events: Vec<_> = references[index..end].iter().flatten().cloned().collect();
            if let Ok(Ok(Some(_))) =
                tokio::time::timeout(Duration::from_secs(30), super::try_empty_batch(state, &events, true)).await
            {
                // All receipts and retry resolutions committed before any final ACK is even polled.
                try_join_all(pending[index..end].iter().map(|item| async move {
                    item.message.double_ack().await.map_err(|_| broker_error())?;
                    item.finished.store(true, Ordering::Release);
                    Ok::<_, DomainError>(())
                }))
                .await?;
                index = end;
                continue;
            }
        }
        // Poison routing/quarantine, durable retry handoff, and effectful analysis retain their old path.
        for item in &pending[index..end] {
            let message = &item.message;
            let sequence = message.info().map_err(|_| broker_error())?.stream_sequence;
            match super::broker_quarantine::handle_delivery(
                state,
                &state.config.nats.stream,
                sequence,
                prefix,
                &message.subject,
                &message.payload,
            )
            .await
            {
                Ok(()) => message.double_ack().await.map_err(|_| broker_error())?,
                Err(error) => {
                    tracing::warn!(%error, "Event analysis failed; broker redelivery requested");
                    message.ack_with(AckKind::Nak(Some(Duration::from_secs(30)))).await.map_err(|_| broker_error())?;
                }
            }
            item.finished.store(true, Ordering::Release);
        }
        index = end;
    }
    Ok(())
}

/// Scoped to this bounded pull; a failed renewal drops work without ACK/NAK of unfinished items.
async fn wait_with_progress<T, W, P, F>(work: W, mut progress: P, interval: Duration) -> DomainResult<T>
where
    W: Future<Output = DomainResult<T>>,
    P: FnMut() -> F,
    F: Future<Output = DomainResult<()>>,
{
    tokio::pin!(work);
    let mut timer = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    loop {
        tokio::select! {
            result = &mut work => return result,
            _ = timer.tick() => progress().await?,
        }
    }
}
