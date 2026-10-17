//! Caller cancellation stops transport; the owned safe result still stages and publishes locally.
use super::{
    execution::{CancelOnDrop, Run},
    records::*,
    stage, store,
};
use agf_aigw::wire::StreamChunk;
use agf_core::error::{DomainError, DomainResult};
use futures::{Stream, StreamExt};
use std::pin::Pin;
use tokio::sync::{mpsc, oneshot};

// This in-process proof has no public constructor or Deserialize implementation.
pub(crate) struct CommittedDelivery(());
pub(crate) enum Delivery {
    Chunk(StreamChunk),
    Committed(CommittedDelivery),
}
pub(crate) type AdmittedDeliveryStream = Pin<Box<dyn Stream<Item = DomainResult<Delivery>> + Send>>;

pub(crate) struct AdmittedStream {
    model: String,
    mocked: bool,
    receiver: mpsc::Receiver<DomainResult<Delivery>>,
    cancellation: CancelOnDrop,
}

impl AdmittedStream {
    pub(crate) fn into_parts(self) -> (String, bool, AdmittedDeliveryStream) {
        let model = self.model.clone();
        let mocked = self.mocked;
        let output = futures::stream::unfold(self, |mut owner| async move {
            let _ticket = &owner.cancellation;
            owner.receiver.recv().await.map(|chunk| (chunk, owner))
        });
        (model, mocked, Box::pin(output))
    }
}

pub(super) async fn start(input: Run) -> DomainResult<AdmittedStream> {
    let cancellation = CancelOnDrop(input.cancellation.clone());
    let (sender, receiver) = mpsc::channel(16);
    let (ready, started) = oneshot::channel();
    tokio::spawn(run(input, sender, ready));
    let (model, mocked) =
        started.await.map_err(|_| DomainError::Internal("Admitted stream startup ended".into()))??;
    Ok(AdmittedStream { model, mocked, receiver, cancellation })
}

async fn run(
    input: Run,
    sender: mpsc::Sender<DomainResult<Delivery>>,
    ready: oneshot::Sender<DomainResult<(String, bool)>>,
) {
    let connection = tokio::select! {
        biased;
        () = sender.closed() => { input.cancellation.cancel(); Err(DomainError::Timeout("Stream caller cancelled before connection".into())) },
        () = input.cancellation.cancelled() => Err(DomainError::Timeout("Stream caller cancelled before connection".into())),
        result = input.gateway.chat_stream_deferred(input.context.clone(), input.request.clone(), input.deferred.clone()) => result,
    };
    let mut failure = None;
    let mut tail = Vec::new();
    let mut tail_bytes = 0usize;
    match connection {
        Ok((metadata, mut chunks)) => {
            if ready.send(Ok((metadata.model.clone(), metadata.mocked))).is_err() {
                input.cancellation.cancel();
                failure = Some(Rejection { stage: Stage::Stream, reason: Reason::Cancelled, rule_ids: Vec::new() });
            } else {
                loop {
                    let item = tokio::select! {
                        biased;
                        () = sender.closed() => { input.cancellation.cancel(); break; },
                        () = input.cancellation.cancelled() => break,
                        result = chunks.next() => result,
                    };
                    let Some(item) = item else { break };
                    match item {
                        Ok(chunk) => {
                            if let Err(error) = input.guard.validate().await {
                                failure = Some(super::rejection::from_error(&error, aggregate(&input)));
                                break;
                            }
                            // Preserve order after the first terminal witness. Neither a finish
                            // marker nor its attached response body can imply committed success.
                            if !tail.is_empty() || terminal(&chunk) {
                                let size = serde_json::to_vec(&chunk).map_or(usize::MAX, |bytes| bytes.len());
                                tail_bytes = tail_bytes.saturating_add(size);
                                if tail_bytes > 4 * 1024 * 1024 {
                                    failure = Some(Rejection {
                                        stage: Stage::Stream,
                                        reason: Reason::Unavailable,
                                        rule_ids: Vec::new(),
                                    });
                                    break;
                                }
                                tail.push(chunk);
                                continue;
                            }
                            if let Err(error) = send(&input, &sender, chunk).await {
                                failure = Some(super::rejection::from_error(&error, aggregate(&input)));
                                break;
                            }
                        }
                        Err(error) => {
                            failure = Some(super::rejection::from_error(&error, aggregate(&input)));
                            break;
                        }
                    }
                }
            }
            drop(chunks); // No further provider polling or fallback after caller cancellation.
        }
        Err(error) => {
            failure = Some(super::rejection::from_error(&error, aggregate(&input)));
            let _ = ready.send(Err(error));
        }
    }
    if input.cancellation.check().is_err() {
        failure = Some(Rejection { stage: Stage::Stream, reason: Reason::Cancelled, rule_ids: Vec::new() });
    }
    let rules = input.deferred.blocked_rules();
    if !rules.is_empty() {
        let limit = rules.iter().any(|rule| rule == "gateway-output-limit");
        failure = Some(Rejection {
            stage: Stage::ResponseScreen,
            reason: if limit { Reason::OutputLimit } else { Reason::Denied },
            rule_ids: rules,
        });
    }
    let intentional_tail = tail.iter().any(|chunk| {
        chunk.finish_reason.is_some()
            || chunk.anthropic_event.as_ref().and_then(|value| value["type"].as_str()) == Some("message_stop")
    });
    if failure.is_none() && !intentional_tail {
        failure = Some(Rejection { stage: Stage::Stream, reason: Reason::Unavailable, rule_ids: Vec::new() });
    }
    let published = publish(&input, failure).await;
    // An intentional protocol end is withheld until settlement and its complete tail are confirmed.
    if !matches!(published, Ok(true)) || !intentional_tail || input.guard.validate().await.is_err() {
        delivery_failed(&sender).await;
        return;
    }
    for chunk in tail {
        if input.guard.validate().await.is_err() || send(&input, &sender, chunk).await.is_err() {
            // Accounting is already immutable. Delivery loss does not grant another dispatch.
            delivery_failed(&sender).await;
            return;
        }
    }
    // A committed intentional conclusion, complete tail and fresh authority mint this proof.
    if input.guard.validate().await.is_err()
        || send_delivery(&input, &sender, Delivery::Committed(CommittedDelivery(()))).await.is_err()
    {
        delivery_failed(&sender).await;
    }
}

async fn delivery_failed(sender: &mpsc::Sender<DomainResult<Delivery>>) {
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        sender.send(Err(DomainError::PreconditionFailed(
            "Original stream evidence remains local; read its attempt UUID".into(),
        ))),
    )
    .await;
}

fn terminal(chunk: &StreamChunk) -> bool {
    chunk.finish_reason.is_some()
        || chunk.usage.is_some()
        || chunk.anthropic_event.as_ref().and_then(|value| value["type"].as_str()) == Some("message_stop")
}

async fn send(input: &Run, sender: &mpsc::Sender<DomainResult<Delivery>>, chunk: StreamChunk) -> DomainResult<()> {
    send_delivery(input, sender, Delivery::Chunk(chunk)).await
}

async fn send_delivery(
    input: &Run,
    sender: &mpsc::Sender<DomainResult<Delivery>>,
    delivery: Delivery,
) -> DomainResult<()> {
    tokio::select! {
        biased;
        () = sender.closed() => { input.cancellation.cancel(); Err(DomainError::Timeout("Stream caller cancelled".into())) },
        () = input.cancellation.cancelled() => Err(DomainError::Timeout("Stream caller cancelled".into())),
        result = tokio::time::timeout_at(input.deferred.original_deadline(), sender.send(Ok(delivery))) => {
            match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(_)) => { input.cancellation.cancel(); Err(DomainError::Timeout("Stream caller cancelled".into())) },
                Err(_) => Err(DomainError::Timeout("Stream delivery exhausted original budget".into())),
            }
        },
    }
}

fn aggregate(input: &Run) -> Evidence {
    input
        .deferred
        .component_outcomes()
        .iter()
        .find_map(|row| match row.evidence {
            agf_aigw::gateway::DeferredEvidence::NotSent => None,
            agf_aigw::gateway::DeferredEvidence::LocalReply => Some(Evidence::LocalReply),
            agf_aigw::gateway::DeferredEvidence::SentUsageKnown => Some(Evidence::SentUsageKnown),
            agf_aigw::gateway::DeferredEvidence::SentUsagePartial => Some(Evidence::SentUsagePartial),
            agf_aigw::gateway::DeferredEvidence::SentUsageUnknown => Some(Evidence::SentUsageUnknown),
        })
        .unwrap_or(Evidence::NotSent)
}

async fn publish(input: &Run, mut rejection: Option<Rejection>) -> DomainResult<bool> {
    let chats = super::chat_components::snapshot(&input.deferred)?;
    let primary = chats.first().ok_or_else(store::missing)?;
    // The final stream verdict decides intentional delivery. Accounting uncertainty
    // from a previous failed candidate must retain a Failure audit, without suppressing
    // a later complete fallback's correctly committed protocol conclusion.
    let completed_delivery =
        rejection.as_ref().is_none_or(|row| row.stage == Stage::ResponseScreen && row.reason == Reason::Denied);
    if chats.iter().any(|row| matches!(row.evidence, Evidence::SentUsageUnknown | Evidence::SentUsagePartial))
        && rejection.is_none()
    {
        rejection = Some(Rejection { stage: Stage::Stream, reason: Reason::Provider, rule_ids: Vec::new() });
    }
    let pending = Pending {
        attempt: input.fact.attempt,
        origin: input.fact.origin.clone(),
        outcome: KnownOutcome {
            evidence: primary.evidence,
            usage: primary.usage.clone(),
            components: chats.iter().skip(1).cloned().collect(),
            semantic: None,
            rejection,
        },
    };
    // A safe complete/partial/unknown snapshot is handed to the existing AEAD stage before awaits.
    let local = stage::spawn_known(
        input.state.clone(),
        input.principal.clone(),
        input.lease.clone(),
        input.submitted_at,
        input.headers.clone(),
        input.fact.clone(),
        pending,
    );
    local.await.map_err(|_| DomainError::Internal("Owned stream publication ended".into()))??;
    Ok(completed_delivery)
}

// Ordinary tests control the owned channel only; no provider/production injection is exported.
#[cfg(test)]
pub(crate) fn controlled_for_test() -> (AdmittedStream, mpsc::Sender<DomainResult<Delivery>>) {
    let (sender, receiver) = mpsc::channel(16);
    let stream = AdmittedStream {
        model: "owned-delivery-test".into(),
        mocked: true,
        receiver,
        cancellation: CancelOnDrop(super::execution::Cancellation::default()),
    };
    (stream, sender)
}
#[cfg(test)]
pub(crate) fn committed_for_test() -> Delivery {
    Delivery::Committed(CommittedDelivery(()))
}
