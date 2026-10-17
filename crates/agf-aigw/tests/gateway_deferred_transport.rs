//! Real literal127 dispatch, parser, cancellation and original deadline; no external network or mock adapter.
mod gateway_deferred_transport_support;
use agf_aigw::{
    gateway::{CallContext, DeferredCall, DeferredComponentAnchor, DeferredEvidence, SettlementGuard},
    wire::ChatRequest,
};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use futures::StreamExt;
use gateway_deferred_transport_support::*;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
struct Guard(AtomicBool);
#[async_trait::async_trait]
impl SettlementGuard for Guard {
    async fn validate(&self) -> DomainResult<()> {
        if self.0.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(DomainError::Forbidden("Owned current authority revoked".into()))
        }
    }
}
fn request(stream: bool) -> DomainResult<ChatRequest> {
    serde_json::from_value(serde_json::json!({"model":MODEL,"stream":stream,"temperature":1,"max_tokens":64,"messages":[{"role":"user","content":"owned-message"}]})).map_err(|_|invalid())
}
fn call(ids: &[Id], window: Duration, guard: Arc<Guard>) -> DomainResult<Arc<DeferredCall>> {
    let anchors = ids.iter().map(|id| DeferredComponentAnchor { usage_id: Id::new(), endpoint_id: *id }).collect();
    Ok(Arc::new(DeferredCall::new_chain(anchors, tokio::time::Instant::now() + window, guard)?))
}

#[tokio::test]
async fn actual_unknown_http_fallback_sends_each_candidate_once_and_meter_stays_deferred() -> DomainResult<()> {
    let tenant = TenantId::new();
    let left = Wire::start(Reply::Failed).await?;
    let right = Wire::start(Reply::Known).await?;
    let a = left.endpoint(tenant, 0);
    let b = right.endpoint(tenant, 1);
    let ids = [a.id, b.id];
    let gateway = gateway(vec![a, b])?;
    let call = call(&ids, Duration::from_secs(3), Arc::new(Guard(AtomicBool::new(true))))?;
    let response = gateway.chat_deferred(CallContext::new(tenant), request(false)?, &call).await?;
    let rows = call.component_outcomes();
    assert!(matches!(rows[0].evidence, DeferredEvidence::SentUsageUnknown));
    assert!(matches!(rows[1].evidence, DeferredEvidence::SentUsageKnown));
    assert_eq!(response.usage_record.id, rows[1].anchor.usage_id);
    assert_eq!(response.usage_record.cost_micro, 100);
    assert_eq!(gateway.meter().snapshot().total.cost_micro, 0);
    assert!(gateway.chat_deferred(CallContext::new(tenant), request(false)?, &call).await.is_err());
    assert_eq!((left.calls(), right.calls()), (1, 1));
    Ok(())
}

#[tokio::test]
async fn dropping_after_actually_parsed_partial_keeps_lower_bound_and_never_starts_fallback() -> DomainResult<()> {
    let tenant = TenantId::new();
    let left = Wire::start(Reply::HeldPartial).await?;
    let right = Wire::start(Reply::Known).await?;
    let a = left.endpoint(tenant, 0);
    let b = right.endpoint(tenant, 1);
    let gateway = gateway(vec![a.clone(), b.clone()])?;
    let call = call(&[a.id, b.id], Duration::from_secs(3), Arc::new(Guard(AtomicBool::new(true))))?;
    let (_, mut chunks) = gateway.chat_stream_deferred(CallContext::new(tenant), request(true)?, call.clone()).await?;
    tokio::time::timeout(Duration::from_secs(2), chunks.next()).await.map_err(|_| invalid())?.ok_or_else(invalid)??;
    assert!(matches!(call.component_outcomes()[0].evidence, DeferredEvidence::SentUsagePartial));
    drop(chunks);
    left.release();
    let rows = call.component_outcomes();
    assert_eq!(
        rows[0].usage.as_ref().map(|row| (row.prompt_tokens, row.completion_tokens, row.cost_micro)),
        Some((40, 3, 43))
    );
    assert!(matches!(rows[1].evidence, DeferredEvidence::NotSent));
    assert!(gateway.chat_stream_deferred(CallContext::new(tenant), request(true)?, call).await.is_err());
    assert_eq!((left.calls(), right.calls()), (1, 0));
    assert_eq!(gateway.meter().snapshot().total.cost_micro, 0);
    Ok(())
}

#[tokio::test]
async fn fresh_guard_revocation_after_partial_stops_next_poll_without_erasing_fee() -> DomainResult<()> {
    let tenant = TenantId::new();
    let wire = Wire::start(Reply::HeldPartial).await?;
    let endpoint = wire.endpoint(tenant, 0);
    let id = endpoint.id;
    let gateway = gateway(vec![endpoint])?;
    let guard = Arc::new(Guard(AtomicBool::new(true)));
    let call = call(&[id], Duration::from_secs(3), guard.clone())?;
    let (_, mut chunks) = gateway.chat_stream_deferred(CallContext::new(tenant), request(true)?, call.clone()).await?;
    chunks.next().await.ok_or_else(invalid)??;
    guard.0.store(false, Ordering::SeqCst);
    assert!(matches!(chunks.next().await, Some(Err(DomainError::Forbidden(_)))));
    assert_eq!(call.component_outcomes()[0].usage.as_ref().map(|row| row.cost_micro), Some(43));
    assert_eq!(wire.calls(), 1);
    Ok(())
}

#[tokio::test]
async fn one_original_deadline_covers_connection_and_all_stream_polls_without_renewal() -> DomainResult<()> {
    let tenant = TenantId::new();
    let wire = Wire::start(Reply::HeldPartial).await?;
    let endpoint = wire.endpoint(tenant, 0);
    let id = endpoint.id;
    let gateway = gateway(vec![endpoint])?;
    let begin = tokio::time::Instant::now();
    let call = call(&[id], Duration::from_millis(600), Arc::new(Guard(AtomicBool::new(true))))?;
    let (_, mut chunks) = gateway.chat_stream_deferred(CallContext::new(tenant), request(true)?, call.clone()).await?;
    chunks.next().await.ok_or_else(invalid)??;
    assert!(matches!(chunks.next().await, Some(Err(DomainError::Timeout(_)))));
    assert!(begin.elapsed() < Duration::from_millis(1100), "Original deadline was renewed");
    assert!(matches!(call.component_outcomes()[0].evidence, DeferredEvidence::SentUsagePartial));
    assert_eq!(wire.calls(), 1);
    Ok(())
}
