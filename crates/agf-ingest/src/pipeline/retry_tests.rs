//! Fault injection validates persistence before deduplication acknowledgement.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Default)]
struct ControlledSink {
    inner: InMemorySink,
    mode: AtomicU8,
    entered: tokio::sync::Notify,
}

#[async_trait]
impl Sink for ControlledSink {
    fn backend(&self) -> &'static str {
        "controlled-test"
    }
    async fn put_raw(&self, raw: &RawLog) -> DomainResult<()> {
        self.inner.put_raw(raw).await
    }
    async fn mark_raw(
        &self,
        tenant: TenantId,
        id: Id,
        parsed: bool,
        event: Option<Id>,
        error: Option<&str>,
    ) -> DomainResult<()> {
        self.inner.mark_raw(tenant, id, parsed, event, error).await
    }
    async fn put_event(&self, event: &Event) -> DomainResult<()> {
        self.inner.put_event(event).await
    }
    async fn put_events(&self, events: &[Event]) -> DomainResult<usize> {
        match self.mode.load(Ordering::SeqCst) {
            1 => return Err(DomainError::DependencyUnavailable { dependency: "test".into(), cause: "offline".into() }),
            2 => {
                self.entered.notify_one();
                std::future::pending::<()>().await;
            }
            _ => (),
        }
        self.inner.put_events(events).await
    }
    async fn get_event(&self, tenant: TenantId, id: Id) -> DomainResult<Option<Event>> {
        self.inner.get_event(tenant, id).await
    }
    async fn unparsed_raw(&self, tenant: TenantId, limit: i64) -> DomainResult<Vec<RawLog>> {
        self.inner.unparsed_raw(tenant, limit).await
    }
    async fn event_count(&self, tenant: TenantId) -> DomainResult<u64> {
        self.inner.event_count(tenant).await
    }
    async fn raw_count(&self, tenant: TenantId) -> DomainResult<u64> {
        self.inner.raw_count(tenant).await
    }
}

fn controlled(mode: u8) -> (Arc<IngestPipeline>, Arc<ControlledSink>, LogSource) {
    let sink = Arc::new(ControlledSink::default());
    sink.mode.store(mode, Ordering::SeqCst);
    let pipeline = Arc::new(IngestPipeline::in_memory(sink.clone()));
    (pipeline, sink, source(0, 65536))
}

#[tokio::test]
async fn failed_event_write_does_not_suppress_single_or_batch_retry() {
    for batch in [false, true] {
        let (pipeline, sink, source) = controlled(1);
        let items = vec![(SYSLOG.as_bytes().to_vec(), "fixture".into()); 2];
        let call = || async {
            if batch {
                pipeline.ingest_batch(&source, IngestProtocol::Syslog, &items).await
            } else {
                pipeline
                    .ingest_raw(&source, IngestProtocol::Syslog, SYSLOG.as_bytes(), "fixture")
                    .await
                    .map(|v| vec![v])
            }
        };
        assert!(call().await.is_err());
        assert_eq!(sink.inner.events().unwrap().len(), 0);
        sink.mode.store(0, Ordering::SeqCst);
        let retry = call().await.unwrap();
        assert!(!retry[0].deduped);
        assert!(retry[0].persisted);
        if batch {
            assert!(retry[1].deduped);
        }
        assert_eq!(sink.inner.events().unwrap().len(), 1);
        assert!(call().await.unwrap().iter().all(|item| item.deduped));
        assert_eq!(sink.inner.events().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn cancelled_write_releases_source_and_allows_retry() {
    let (pipeline, sink, source) = controlled(2);
    let task = tokio::spawn({
        let pipeline = pipeline.clone();
        let source = source.clone();
        async move { pipeline.ingest_raw(&source, IngestProtocol::Syslog, SYSLOG.as_bytes(), "fixture").await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(3), sink.entered.notified()).await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    sink.mode.store(0, Ordering::SeqCst);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        pipeline.ingest_raw(&source, IngestProtocol::Syslog, SYSLOG.as_bytes(), "fixture"),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!result.deduped);
    assert_eq!(sink.inner.events().unwrap().len(), 1);
}

#[tokio::test]
async fn concurrent_identical_requests_create_only_one_event() {
    let (pipeline, sink, source) = controlled(0);
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let pipeline = pipeline.clone();
        let source = source.clone();
        tasks.spawn(
            async move { pipeline.ingest_raw(&source, IngestProtocol::Syslog, SYSLOG.as_bytes(), "fixture").await },
        );
    }
    let mut duplicates = 0;
    while let Some(result) = tasks.join_next().await {
        duplicates += usize::from(result.unwrap().unwrap().deduped);
    }
    assert_eq!(duplicates, 19);
    assert_eq!(sink.inner.events().unwrap().len(), 1);
    assert_eq!(sink.inner.raws().unwrap().len(), 20);
}
