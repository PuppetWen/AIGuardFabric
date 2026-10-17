//! Isolated database and optional local broker checks for durable, tenant-bound publication.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use agf_core::{
    enums::IngestProtocol,
    error::{DomainError, DomainResult},
    event::{Event, RawLog},
    ids::{Id, TenantId},
    time::Timestamp,
};
use agf_ingest::{
    bus::{EventBus, EventOutbox, InMemoryEventBus},
    pipeline::{IngestWrite, Sink, SqlSink},
};
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

async fn store() -> Arc<Store> {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap();
    let db = Database::from_pool(pool);
    db.migrate().await.unwrap();
    Arc::new(Store::new(db, None, Arc::new(MemoryObjectStore::new())))
}

async fn tenant(store: &Store) -> TenantId {
    let id = TenantId::new();
    sqlx::query("INSERT INTO tenants(id,slug,name) VALUES ($1,$2,'Event delivery validation')")
        .bind(id.as_uuid())
        .bind(format!("event-delivery-{id}"))
        .execute(store.db().pool())
        .await
        .unwrap();
    id
}

fn item(tenant: TenantId) -> IngestWrite {
    let source = Id::new();
    let event = Event::new(tenant, source, IngestProtocol::Otlp);
    IngestWrite {
        raw: RawLog {
            id: Id::new(),
            tenant_id: tenant,
            source_id: source,
            received_at: Timestamp::now(),
            protocol: IngestProtocol::Otlp,
            payload_b64: "dGVzdA==".into(),
            payload_hash: "fixture".into(),
            bytes: 4,
            origin: "event-delivery-test".into(),
            parsed: true,
            parse_error: None,
            event_id: Some(event.id),
        },
        event: Some(event),
    }
}

#[derive(Debug)]
struct Broker {
    offline: AtomicBool,
    received: InMemoryEventBus,
}
#[async_trait::async_trait]
impl EventBus for Broker {
    fn name(&self) -> &'static str {
        "fault-injection"
    }
    async fn publish(&self, event: &Event) -> DomainResult<()> {
        if self.offline.load(Ordering::SeqCst) {
            return Err(DomainError::DependencyUnavailable {
                dependency: "test-broker".into(),
                cause: "offline".into(),
            });
        }
        self.received.publish(event).await
    }
    async fn publish_batch(&self, events: &[Event]) -> DomainResult<usize> {
        for event in events {
            self.publish(event).await?;
        }
        Ok(events.len())
    }
    async fn health(&self) -> DomainResult<()> {
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn rollback_failure_restart_retry_and_concurrent_workers_preserve_events() {
    let database = store().await;
    let tenant = tenant(&database).await;
    let sink = SqlSink::new(database.clone()).with_event_outbox(true);
    let queue = EventOutbox::new(database.clone(), tenant);
    let mut batch = vec![item(tenant), item(tenant)];
    batch[1].event.as_mut().unwrap().message = "invalid\0text".into();
    assert!(sink.persist_ingest(&batch).await.is_err());
    assert_eq!(queue.pending().await.unwrap(), (0, 0));
    batch[1].event.as_mut().unwrap().message = "retry after rollback".into();
    sink.persist_ingest(&batch).await.unwrap();
    assert_eq!(queue.pending().await.unwrap(), (2, 0));
    let broker = Broker { offline: AtomicBool::new(true), received: InMemoryEventBus::new(256) };
    assert_eq!(queue.drain_once(&broker).await.unwrap().failed, 2);
    assert_eq!(queue.pending().await.unwrap(), (2, 2));
    assert_eq!(queue.drain_once(&broker).await.unwrap().claimed, 0, "retry delay must be honored");
    let restarted = EventOutbox::new(store().await, tenant);
    assert_eq!(restarted.pending().await.unwrap(), (2, 2));
    let foreign = EventOutbox::new(database.clone(), TenantId::new());
    assert_eq!(foreign.pending().await.unwrap(), (0, 0));
    assert_eq!(foreign.drain_once(&broker).await.unwrap().claimed, 0);
    broker.offline.store(false, Ordering::SeqCst);
    let mut tx = database.db().begin_tenant(tenant).await.unwrap();
    sqlx::query("UPDATE event_delivery_outbox SET available_at=now() WHERE delivered_at IS NULL")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(restarted.drain_once(&broker).await.unwrap().delivered, 2);
    assert_eq!(restarted.pending().await.unwrap(), (0, 0));
    assert_eq!(broker.received.pending(), 2);
    sink.persist_ingest(&(0..32).map(|_| item(tenant)).collect::<Vec<_>>()).await.unwrap();
    let (left, right) = tokio::join!(queue.drain_once(&broker), restarted.drain_once(&broker));
    assert_eq!(left.unwrap().delivered + right.unwrap().delivered, 32);
    let events = broker.received.drain(100).unwrap();
    let ids: std::collections::BTreeSet<_> = events.iter().map(|event| event.id).collect();
    assert_eq!(events.len(), 34);
    assert_eq!(ids.len(), 34, "concurrent workers must not acquire the same event");
}

#[derive(Debug)]
struct PartialBroker {
    failed_id: Id,
    offline: AtomicBool,
    active: AtomicUsize,
    maximum: AtomicUsize,
    received: InMemoryEventBus,
}

#[async_trait::async_trait]
impl EventBus for PartialBroker {
    fn name(&self) -> &'static str {
        "partial-fault-injection"
    }
    async fn publish(&self, event: &Event) -> DomainResult<()> {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.maximum.fetch_max(active, Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        self.active.fetch_sub(1, Ordering::SeqCst);
        if event.id == self.failed_id && self.offline.load(Ordering::SeqCst) {
            return Err(DomainError::DependencyUnavailable {
                dependency: "test-broker".into(),
                cause: "one publication unconfirmed".into(),
            });
        }
        self.received.publish(event).await
    }
    async fn publish_batch(&self, events: &[Event]) -> DomainResult<usize> {
        for event in events {
            self.publish(event).await?;
        }
        Ok(events.len())
    }
    async fn health(&self) -> DomainResult<()> {
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn concurrent_publication_records_only_individual_confirmations_and_retries_the_failure() {
    let database = store().await;
    let foreign = tenant(&database).await;
    let tenant = tenant(&database).await;
    let sink = SqlSink::new(database.clone()).with_event_outbox(true);
    let queue = EventOutbox::new(database.clone(), tenant);
    let batch: Vec<_> = (0..16).map(|_| item(tenant)).collect();
    let failed_id = batch[0].event.as_ref().unwrap().id;
    sink.persist_ingest(&batch).await.unwrap();
    sink.persist_ingest(&[item(foreign)]).await.unwrap();
    let broker = PartialBroker {
        failed_id,
        offline: AtomicBool::new(true),
        active: AtomicUsize::new(0),
        maximum: AtomicUsize::new(0),
        received: InMemoryEventBus::new(256),
    };
    let report = queue.drain_once(&broker).await.unwrap();
    assert_eq!((report.claimed, report.delivered, report.failed), (16, 15, 1));
    assert!(broker.maximum.load(Ordering::SeqCst) > 1, "independent broker acknowledgements must overlap");
    assert!(broker.maximum.load(Ordering::SeqCst) <= 16, "delivery concurrency must stay bounded");
    assert_eq!(queue.pending().await.unwrap(), (1, 1));
    assert_eq!(EventOutbox::new(database.clone(), foreign).pending().await.unwrap(), (1, 0));
    let mut tx = database.db().begin_tenant(tenant).await.unwrap();
    let failure: (bool, bool, bool, i32) = sqlx::query_as(
        "SELECT delivered_at IS NULL, last_error IS NOT NULL, lease_id IS NULL, attempts
         FROM event_delivery_outbox WHERE event_id=$1",
    )
    .bind(failed_id.as_uuid())
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(failure, (true, true, true, 1));
    sqlx::query("UPDATE event_delivery_outbox SET available_at=now() WHERE event_id=$1")
        .bind(failed_id.as_uuid())
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    broker.offline.store(false, Ordering::SeqCst);
    assert_eq!(queue.drain_once(&broker).await.unwrap().delivered, 1);
    assert_eq!(queue.pending().await.unwrap(), (0, 0));
    let events = broker.received.drain(256).unwrap();
    let ids: std::collections::BTreeSet<_> = events.iter().map(|event| event.id).collect();
    assert_eq!(events.len(), 16);
    assert_eq!(ids.len(), 16, "successful siblings must not be retried");
    assert!(events.iter().all(|event| event.tenant_id == tenant));
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn bounded_128_claim_keeps_publication_concurrency_and_individual_receipts() {
    let database = store().await;
    let foreign = tenant(&database).await;
    let tenant = tenant(&database).await;
    let sink = SqlSink::new(database.clone()).with_event_outbox(true);
    let queue = EventOutbox::new(database.clone(), tenant);
    let batch: Vec<_> = (0..129).map(|_| item(tenant)).collect();
    sink.persist_ingest(&batch).await.unwrap();
    sink.persist_ingest(&[item(foreign)]).await.unwrap();
    let mut tx = database.db().begin_tenant(tenant).await.unwrap();
    // Select an actual first-page row rather than assume generated UUID order.
    let first: uuid::Uuid = sqlx::query_scalar(
        "SELECT event_id FROM event_delivery_outbox WHERE delivered_at IS NULL
         AND deleted_at IS NULL ORDER BY available_at, event_id LIMIT 1",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let failed_id = Id::from_uuid(first);
    let broker = PartialBroker {
        failed_id,
        offline: AtomicBool::new(true),
        active: AtomicUsize::new(0),
        maximum: AtomicUsize::new(0),
        received: InMemoryEventBus::new(256),
    };
    let report = queue.drain_once(&broker).await.unwrap();
    assert_eq!((report.claimed, report.delivered, report.failed), (128, 127, 1));
    assert!(broker.maximum.load(Ordering::SeqCst) > 1);
    assert!(broker.maximum.load(Ordering::SeqCst) <= 16, "claim size must not raise broker concurrency");
    assert_eq!(queue.pending().await.unwrap(), (2, 1), "one failed and one unclaimed row remain durable");
    assert_eq!(EventOutbox::new(database.clone(), foreign).pending().await.unwrap(), (1, 0));
    let mut tx = database.db().begin_tenant(tenant).await.unwrap();
    let failure: (bool, bool, bool, i32) = sqlx::query_as(
        "SELECT delivered_at IS NULL, last_error IS NOT NULL, lease_id IS NULL, attempts
         FROM event_delivery_outbox WHERE event_id=$1",
    )
    .bind(failed_id.as_uuid())
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(failure, (true, true, true, 1));
    // Only this owned failed fixture is made retryable; confirmed siblings stay settled.
    sqlx::query("UPDATE event_delivery_outbox SET available_at=now() WHERE event_id=$1")
        .bind(failed_id.as_uuid())
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    broker.offline.store(false, Ordering::SeqCst);
    let retry = queue.drain_once(&broker).await.unwrap();
    assert_eq!((retry.claimed, retry.delivered, retry.failed), (2, 2, 0));
    assert_eq!(queue.pending().await.unwrap(), (0, 0));
    let events = broker.received.drain(256).unwrap();
    let ids: std::collections::BTreeSet<_> = events.iter().map(|event| event.id).collect();
    assert_eq!(events.len(), 129);
    assert_eq!(ids.len(), 129, "confirmed siblings must not be retried");
    assert!(events.iter().all(|event| event.tenant_id == tenant));
}

#[derive(Debug)]
struct LeaseChangingBroker {
    database: Arc<Store>,
}

#[async_trait::async_trait]
impl EventBus for LeaseChangingBroker {
    fn name(&self) -> &'static str {
        "lease-loss-injection"
    }
    async fn publish(&self, event: &Event) -> DomainResult<()> {
        // Simulate losing ownership while a broker confirmation is in flight.
        let mut tx = self.database.db().begin_tenant(event.tenant_id).await?;
        sqlx::query("UPDATE event_delivery_outbox SET lease_id=$2 WHERE event_id=$1")
            .bind(event.id.as_uuid())
            .bind(Id::new().as_uuid())
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await?;
        Ok(())
    }
    async fn publish_batch(&self, events: &[Event]) -> DomainResult<usize> {
        for event in events {
            self.publish(event).await?;
        }
        Ok(events.len())
    }
    async fn health(&self) -> DomainResult<()> {
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn a_lost_lease_cannot_commit_or_count_a_delivery_receipt() {
    let database = store().await;
    let tenant = tenant(&database).await;
    let sink = SqlSink::new(database.clone()).with_event_outbox(true);
    let queue = EventOutbox::new(database.clone(), tenant);
    sink.persist_ingest(&[item(tenant)]).await.unwrap();
    let report = queue.drain_once(&LeaseChangingBroker { database: database.clone() }).await.unwrap();
    assert_eq!((report.claimed, report.delivered, report.failed), (1, 0, 0));
    assert_eq!(queue.pending().await.unwrap(), (1, 0));
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn a_forged_payload_is_retained_for_retry_without_publishing_or_hiding_a_valid_sibling() {
    let database = store().await;
    let tenant = tenant(&database).await;
    let sink = SqlSink::new(database.clone()).with_event_outbox(true);
    let queue = EventOutbox::new(database.clone(), tenant);
    let batch = vec![item(tenant), item(tenant)];
    sink.persist_ingest(&batch).await.unwrap();
    let mut forged = batch[0].event.clone().unwrap();
    forged.tenant_id = TenantId::new();
    let mut tx = database.db().begin_tenant(tenant).await.unwrap();
    sqlx::query("UPDATE event_delivery_outbox SET payload=$2 WHERE event_id=$1")
        .bind(forged.id.as_uuid())
        .bind(serde_json::to_value(&forged).unwrap())
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let broker = Broker { offline: AtomicBool::new(false), received: InMemoryEventBus::new(256) };
    let report = queue.drain_once(&broker).await.unwrap();
    assert_eq!((report.claimed, report.delivered, report.failed), (2, 1, 1));
    assert_eq!(queue.pending().await.unwrap(), (1, 1));
    let events = broker.received.drain(256).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, batch[1].event.as_ref().unwrap().id);
    assert_eq!(events[0].tenant_id, tenant);
}

#[derive(Debug)]
struct TimeoutBroker {
    timeout_id: Id,
    received: InMemoryEventBus,
}

#[async_trait::async_trait]
impl EventBus for TimeoutBroker {
    fn name(&self) -> &'static str {
        "timeout-injection"
    }
    async fn publish(&self, event: &Event) -> DomainResult<()> {
        if event.id == self.timeout_id {
            std::future::pending::<()>().await;
        }
        self.received.publish(event).await
    }
    async fn publish_batch(&self, events: &[Event]) -> DomainResult<usize> {
        for event in events {
            self.publish(event).await?;
        }
        Ok(events.len())
    }
    async fn health(&self) -> DomainResult<()> {
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL; exercises the real five-second publish timeout"]
async fn a_broker_timeout_does_not_cancel_or_retry_a_confirmed_sibling() {
    let database = store().await;
    let tenant = tenant(&database).await;
    let sink = SqlSink::new(database.clone()).with_event_outbox(true);
    let queue = EventOutbox::new(database.clone(), tenant);
    let batch = vec![item(tenant), item(tenant)];
    sink.persist_ingest(&batch).await.unwrap();
    let broker =
        TimeoutBroker { timeout_id: batch[0].event.as_ref().unwrap().id, received: InMemoryEventBus::new(256) };
    let report = tokio::time::timeout(std::time::Duration::from_secs(10), queue.drain_once(&broker))
        .await
        .expect("a stalled broker must not hang the outbox worker")
        .unwrap();
    assert_eq!((report.claimed, report.delivered, report.failed), (2, 1, 1));
    assert_eq!(queue.pending().await.unwrap(), (1, 1));
    assert_eq!(queue.drain_once(&broker).await.unwrap().claimed, 0, "timeout retry delay must be honored");
    let events = broker.received.drain(256).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, batch[1].event.as_ref().unwrap().id);
}

#[cfg(feature = "nats")]
#[tokio::test]
#[ignore = "requires AGF_TEST_NATS_URL pointing to a local test broker"]
async fn jetstream_acknowledges_storage_and_deduplicates_retry_across_clients() {
    use agf_ingest::bus::JetStreamEventBus;
    let url = std::env::var("AGF_TEST_NATS_URL").unwrap();
    let parsed = url::Url::parse(&url).unwrap();
    assert!(matches!(parsed.host_str(), Some("127.0.0.1" | "localhost")));
    let suffix = Id::new().to_string().replace('-', "");
    let stream = format!("AGF_REQUIREMENTS_{suffix}");
    let prefix = format!("agf.requirements.{suffix}");
    let first = JetStreamEventBus::connect(&url, &stream, &prefix).await.unwrap();
    let event = item(TenantId::default_tenant()).event.unwrap();
    first.publish(&event).await.unwrap();
    let second = JetStreamEventBus::connect(&url, &stream, &prefix).await.unwrap();
    second.publish(&event).await.unwrap();
    let context = async_nats::jetstream::new(async_nats::connect(url).await.unwrap());
    let recorded = context.get_stream(&stream).await.unwrap();
    assert_eq!(recorded.cached_info().state.messages, 1, "stable event IDs must suppress retried publications");
    // This generated name belongs exclusively to this test; no shared stream is deleted.
    assert!(stream.starts_with("AGF_REQUIREMENTS_") && stream.ends_with(&suffix));
    context.delete_stream(&stream).await.unwrap();
}
