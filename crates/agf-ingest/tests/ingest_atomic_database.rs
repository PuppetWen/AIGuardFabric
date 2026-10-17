//! Isolated PostgreSQL verifies all-or-nothing evidence/event persistence.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use agf_core::{
    enums::IngestProtocol,
    event::{Event, RawLog},
    ids::{Id, TenantId},
    time::Timestamp,
};
use agf_ingest::pipeline::{IngestWrite, Sink, SqlSink};
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use std::sync::Arc;

fn item(source: Id) -> IngestWrite {
    let tenant = TenantId::default_tenant();
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
            origin: "atomic-database-test".into(),
            parsed: true,
            parse_error: None,
            event_id: Some(event.id),
        },
        event: Some(event),
    }
}

async fn counts(store: &Store, source: Id) -> (i64, i64) {
    let mut tx = store.db().begin_tenant(TenantId::default_tenant()).await.unwrap();
    let raw = sqlx::query_scalar("SELECT count(*) FROM raw_logs WHERE source_id=$1")
        .bind(source.as_uuid())
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let events = sqlx::query_scalar("SELECT count(*) FROM events WHERE source_id=$1")
        .bind(source.as_uuid())
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    (raw, events)
}

#[tokio::test]
#[ignore = "requires AGF_TEST_DATABASE_URL for an isolated agf_requirements_test_ database"]
async fn failed_second_event_rolls_back_the_entire_batch_and_can_retry() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(4).connect(&url).await.unwrap();
    let db = Database::from_pool(pool);
    db.migrate().await.unwrap();
    let store = Arc::new(Store::new(db, None, Arc::new(MemoryObjectStore::new())));
    let sink = SqlSink::new(store.clone());
    let source = Id::new();
    let mut items = vec![item(source), item(source)];
    items[1].event.as_mut().unwrap().message = "invalid PostgreSQL text\0fixture".into();
    assert!(sink.persist_ingest(&items).await.is_err());
    assert_eq!(counts(&store, source).await, (0, 0), "neither first event nor raw evidence can escape rollback");
    items[1].event.as_mut().unwrap().message = "valid retry".into();
    assert_eq!(sink.persist_ingest(&items).await.unwrap(), 2);
    assert_eq!(counts(&store, source).await, (2, 2));

    let mut invalid = vec![item(source)];
    invalid[0].event.as_mut().unwrap().tenant_id = TenantId::new();
    assert!(sink.persist_ingest(&invalid).await.is_err());
    assert_eq!(counts(&store, source).await, (2, 2));

    let second_source = Id::new();
    let first = Event::new(TenantId::default_tenant(), second_source, IngestProtocol::Otlp);
    let mut second = first.clone();
    second.id = Id::new();
    second.message = "invalid\0event".into();
    let result = store
        .with_tenant(TenantId::default_tenant(), move |tx| {
            Box::pin(async move { agf_storage::repository::EventRepo::insert_batch(tx, &[first, second]).await })
        })
        .await;
    assert!(result.is_err(), "repository must propagate partial batch failures");
    assert_eq!(counts(&store, second_source).await, (0, 0));
}

async fn isolated_store() -> Arc<Store> {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(4).connect(&url).await.unwrap();
    let db = Database::from_pool(pool);
    db.migrate().await.unwrap();
    Arc::new(Store::new(db, None, Arc::new(MemoryObjectStore::new())))
}

async fn create_tenant(store: &Store) -> TenantId {
    let tenant = TenantId::new();
    sqlx::query("INSERT INTO tenants(id,slug,name) VALUES ($1,$2,'Bulk ingest validation')")
        .bind(tenant.as_uuid())
        .bind(format!("bulk-ingest-{tenant}"))
        .execute(store.db().pool())
        .await
        .unwrap();
    tenant
}

fn tenant_item(tenant: TenantId, source: Id) -> IngestWrite {
    let mut result = item(source);
    result.raw.tenant_id = tenant;
    result.event.as_mut().unwrap().tenant_id = tenant;
    result
}

async fn tenant_counts(store: &Store, tenant: TenantId) -> (i64, i64, i64) {
    let mut tx = store.db().begin_tenant(tenant).await.unwrap();
    let counts = sqlx::query_as(
        "SELECT (SELECT count(*) FROM raw_logs), (SELECT count(*) FROM events),
                (SELECT count(*) FROM event_delivery_outbox)",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    counts
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn chunked_ingest_rolls_back_late_failure_then_retries_without_duplicate_outbox() {
    let store = isolated_store().await;
    let tenant = create_tenant(&store).await;
    let foreign = create_tenant(&store).await;
    let source = Id::new();
    let sink = SqlSink::new(store.clone()).with_event_outbox(true);
    // 2,600 * 26 event binds exceeds PostgreSQL's statement limit without chunking.
    let mut batch: Vec<_> = (0..2600).map(|_| tenant_item(tenant, source)).collect();
    batch.last_mut().unwrap().event.as_mut().unwrap().message = "late\0failure".into();
    assert!(sink.persist_ingest(&batch).await.is_err());
    assert_eq!(tenant_counts(&store, tenant).await, (0, 0, 0), "all earlier chunks must roll back");
    batch.last_mut().unwrap().event.as_mut().unwrap().message = "valid retry".into();
    assert_eq!(sink.persist_ingest(&batch).await.unwrap(), 2600);
    assert_eq!(tenant_counts(&store, tenant).await, (2600, 2600, 2600));
    assert_eq!(sink.persist_ingest(&batch).await.unwrap(), 2600, "retain accepted-input count on retry");
    assert_eq!(tenant_counts(&store, tenant).await, (2600, 2600, 2600));
    assert_eq!(tenant_counts(&store, foreign).await, (0, 0, 0), "runtime SQL must remain RLS scoped");
    let mixed = vec![tenant_item(tenant, source), tenant_item(foreign, source)];
    assert!(sink.persist_ingest(&mixed).await.is_err());
    assert_eq!(tenant_counts(&store, tenant).await, (2600, 2600, 2600));
    assert_eq!(tenant_counts(&store, foreign).await, (0, 0, 0));
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn mixed_dedup_raw_bytes_references_retry_state_and_id_conflicts_are_preserved() {
    let store = isolated_store().await;
    let tenant = create_tenant(&store).await;
    let foreign = create_tenant(&store).await;
    let source = Id::new();
    let sink = SqlSink::new(store.clone()).with_event_outbox(true);
    let bytes = b"\0\xffA\x80\n";
    let mut original = tenant_item(tenant, source);
    original.raw.payload_b64 = B64.encode(bytes);
    original.raw.bytes = bytes.len();
    let mut deduped = original.clone();
    deduped.raw.id = Id::new();
    deduped.raw.event_id = None;
    deduped.raw.parse_error = Some("duplicate evidence; event suppressed".into());
    deduped.event = None;
    assert_eq!(sink.persist_ingest(&[original.clone(), deduped.clone()]).await.unwrap(), 1);
    assert_eq!(tenant_counts(&store, tenant).await, (2, 1, 1));
    let mut tx = store.db().begin_tenant(tenant).await.unwrap();
    let retained: (String, i32, bool, Option<uuid::Uuid>, Option<String>) =
        sqlx::query_as("SELECT payload_b64,bytes,parsed,event_id,parse_error FROM raw_logs WHERE id=$1")
            .bind(original.raw.id.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(B64.decode(&retained.0).unwrap(), bytes);
    assert_eq!(retained.1, i32::try_from(bytes.len()).unwrap());
    assert!(retained.2);
    assert_eq!(retained.3, Some(original.event.as_ref().unwrap().id.as_uuid()));
    assert_eq!(retained.4, None);
    let queued: serde_json::Value = sqlx::query_scalar("SELECT payload FROM event_delivery_outbox WHERE event_id=$1")
        .bind(original.event.as_ref().unwrap().id.as_uuid())
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(queued, serde_json::to_value(original.event.as_ref().unwrap()).unwrap());
    tx.commit().await.unwrap();

    // A stale retry of only the evidence must not overwrite an existing parse result.
    let mut stale = original.clone();
    stale.event = None;
    stale.raw.event_id = None;
    stale.raw.parsed = false;
    stale.raw.parse_error = Some("stale retry".into());
    assert_eq!(sink.persist_ingest(&[stale]).await.unwrap(), 0);
    let mut tx = store.db().begin_tenant(tenant).await.unwrap();
    let state: (bool, Option<uuid::Uuid>, Option<String>) =
        sqlx::query_as("SELECT parsed,event_id,parse_error FROM raw_logs WHERE id=$1")
            .bind(original.raw.id.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(state, (true, Some(original.event.as_ref().unwrap().id.as_uuid()), None));
    tx.commit().await.unwrap();

    let mut collision = original.clone();
    // Same claimed hash but different retained bytes must never replace evidence.
    collision.raw.payload_b64 = B64.encode(b"other");
    assert!(sink.persist_ingest(&[tenant_item(tenant, source), collision]).await.is_err());
    assert_eq!(tenant_counts(&store, tenant).await, (2, 1, 1));
    let fresh = tenant_item(tenant, source);
    let mut repeated_id = fresh.clone();
    repeated_id.raw.payload_b64 = B64.encode(b"else");
    assert!(sink.persist_ingest(&[fresh, repeated_id]).await.is_err());
    assert_eq!(tenant_counts(&store, tenant).await, (2, 1, 1));

    let mut late_conflict: Vec<_> = (0..600).map(|_| tenant_item(tenant, source)).collect();
    let last = late_conflict.last_mut().unwrap();
    last.raw.id = original.raw.id;
    assert!(sink.persist_ingest(&late_conflict).await.is_err());
    assert_eq!(tenant_counts(&store, tenant).await, (2, 1, 1), "raw chunks preceding a late ID conflict roll back");

    let foreign_evidence = tenant_item(foreign, source);
    sink.persist_ingest(std::slice::from_ref(&foreign_evidence)).await.unwrap();
    let mut foreign_id = tenant_item(tenant, source);
    foreign_id.raw.id = foreign_evidence.raw.id;
    assert!(sink.persist_ingest(&[tenant_item(tenant, source), foreign_id]).await.is_err());
    assert_eq!(tenant_counts(&store, tenant).await, (2, 1, 1), "foreign IDs must fail closed and roll back");
    assert_eq!(tenant_counts(&store, foreign).await, (1, 1, 1));
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn concurrent_raw_id_retry_waits_for_commit_then_verifies_existing_evidence() {
    let store = isolated_store().await;
    let tenant = create_tenant(&store).await;
    let original = tenant_item(tenant, Id::new());
    let mut first = store.db().begin_tenant(tenant).await.unwrap();
    agf_storage::repository::EventRepo::insert_raw_batch(&mut first, std::slice::from_ref(&original.raw))
        .await
        .unwrap();
    let marker = format!("bulk-raw-retry-{}", Id::new());
    let entered = Arc::new(tokio::sync::Notify::new());
    let retry = tokio::spawn({
        let database = store.clone();
        let marker = marker.clone();
        let entered = entered.clone();
        let raw = original.raw.clone();
        async move {
            let mut tx = database.db().begin_tenant(tenant).await.unwrap();
            sqlx::query("SELECT set_config('application_name',$1,true)").bind(marker).execute(&mut *tx).await.unwrap();
            entered.notify_one();
            agf_storage::repository::EventRepo::insert_raw_batch(&mut tx, &[raw]).await.unwrap();
            tx.commit().await.unwrap();
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified()).await.unwrap();
    // Observe an actual PostgreSQL lock wait; scheduling alone cannot satisfy this test.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock')",
            )
            .bind(&marker)
            .fetch_one(store.db().pool())
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("second insertion must wait for the first uncommitted raw ID");
    first.commit().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), retry).await.unwrap().unwrap();
    assert_eq!(tenant_counts(&store, tenant).await, (1, 0, 0));
    let sink = SqlSink::new(store.clone()).with_event_outbox(true);
    assert_eq!(sink.persist_ingest(&[original]).await.unwrap(), 1);
    assert_eq!(tenant_counts(&store, tenant).await, (1, 1, 1));
}
