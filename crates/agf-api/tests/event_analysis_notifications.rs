//! Empty analysis receipts do not enter the notification queue; alert jobs still commit before their mark.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{
    enums::IngestProtocol,
    event::{Event, EventCategory},
    ids::Id,
    notify::ChannelKind,
    rule::Detection,
};
use agf_ingest::pipeline::SqlSink;
use agf_storage::{Database, EventRepo, Store, objectstore::MemoryObjectStore};
use common::*;

async fn setup_sql() -> (Harness, Arc<Store>, TenantId, TenantId) {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap();
    let db = Database::from_pool(pool);
    db.migrate().await.unwrap();
    let db = Arc::new(Store::new(db, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.state.ingest_sink = Arc::new(SqlSink::new(db.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
    let mut tenants = Vec::new();
    for _ in 0..2 {
        let entry = agf_api::tenant_directory::new(
            format!("empty-notification-{}", Id::new()),
            "Isolated notification validation".into(),
        );
        tenants.push(entry.id);
        agf_api::tenant_directory::save(&h.state, entry, true).await.unwrap();
    }
    let mut rule = agf_api::state::fallback_rules().remove(0);
    rule.key = "empty-notification-detection".into();
    rule.name = "Notification validation".into();
    rule.detection = Detection::Keyword { any: vec!["notification-warning".into()] };
    rule.samples.positive = vec!["notification-warning".into()];
    rule.samples.negative = vec!["notification-benign".into()];
    h.state.rules = Arc::new(agf_scan::loader::RulePackLoader::strict().load_inline(vec![rule]).unwrap());
    (h, db, tenants[0], tenants[1])
}

async fn process_event(h: &Harness, db: &Store, tenant: TenantId, warning: bool) -> Event {
    let mut event = Event::new(tenant, Id::new(), IngestProtocol::Otlp);
    event.category = EventCategory::AiSession;
    event.message = if warning { "notification-warning" } else { "notification-benign" }.into();
    event.raw_hash = agf_core::secret::content_hash(&event.message);
    let write = event.clone();
    db.with_tenant(tenant, move |tx| Box::pin(async move { EventRepo::insert(tx, &write).await })).await.unwrap();
    let result = agf_api::event_analysis::process(&h.state, &event).await.unwrap();
    assert_eq!(result.alert_ids.is_empty(), !warning);
    event
}

async fn marked(db: &Store, tenant: TenantId, event_id: uuid::Uuid) -> bool {
    db.with_tenant(tenant, move |tx| {
        Box::pin(async move {
            sqlx::query_scalar(
                "SELECT notification_enqueued_at IS NOT NULL FROM event_analysis_receipts WHERE event_id=$1",
            )
            .bind(event_id)
            .fetch_one(&mut **tx)
            .await
            .map_err(|e| agf_storage::map_sqlx_err("notification_mark", &e))
        })
    })
    .await
    .unwrap()
}

async fn seed_receipt(db: &Store, tenant: TenantId, event_id: uuid::Uuid, alert_ids: Value) {
    db.with_tenant(tenant, move |tx| Box::pin(async move {
        sqlx::query("INSERT INTO event_analysis_receipts(tenant_id,event_id,event_time,rule_fingerprint,alert_ids,processed_at)
            VALUES ($1,$2,now(),'isolated-legacy-notification',$3,'2026-01-01T00:00:00Z')")
            .bind(tenant.as_uuid()).bind(event_id).bind(alert_ids).execute(&mut **tx).await
            .map_err(|e| agf_storage::map_sqlx_err("legacy_notification_receipt", &e))?;
        Ok(())
    })).await.unwrap();
}

async fn poison_channels(h: &Harness, tenant: TenantId) -> Id {
    let id = Id::new();
    h.state
        .configurations
        .put(tenant, agf_api::notification_config::KIND, id, &json!({"invalid":"StoredChannel"}))
        .await
        .unwrap();
    id
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn new_empty_receipt_is_complete_without_reading_notification_channels() {
    let (h, db, tenant, _) = setup_sql().await;
    poison_channels(&h, tenant).await;
    let event = process_event(&h, &db, tenant, false).await;
    assert!(marked(&db, tenant, event.id.as_uuid()).await);
    assert_eq!(agf_api::event_analysis::recover_pending(&h.state, tenant).await.unwrap(), (0, 0));
    assert!(agf_api::notification_outbox::history(&h.state, tenant).await.unwrap().is_empty());
    assert!(agf_api::event_analysis::process(&h.state, &event).await.unwrap().duplicate);
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn legacy_empty_batch_is_bounded_deterministic_and_tenant_isolated_without_channel_reads() {
    let (h, db, tenant, foreign) = setup_sql().await;
    poison_channels(&h, tenant).await;
    let mut ids: Vec<_> = (0..33).map(|_| uuid::Uuid::new_v4()).collect();
    ids.sort();
    for id in &ids {
        seed_receipt(&db, tenant, *id, json!([])).await;
    }
    // The same event UUID in another tenant must not be touched by the bounded UPDATE.
    seed_receipt(&db, foreign, ids[0], json!([])).await;
    assert_eq!(agf_api::event_analysis::recover_pending(&h.state, tenant).await.unwrap(), (0, 32));
    for (index, id) in ids.iter().enumerate() {
        assert_eq!(marked(&db, tenant, *id).await, index < 32);
    }
    assert!(!marked(&db, foreign, ids[0]).await);
    assert_eq!(agf_api::event_analysis::recover_pending(&h.state, tenant).await.unwrap(), (0, 1));
    assert!(marked(&db, tenant, ids[32]).await);
    assert!(!marked(&db, foreign, ids[0]).await);
    assert!(agf_api::notification_outbox::history(&h.state, tenant).await.unwrap().is_empty());
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn alert_receipt_stays_unmarked_on_enqueue_failure_and_recovers_without_duplicate_job() {
    let (h, db, tenant, _) = setup_sql().await;
    let event = process_event(&h, &db, tenant, true).await;
    assert!(
        !marked(&db, tenant, event.id.as_uuid()).await,
        "an alert cannot be marked at the analysis INSERT or final UPDATE"
    );
    agf_api::notification_config::save(
        &h.state,
        tenant,
        ChannelKind::InApp,
        serde_json::from_value(json!({"enabled":true,"minSeverity":"info","settings":{},"secrets":{},"target":""}))
            .unwrap(),
    )
    .await
    .unwrap();
    // Channel loading succeeds; the persistent enqueue itself fails on its malformed queue.
    let queue_id = agf_core::ids::deterministic_id("agf.notification-outbox", &tenant.to_string());
    h.state
        .configurations
        .put(tenant, agf_api::notification_outbox::KIND, queue_id, &json!({"invalid":"Queue"}))
        .await
        .unwrap();
    assert!(agf_api::event_analysis::recover_pending(&h.state, tenant).await.is_err());
    assert!(!marked(&db, tenant, event.id.as_uuid()).await);
    h.state.configurations.delete(tenant, agf_api::notification_outbox::KIND, queue_id).await.unwrap();
    assert_eq!(agf_api::event_analysis::recover_pending(&h.state, tenant).await.unwrap(), (0, 1));
    assert!(marked(&db, tenant, event.id.as_uuid()).await);
    assert_eq!(agf_api::notification_outbox::history(&h.state, tenant).await.unwrap().len(), 1);
    assert_eq!(agf_api::event_analysis::recover_pending(&h.state, tenant).await.unwrap(), (0, 0));
    assert_eq!(agf_api::notification_outbox::history(&h.state, tenant).await.unwrap().len(), 1);
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn malformed_alert_ids_fail_before_empty_batch_marks_and_can_be_repaired() {
    let (h, db, tenant, _) = setup_sql().await;
    let good = uuid::Uuid::new_v4();
    let bad = uuid::Uuid::new_v4();
    seed_receipt(&db, tenant, good, json!([])).await;
    seed_receipt(&db, tenant, bad, json!({"invalid":"not an array"})).await;
    assert!(agf_api::event_analysis::recover_pending(&h.state, tenant).await.is_err());
    assert!(!marked(&db, tenant, good).await);
    assert!(!marked(&db, tenant, bad).await);
    db.with_tenant(tenant, move |tx| {
        Box::pin(async move {
            sqlx::query("UPDATE event_analysis_receipts SET alert_ids='[]'::jsonb WHERE event_id=$1")
                .bind(bad)
                .execute(&mut **tx)
                .await
                .map_err(|e| agf_storage::map_sqlx_err("repair_notification_ids", &e))?;
            Ok(())
        })
    })
    .await
    .unwrap();
    assert_eq!(agf_api::event_analysis::recover_pending(&h.state, tenant).await.unwrap(), (0, 2));
    assert!(marked(&db, tenant, good).await);
    assert!(marked(&db, tenant, bad).await);
}
