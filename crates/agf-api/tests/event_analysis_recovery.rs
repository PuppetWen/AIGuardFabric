//! SQL recovery remains automatic without NATS and isolates poisoned events with retry backoff.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{
    enums::IngestProtocol,
    event::{Event, EventCategory},
    ids::Id,
    rule::Detection,
};
use agf_ingest::pipeline::SqlSink;
use agf_storage::{Database, EventRepo, Store, objectstore::MemoryObjectStore};
use common::*;

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn failed_analysis_rolls_back_then_recovers_with_one_persistent_notification() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap();
    let db = Database::from_pool(pool);
    db.migrate().await.unwrap();
    let db = Arc::new(Store::new(db, None, Arc::new(MemoryObjectStore::new())));
    let tenant = TenantId::new();
    sqlx::query("INSERT INTO tenants(id,slug,name) VALUES ($1,$2,'Event recovery validation')")
        .bind(tenant.as_uuid())
        .bind(format!("event-recovery-{tenant}"))
        .execute(db.db().pool())
        .await
        .unwrap();
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.state.ingest_sink = Arc::new(SqlSink::new(db.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
    let mut rule = agf_api::state::fallback_rules().remove(0);
    rule.key = "requirements-recovery".into();
    rule.name = "Bad SQL title\0".into();
    rule.detection = Detection::Keyword { any: vec!["recovery-detection-marker".into()] };
    rule.samples.positive = vec!["recovery-detection-marker".into()];
    rule.samples.negative = vec!["benign".into()];
    h.state.rules = Arc::new(agf_scan::loader::RulePackLoader::strict().load_inline(vec![rule.clone()]).unwrap());
    agf_api::notification_config::save(
        &h.state,
        tenant,
        agf_core::notify::ChannelKind::InApp,
        serde_json::from_value(json!({"enabled":true,"minSeverity":"info","settings":{},"secrets":{},"target":""}))
            .unwrap(),
    )
    .await
    .unwrap();
    let mut bad = Event::new(tenant, Id::new(), IngestProtocol::Otlp);
    bad.category = EventCategory::AiSession;
    bad.message = "recovery-detection-marker".into();
    let mut good = bad.clone();
    good.id = Id::new();
    good.message = "benign".into();
    let writes = vec![bad.clone(), good];
    db.with_tenant(tenant, move |tx| Box::pin(async move { EventRepo::insert_batch(tx, &writes).await }))
        .await
        .unwrap();
    assert_eq!(agf_api::event_analysis::recover_pending(&h.state, tenant).await.unwrap().0, 1);
    let counts: (i64, i64, i64, i64) = db
        .with_tenant(tenant, |tx| {
            Box::pin(async move {
                sqlx::query_as(
                    "SELECT (SELECT count(*) FROM findings),(SELECT count(*) FROM alerts),
            (SELECT count(*) FROM event_analysis_receipts),(SELECT count(*) FROM event_analysis_retries)",
                )
                .fetch_one(&mut **tx)
                .await
                .map_err(|e| agf_storage::map_sqlx_err("recovery_counts", &e))
            })
        })
        .await
        .unwrap();
    assert_eq!(counts, (0, 0, 1, 1), "failed detection must roll back finding, alert and receipt together");
    assert_eq!(
        agf_api::event_analysis::recover_pending(&h.state, tenant).await.unwrap().0,
        0,
        "backoff must prevent an immediate retry loop"
    );
    rule.name = "Recovered event rule".into();
    h.state.rules = Arc::new(agf_scan::loader::RulePackLoader::strict().load_inline(vec![rule]).unwrap());
    db.with_tenant(tenant, |tx| {
        Box::pin(async move {
            sqlx::query("UPDATE event_analysis_retries SET available_at=now()-interval '1 second'")
                .execute(&mut **tx)
                .await
                .map_err(|e| agf_storage::map_sqlx_err("retry_due", &e))?;
            Ok(())
        })
    })
    .await
    .unwrap();
    assert_eq!(agf_api::event_analysis::recover_pending(&h.state, tenant).await.unwrap().0, 1);
    let jobs = agf_api::notification_outbox::history(&h.state, tenant).await.unwrap();
    assert_eq!(jobs.len(), 1);
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
    let jobs = agf_api::notification_outbox::history(&h.state, tenant).await.unwrap();
    let id = jobs[0]["id"].as_str().unwrap().parse().unwrap();
    let sent = agf_api::notification_outbox::attempt(&h.state, tenant, id, Timestamp::now()).await.unwrap();
    assert_eq!(sent["outcome"], "delivered", "{sent}");
    assert_eq!(agf_api::event_analysis::recover_pending(&h.state, tenant).await.unwrap().0, 0);
    assert_eq!(agf_api::notification_outbox::history(&h.state, tenant).await.unwrap().len(), 1);
}
