//! Demo replay samples must be safe to seed after a server restart.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use agf_core::{
    enums::IngestProtocol,
    event::RawLog,
    ids::{Id, TenantId},
    time::Timestamp,
};
use agf_ingest::pipeline::SqlSink;
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use common::*;

async fn sample_rows(db: &Store, tenant: TenantId) -> Vec<Value> {
    db.with_tenant(tenant, |tx| Box::pin(async move {
        sqlx::query_scalar("SELECT to_jsonb(r) FROM raw_logs r WHERE origin IN ('demo-src-wazuh-json','demo-src-aliyun-waf') ORDER BY origin")
            .fetch_all(&mut **tx).await.map_err(|e| agf_storage::map_sqlx_err("read_demo_raw", &e))
    })).await.unwrap()
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn repeat_seed_keeps_existing_parse_state_and_rejects_id_collisions() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(4).connect(&url).await.unwrap();
    let database = Database::from_pool(pool);
    database.migrate().await.unwrap();
    let db = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.ingest_sink = Arc::new(SqlSink::new(db.clone()));
    let tenant = TenantId::default_tenant();

    assert_eq!(h.state.seed_replay_samples().await.unwrap(), 2);
    let rows = sample_rows(&db, tenant).await;
    assert_eq!(rows.len(), 2);
    let id = Id::from_uuid(uuid::Uuid::parse_str(rows[0]["id"].as_str().unwrap()).unwrap());
    h.state.ingest_sink.mark_raw(tenant, id, true, None, None).await.unwrap();
    let before = sample_rows(&db, tenant).await;
    assert_eq!(h.state.seed_replay_samples().await.unwrap(), 2);
    assert_eq!(sample_rows(&db, tenant).await, before, "restart seed changed saved raw logs");

    let collision = RawLog {
        id,
        tenant_id: tenant,
        source_id: Id::from_uuid(uuid::Uuid::parse_str(before[0]["source_id"].as_str().unwrap()).unwrap()),
        received_at: Timestamp::now(),
        protocol: IngestProtocol::Webhook,
        payload_b64: "eA==".into(),
        payload_hash: "different-content".into(),
        bytes: 1,
        origin: before[0]["origin"].as_str().unwrap().into(),
        parsed: false,
        parse_error: None,
        event_id: None,
    };
    let error = h.state.ingest_sink.put_raw(&collision).await.unwrap_err();
    assert!(error.to_string().contains("冲突"), "{error}");
    assert_eq!(sample_rows(&db, tenant).await, before);
}
