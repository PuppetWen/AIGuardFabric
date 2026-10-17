//! Real PostgreSQL: independent API instances share leases, payloads and dedup state.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::{notification_config as config, notification_outbox as queue};
use agf_core::{enums::Severity, ids::Id, notify::ChannelKind};
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use common::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires AGF_TEST_DATABASE_URL pointing to an isolated requirements database"]
async fn notification_queue_survives_fresh_instances_and_parallel_claims() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap();
    let database = Database::from_pool(pool.clone());
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut first = setup().await;
    first.state.configurations = Arc::new(agf_api::config_store::ConfigStore::new(Some(store.clone())));
    first.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    let tenant = agf_api::tenant_directory::new(format!("outbox-{}", Id::new()), "Notification test".into());
    let tenant = agf_api::tenant_directory::save(&first.state, tenant, true).await.unwrap().id;
    config::save(&first.state, tenant, ChannelKind::InApp, serde_json::from_value(json!({"enabled":true})).unwrap())
        .await
        .unwrap();
    let row = first
        .state
        .configurations
        .get::<config::StoredChannel>(tenant, config::KIND, config::id(tenant, ChannelKind::InApp))
        .await
        .unwrap()
        .unwrap();
    let subject = Id::new();
    let id = queue::enqueue(
        &first.state,
        tenant,
        vec![row.clone()],
        "custom",
        subject,
        "pg-private-notification",
        "pg-private-body",
        Severity::High,
    )
    .await
    .unwrap()[0];
    let mut second = setup().await;
    second.state.configurations = Arc::new(agf_api::config_store::ConfigStore::new(Some(store.clone())));
    let now = Timestamp::now();
    let (a, b) =
        tokio::join!(queue::attempt(&first.state, tenant, id, now), queue::attempt(&second.state, tenant, id, now));
    assert!(a.is_ok() && b.is_ok(), "{a:?} {b:?}");
    let inbox = second.state.configurations.list::<Value>(tenant, "notification-inbox").await.unwrap();
    assert_eq!(inbox.len(), 1);
    let raw = second.state.configurations.list::<Value>(tenant, queue::KIND).await.unwrap();
    assert!(!serde_json::to_string(&raw).unwrap().contains("pg-private"));
    assert_eq!(
        queue::enqueue(
            &second.state,
            tenant,
            vec![row],
            "custom",
            subject,
            "pg-private-notification",
            "pg-private-body",
            Severity::High
        )
        .await
        .unwrap()[0],
        id
    );
    assert_eq!(queue::attempt(&second.state, tenant, id, Timestamp::now()).await.unwrap()["attempts"], 1);
    assert!(queue::history(&second.state, TenantId::new()).await.unwrap().is_empty());
    // Inactive test tenant keeps subsequent background validation isolated.
    let mut entry = agf_api::tenant_directory::list(&first.state)
        .await
        .unwrap()
        .into_iter()
        .find(|entry| entry.id == tenant)
        .unwrap();
    entry.enabled = false;
    agf_api::tenant_directory::save(&first.state, entry, false).await.unwrap();
    pool.close().await;
}
