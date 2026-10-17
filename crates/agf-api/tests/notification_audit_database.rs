//! A notification settings write and its success audit must share one database commit.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::notification_config::{self, StoredChannel};
use agf_core::{ids::Id, notify::ChannelKind};
use agf_storage::{AuditRepo, Database, Store, objectstore::MemoryObjectStore};
use common::*;

const SETTINGS: &str = "/api/v1/settings/notifications/in-app";

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn notification_configuration_rolls_back_when_audit_fails() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap();
    let database = Database::from_pool(pool.clone());
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(store)));
    let tenant =
        agf_api::tenant_directory::new(format!("notification-audit-{}", Id::new()), "Notification audit test".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.app = build_router(h.state.clone());
    let token = format!("Bearer {}", h.admin);
    let tenant_id = tenant.id.to_string();
    let headers = [("authorization", token.as_str()), ("x-agf-tenant", tenant_id.as_str())];
    let initial = h.request_with("PUT", SETTINGS, &headers, Some(json!({"enabled":true}))).await;
    assert_eq!(initial.status, StatusCode::OK, "{}", initial.text);
    assert_eq!(initial.json()["version"], 1);
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    let before = AuditRepo::chain_stats(&mut tx).await.unwrap();
    tx.commit().await.unwrap();

    let constraint = format!("agf_test_notification_audit_{}", Id::new().as_uuid().simple());
    let sql = format!(
        "ALTER TABLE audit_logs ADD CONSTRAINT {constraint} CHECK (tenant_id <> '{}'::uuid) NOT VALID",
        tenant.id
    );
    sqlx::query(&sql).execute(&pool).await.unwrap();
    let failed = h.request_with("PUT", SETTINGS, &headers, Some(json!({"expectedVersion":1,"enabled":false}))).await;
    assert!(!failed.status.is_success(), "{}", failed.text);
    let stored = h
        .state
        .configurations
        .get::<StoredChannel>(
            tenant.id,
            notification_config::KIND,
            notification_config::id(tenant.id, ChannelKind::InApp),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.version, 1);
    assert!(stored.enabled);
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    assert_eq!(AuditRepo::chain_stats(&mut tx).await.unwrap(), before);
    tx.commit().await.unwrap();

    sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}")).execute(&pool).await.unwrap();
    let saved = h.request_with("PUT", SETTINGS, &headers, Some(json!({"expectedVersion":1,"enabled":false}))).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.json()["version"], 2);
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    assert_ne!(AuditRepo::chain_stats(&mut tx).await.unwrap(), before);
    tx.commit().await.unwrap();
    pool.close().await;
}
