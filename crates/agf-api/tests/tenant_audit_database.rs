//! A tenant directory change and its success audit must share one database commit.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::ids::{Id, TenantId};
use agf_storage::{AuditRepo, Database, Store, objectstore::MemoryObjectStore};
use common::*;

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn tenant_create_and_disable_roll_back_when_audit_fails() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap();
    let database = Database::from_pool(pool.clone());
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(store)));
    h.app = build_router(h.state.clone());
    let slug = format!("audit-tenant-{}", Id::new());
    let created = h.post("/api/v1/tenants", json!({"slug":slug,"name":"Audit tenant"})).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let tenant = TenantId::parse(created.json()["id"].as_str().unwrap()).unwrap();
    let auditor = TenantId::default_tenant();
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(auditor).await.unwrap();
    let before = AuditRepo::chain_stats(&mut tx).await.unwrap();
    tx.commit().await.unwrap();

    let constraint = format!("agf_test_tenant_audit_{}", Id::new().as_uuid().simple());
    let sql =
        format!("ALTER TABLE audit_logs ADD CONSTRAINT {constraint} CHECK (tenant_id <> '{auditor}'::uuid) NOT VALID");
    sqlx::query(&sql).execute(&pool).await.unwrap();
    let other_slug = format!("audit-tenant-{}", Id::new());
    let failed_create = h.post("/api/v1/tenants", json!({"slug":other_slug,"name":"Must roll back"})).await;
    assert!(!failed_create.status.is_success(), "{}", failed_create.text);
    assert!(agf_api::tenant_directory::list(&h.state).await.unwrap().iter().all(|row| row.slug != other_slug));

    let path = format!("/api/v1/tenants/{tenant}");
    let failed_update = h
        .request("PATCH", &path, Some(&h.admin), Some(json!({"name":"Changed","enabled":false,"expected_version":1})))
        .await;
    assert!(!failed_update.status.is_success(), "{}", failed_update.text);
    let original = agf_api::tenant_directory::get(&h.state, tenant).await.unwrap();
    assert!(original.enabled);
    assert_eq!(original.name, "Audit tenant");
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(auditor).await.unwrap();
    assert_eq!(AuditRepo::chain_stats(&mut tx).await.unwrap(), before);
    tx.commit().await.unwrap();

    sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}")).execute(&pool).await.unwrap();
    let updated = h
        .request("PATCH", &path, Some(&h.admin), Some(json!({"name":"Changed","enabled":false,"expected_version":1})))
        .await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.text);
    assert_eq!(updated.json()["version"], 2);
    let stale = h
        .request("PATCH", &path, Some(&h.admin), Some(json!({"name":"Stale","enabled":true,"expected_version":1})))
        .await;
    assert_eq!(stale.status, StatusCode::CONFLICT, "{}", stale.text);
    let actual = agf_api::tenant_directory::get(&h.state, tenant).await.unwrap();
    assert!(!actual.enabled);
    assert_eq!(actual.name, "Changed");
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(auditor).await.unwrap();
    assert_ne!(AuditRepo::chain_stats(&mut tx).await.unwrap(), before);
    tx.commit().await.unwrap();
    pool.close().await;
}
