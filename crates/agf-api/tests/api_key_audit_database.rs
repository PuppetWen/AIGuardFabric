//! API Key issuance and revocation must roll back when success audit cannot be saved.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::tenant_directory;
use agf_core::ids::Id;
use agf_storage::{AuditRepo, Database, Store, objectstore::MemoryObjectStore};
use common::*;

const PATH: &str = "/api/v1/settings/api-keys";

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn key_writes_roll_back_when_audit_fails() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap();
    let database = Database::from_pool(pool.clone());
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(store));
    let tenant = tenant_directory::new(format!("key-audit-{}", Id::new()), "Key audit test".into());
    tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.app = build_router(h.state.clone());
    let token = format!("Bearer {}", h.admin);
    let tenant_id = tenant.id.to_string();
    let headers = [("authorization", token.as_str()), ("x-agf-tenant", tenant_id.as_str())];

    let first = h.request_with("POST", PATH, &headers, Some(json!({"name":"before","scopes":["assets:read"]}))).await;
    assert_eq!(first.status, StatusCode::CREATED, "{}", first.text);
    let id = first.json()["api_key"]["id"].as_str().unwrap().to_owned();
    let before = h.state.store.api_key_list_durable(tenant.id).await.unwrap();
    assert_eq!(before.len(), 1);
    assert!(!before[0].revoked);
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    let chain = AuditRepo::chain_stats(&mut tx).await.unwrap();
    tx.commit().await.unwrap();

    let constraint = format!("agf_test_key_audit_{}", Id::new().as_uuid().simple());
    sqlx::query(&format!(
        "ALTER TABLE audit_logs ADD CONSTRAINT {constraint} CHECK (tenant_id <> '{}'::uuid) NOT VALID",
        tenant.id
    ))
    .execute(&pool)
    .await
    .unwrap();
    let failed_issue =
        h.request_with("POST", PATH, &headers, Some(json!({"name":"ghost","scopes":["assets:read"]}))).await;
    assert!(!failed_issue.status.is_success(), "{}", failed_issue.text);
    let failed_revoke = h.request_with("DELETE", &format!("{PATH}/{id}"), &headers, None).await;
    assert!(!failed_revoke.status.is_success(), "{}", failed_revoke.text);
    let after = h.state.store.api_key_list_durable(tenant.id).await.unwrap();
    assert_eq!(serde_json::to_value(after).unwrap(), serde_json::to_value(before).unwrap());
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    assert_eq!(AuditRepo::chain_stats(&mut tx).await.unwrap(), chain);
    tx.commit().await.unwrap();

    sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}")).execute(&pool).await.unwrap();
    let revoked = h.request_with("DELETE", &format!("{PATH}/{id}"), &headers, None).await;
    assert_eq!(revoked.status, StatusCode::OK, "{}", revoked.text);
    let after = h.state.store.api_key_list_durable(tenant.id).await.unwrap();
    assert_eq!(after.len(), 1);
    assert!(after[0].revoked);
    pool.close().await;
}
