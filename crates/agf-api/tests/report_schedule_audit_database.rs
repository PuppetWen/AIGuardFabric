//! Report schedule writes and their success audits must commit together.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::{report_service::SCHEDULES, tenant_directory};
use agf_core::ids::Id;
use agf_storage::{AuditRepo, Database, Store, objectstore::MemoryObjectStore};
use common::*;

const PATH: &str = "/api/v1/reports/schedules";

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn schedule_changes_roll_back_when_audit_fails() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap();
    let database = Database::from_pool(pool.clone());
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(store)));
    let tenant = tenant_directory::new(format!("report-audit-{}", Id::new()), "Report audit test".into());
    tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.app = build_router(h.state.clone());
    let token = format!("Bearer {}", h.admin);
    let tenant_id = tenant.id.to_string();
    let headers = [("authorization", token.as_str()), ("x-agf-tenant", tenant_id.as_str())];

    let created = h.request_with("POST", PATH, &headers, Some(json!({"name":"before","cron":"0 0 * * *"}))).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let row = created.json()["schedule"].clone();
    let id = Id::parse(row["id"].as_str().unwrap()).unwrap();
    let edit_path = format!("{PATH}/{id}");
    let before: Value = h.state.configurations.get(tenant.id, SCHEDULES, id).await.unwrap().unwrap();
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    let chain = AuditRepo::chain_stats(&mut tx).await.unwrap();
    tx.commit().await.unwrap();

    let constraint = format!("agf_test_report_audit_{}", Id::new().as_uuid().simple());
    sqlx::query(&format!(
        "ALTER TABLE audit_logs ADD CONSTRAINT {constraint} CHECK (tenant_id <> '{}'::uuid) NOT VALID",
        tenant.id
    ))
    .execute(&pool)
    .await
    .unwrap();
    let attempts = [
        ("POST", PATH.to_string(), Some(json!({"name":"ghost","cron":"0 0 * * *"}))),
        ("PATCH", edit_path.clone(), Some(json!({"name":"after","expected_version":1}))),
        ("DELETE", format!("{edit_path}?expected_version=1"), None),
    ];
    for (method, path, body) in attempts {
        let failed = h.request_with(method, &path, &headers, body).await;
        assert!(!failed.status.is_success(), "{method} {path}: {}", failed.text);
        let stored: Value = h.state.configurations.get(tenant.id, SCHEDULES, id).await.unwrap().unwrap();
        assert_eq!(stored, before, "{method} changed the plan without an audit");
        let list = h.request_with("GET", PATH, &headers, None).await.json();
        assert_eq!(list["total"], 1, "{method} created or deleted a plan");
        let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
        assert_eq!(AuditRepo::chain_stats(&mut tx).await.unwrap(), chain);
        tx.commit().await.unwrap();
    }
    sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}")).execute(&pool).await.unwrap();
    let updated =
        h.request_with("PATCH", &edit_path, &headers, Some(json!({"name":"after","expected_version":1}))).await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.text);
    assert_eq!(updated.json()["version"], 2);
    let deleted = h.request_with("DELETE", &format!("{edit_path}?expected_version=2"), &headers, None).await;
    assert_eq!(deleted.status, StatusCode::OK, "{}", deleted.text);
    assert_eq!(h.request_with("GET", PATH, &headers, None).await.json()["total"], 0);
    pool.close().await;
}
