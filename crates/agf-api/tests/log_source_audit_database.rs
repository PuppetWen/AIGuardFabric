//! Source configuration and its success audit must commit or roll back together.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::source_store::{self, KIND, Record};
use agf_core::ids::Id;
use agf_storage::{AuditRepo, Database, Store, objectstore::MemoryObjectStore};
use common::*;

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn source_changes_roll_back_when_success_audit_cannot_commit() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap();
    let database = Database::from_pool(pool.clone());
    database.migrate().await.unwrap();
    let database = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(database.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(database.clone())));
    let tenant =
        agf_api::tenant_directory::new(format!("source-sql-{}", TenantId::new()), "Source SQL validation".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.app = build_router(h.state.clone());
    let token = format!("Bearer {}", h.admin);
    let tenant_id = tenant.id.to_string();
    let headers = [("authorization", token.as_str()), ("x-agf-tenant", tenant_id.as_str())];
    let created = h
        .request_with(
            "POST",
            "/api/v1/ingest/sources",
            &headers,
            Some(json!({"name":"atomic source","protocol":"http-webhook"})),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let id = Id::parse(created.json()["id"].as_str().unwrap()).unwrap();
    let path = format!("/api/v1/ingest/sources/{id}");
    let toggle = h.request_with("PATCH", &path, &headers, Some(json!({"enabled":false}))).await;
    assert_eq!(toggle.status, StatusCode::OK, "{}", toggle.text);
    let updated = h
        .request_with(
            "PUT",
            &path,
            &headers,
            Some(json!({"name":"renamed source","protocol":"http-webhook","enabled":false})),
        )
        .await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.text);
    let before = source_store::load(&h.state, tenant.id, id).await.unwrap();
    assert_eq!(before.source.as_ref().unwrap().name, "renamed source");
    assert!(!before.source.as_ref().unwrap().enabled);
    let mut tx = database.db().begin_tenant(tenant.id).await.unwrap();
    let audit_before = AuditRepo::chain_stats(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    let config_before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM console_configurations WHERE tenant_id=$1 AND kind=$2 AND deleted_at IS NULL",
    )
    .bind(tenant.id.as_uuid())
    .bind(KIND)
    .fetch_one(&pool)
    .await
    .unwrap();
    let constraint = format!("agf_test_source_audit_{}", Id::new().as_uuid().simple());
    let create = format!(
        "ALTER TABLE audit_logs ADD CONSTRAINT {constraint} CHECK (tenant_id <> '{}'::uuid) NOT VALID",
        tenant.id
    );
    sqlx::query(&create).execute(&pool).await.unwrap();
    let rejected_toggle = h.request_with("PATCH", &path, &headers, Some(json!({"enabled":true}))).await;
    let rejected_update = h
        .request_with("PUT", &path, &headers, Some(json!({"name":"should roll back","protocol":"http-webhook"})))
        .await;
    let rejected_delete = h.request_with("DELETE", &path, &headers, None).await;
    let rejected_create = h
        .request_with(
            "POST",
            "/api/v1/ingest/sources",
            &headers,
            Some(json!({"name":"should not exist","protocol":"http-webhook"})),
        )
        .await;
    for response in [&rejected_toggle, &rejected_update, &rejected_delete, &rejected_create] {
        assert!(!response.status.is_success(), "audit failure cannot report success: {}", response.text);
    }
    sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}")).execute(&pool).await.unwrap();
    let after: Record = source_store::load(&h.state, tenant.id, id).await.unwrap();
    assert_eq!(after.source.as_ref().unwrap().name, "renamed source");
    assert!(!after.source.as_ref().unwrap().enabled);
    let config_after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM console_configurations WHERE tenant_id=$1 AND kind=$2 AND deleted_at IS NULL",
    )
    .bind(tenant.id.as_uuid())
    .bind(KIND)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(config_after, config_before, "failed create must not leave a source row");
    let mut tx = database.db().begin_tenant(tenant.id).await.unwrap();
    assert_eq!(AuditRepo::chain_stats(&mut tx).await.unwrap(), audit_before);
    tx.commit().await.unwrap();
    let deleted = h.request_with("DELETE", &path, &headers, None).await;
    assert_eq!(deleted.status, StatusCode::OK, "{}", deleted.text);
    assert!(source_store::load(&h.state, tenant.id, id).await.is_err());
    pool.close().await;
}
