//! Inbox bodies respect resource permissions; read markers belong to a person and tenant.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::ids::{Id, deterministic_id};
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use common::*;

async fn call(h: &Harness, token: &str, method: &str, path: &str, body: Option<Value>) -> Resp {
    h.request_with(
        method,
        path,
        &[("authorization", &format!("Bearer {token}")), ("x-agf-tenant", &h.tenant.to_string())],
        body,
    )
    .await
}
async fn seed(h: &Harness, subject: &str) -> Id {
    let dedup = Id::new().to_string();
    let id = deterministic_id("agf.notification-inbox", &dedup);
    h.state
        .configurations
        .put(
            h.tenant,
            "notification-inbox",
            id,
            &json!({"dedup_key":dedup,
        "subject_kind":subject,"subject_id":Id::new(),"tenant_id":h.tenant,"at":Timestamp::now(),
        "severity":"high","title":format!("{subject} notice"),"body":format!("private {subject} content")}),
        )
        .await
        .unwrap();
    id
}
async fn verify(h: &Harness) {
    let alert = seed(h, "alert").await;
    seed(h, "alert-escalation:1:1").await;
    let report = seed(h, "report").await;
    seed(h, "case").await;
    seed(h, "test").await;
    let path = "/api/v1/notifications/inbox";
    let admin = call(h, &h.admin, "GET", path, None).await;
    assert_eq!(admin.status, StatusCode::OK, "{}", admin.text);
    assert_eq!(admin.json().as_array().unwrap().len(), 5);
    let marked =
        call(h, &h.admin, "POST", "/api/v1/notifications/inbox/read", Some(json!({"ids":[alert,alert]}))).await;
    assert_eq!(marked.status, StatusCode::OK, "{}", marked.text);
    assert_eq!(marked.json()["marked"], 1);
    let repeated = call(h, &h.admin, "POST", "/api/v1/notifications/inbox/read", Some(json!({"ids":[alert]}))).await;
    assert_eq!(repeated.json()["marked"], 0);
    let seen = call(h, &h.admin, "GET", path, None).await.json();
    assert_eq!(seen.as_array().unwrap().iter().find(|r| r["id"] == alert.to_string()).unwrap()["read"], true);
    if h.tenant == TenantId::default_tenant() {
        let viewer = call(h, &h.viewer, "GET", path, None).await.json();
        assert_eq!(viewer.as_array().unwrap().iter().find(|r| r["id"] == alert.to_string()).unwrap()["read"], false);
    }
    let key = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("alerts:read")],
        ..ApiKeyIssueRequest::named(h.tenant, "alert inbox reader", Timestamp::now())
    });
    h.state.store.api_key_create_durable(&key.record).await.unwrap();
    let reader = h.request_with("GET", path, &[("x-agf-key", &key.plaintext)], None).await;
    let rows = reader.json();
    assert_eq!(reader.status, StatusCode::OK, "{}", reader.text);
    assert_eq!(rows.as_array().unwrap().len(), 2);
    assert!(rows.as_array().unwrap().iter().all(|r| r["can_mark"] == false && r["id"] != report.to_string()));
    assert_eq!(
        h.request_with(
            "POST",
            "/api/v1/notifications/inbox/read",
            &[("x-agf-key", &key.plaintext)],
            Some(json!({"ids":[alert]}))
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(h, &h.admin, "POST", "/api/v1/notifications/inbox/read", Some(json!({"ids":[Id::new()]}))).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(h, &h.admin, "POST", "/api/v1/notifications/inbox/read", Some(json!({"ids":[]}))).await.status,
        StatusCode::BAD_REQUEST
    );
    // Apply ACL before the 100-row limit; many newer reports must not hide older readable alerts.
    for _ in 0..101 {
        seed(h, "report").await;
    }
    assert_eq!(call(h, &h.admin, "GET", path, None).await.json().as_array().unwrap().len(), 100);
    assert_eq!(
        h.request_with("GET", path, &[("x-agf-key", &key.plaintext)], None).await.json().as_array().unwrap().len(),
        2
    );
}

#[tokio::test]
async fn inbox_reads_are_personal_and_permission_scoped() {
    verify(&setup().await).await;
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn sql_inbox_reads_survive_new_instances_and_filter_before_limit() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let database =
        Database::from_pool(sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap());
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::ApiStore::with_database(store.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(store.clone())));
    let mut tenant = agf_api::tenant_directory::new(format!("inbox-{}", Id::new()), "Inbox verification".into());
    h.tenant = tenant.id;
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.app = build_router(h.state.clone());
    verify(&h).await;
    let fresh = seed(&h, "alert").await;
    assert_eq!(
        call(&h, &h.admin, "POST", "/api/v1/notifications/inbox/read", Some(json!({"ids":[fresh]}))).await.status,
        StatusCode::OK
    );
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(store.clone())));
    h.app = build_router(h.state.clone());
    let rows = call(&h, &h.admin, "GET", "/api/v1/notifications/inbox", None).await.json();
    assert_eq!(rows.as_array().unwrap().iter().find(|r| r["id"] == fresh.to_string()).unwrap()["read"], true);
    let mut tx = store.db().begin_tenant(TenantId::new()).await.unwrap();
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM console_configurations WHERE kind='notification-inbox-reads'")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(count, 0);
    tx.commit().await.unwrap();
    tenant.enabled = false;
    agf_api::tenant_directory::save(&h.state, tenant, false).await.unwrap();
}
