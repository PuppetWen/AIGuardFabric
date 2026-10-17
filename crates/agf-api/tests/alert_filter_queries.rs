//! Alert filters and ordering apply before pagination and share SQL/offline semantics.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::ids::Id;
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use common::*;

async fn call(h: &Harness, method: &str, path: &str, body: Option<Value>) -> Resp {
    h.request_with(
        method,
        path,
        &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &h.tenant.to_string())],
        body,
    )
    .await
}
async fn verify(h: &Harness) {
    for n in 0..24 {
        let (severity, domain) = if n % 2 == 0 { ("high", "credential-leak") } else { ("low", "tool-abuse") };
        let r = call(
            h,
            "POST",
            "/api/v1/alerts",
            Some(json!({"title":format!("selection-{n:02}"),"severity":severity,"domain":domain})),
        )
        .await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.text);
    }
    let path = "/api/v1/alerts?severity=high&domain=credential-leak&state=open,acknowledged&page_size=5&sort=title";
    let first = call(h, "GET", path, None).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    assert_eq!(first.json()["total"], 12);
    assert_eq!(first.json()["items"].as_array().unwrap().len(), 5);
    assert_eq!(first.json()["items"][0]["title"], "selection-00");
    let second = call(h, "GET", &format!("{path}&page=2"), None).await.json();
    assert_eq!(second["items"][0]["title"], "selection-10");
    let last = call(h, "GET", &format!("{path}&page=3"), None).await.json();
    assert_eq!(last["items"].as_array().unwrap().len(), 2);
    assert_eq!(last["items"][1]["title"], "selection-22");
    assert_eq!(
        call(
            h,
            "GET",
            "/api/v1/alerts?severity=high,low&domain=credential-leak,tool-abuse&page_size=1&sort=-severity",
            None
        )
        .await
        .json()["items"][0]["severity"],
        "high"
    );
    let id = first.json()["items"][0]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        call(h, "POST", &format!("/api/v1/alerts/{id}/status"), Some(json!({"status":"resolved"}))).await.status,
        StatusCode::OK
    );
    assert_eq!(call(h, "GET", &format!("/api/v1/alerts?q={id}&state=closed"), None).await.json()["total"], 1);
    assert_eq!(call(h, "GET", &format!("/api/v1/alerts?q={id}&active=true"), None).await.json()["total"], 0);
    for filter in ["severity=invalid", "state=closed,invalid", "domain=invalid", "sort=invalid"] {
        assert_eq!(call(h, "GET", &format!("/api/v1/alerts?{filter}"), None).await.status, StatusCode::BAD_REQUEST);
    }
    h.state.store.alert_set_sla_durable(h.tenant, Id::parse(&id).unwrap(), None, false, 0, None).await.unwrap();
    for sort in ["sla_due_at", "-sla_due_at"] {
        let sorted = call(h, "GET", &format!("/api/v1/alerts?sort={sort}&page_size=200"), None).await.json();
        assert_eq!(
            sorted["items"].as_array().unwrap().last().unwrap()["id"],
            id,
            "missing deadlines stay last: {sort}"
        );
    }
    let updated = call(h, "GET", "/api/v1/alerts?sort=-updated_at&page_size=1", None).await.json();
    assert_eq!(updated["items"][0]["id"], id, "actual modification time controls updated_at ordering");
    let key = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("alerts:read")],
        ..ApiKeyIssueRequest::named(h.tenant, "read-only", Timestamp::now())
    });
    h.state.store.api_key_create_durable(&key.record).await.unwrap();
    let list = h.request_with("GET", "/api/v1/alerts", &[("x-agf-key", &key.plaintext)], None).await;
    assert_eq!(list.json()["can_write"], false);
    assert_eq!(
        h.request_with(
            "POST",
            &format!("/api/v1/alerts/{id}/status"),
            &[("x-agf-key", &key.plaintext)],
            Some(json!({"status":"open"}))
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
}
#[tokio::test]
async fn alert_selections_work_across_pages() {
    verify(&setup().await).await;
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn sql_alert_selections_work_across_pages() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let database =
        Database::from_pool(sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap());
    database.migrate().await.unwrap();
    let db = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::ApiStore::with_database(db.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db)));
    let tenant =
        agf_api::tenant_directory::new(format!("alert-selection-{}", Id::new()), "Alert selection tests".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.tenant = tenant.id;
    h.app = build_router(h.state.clone());
    verify(&h).await;
}
