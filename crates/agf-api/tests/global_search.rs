//! Scoped search must not disclose unrelated resources, and links must resolve exactly.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{
    enums::{RiskDomain, Severity},
    ids::Id,
    risk::Finding,
};
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
async fn scoped(h: &Harness, scope: &str, q: &str) -> Resp {
    let key = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw(scope)],
        ..ApiKeyIssueRequest::named(h.tenant, "search-reader", Timestamp::now())
    });
    h.state.store.api_key_create_durable(&key.record).await.unwrap();
    h.request_with("GET", q, &[("x-agf-key", &key.plaintext)], None).await
}
async fn verify(h: &Harness) {
    let assets: Vec<_> = (0..12)
        .map(
            |n| json!({"fingerprint":format!("search-{n}"),"name":format!("globalneedle asset {n:02}"),"kind":"skill"}),
        )
        .collect();
    assert_eq!(
        call(h, "POST", "/api/v1/assets/discovery", Some(json!({"assets":assets}))).await.status,
        StatusCode::OK
    );
    let finding = Finding::new(
        h.tenant,
        RiskDomain::PromptAttack,
        Severity::High,
        "target",
        "globalneedle finding",
        "private summary",
        "fix",
    );
    h.state.store.finding_insert_durable(&finding).await.unwrap();
    let alert =
        call(h, "POST", "/api/v1/alerts", Some(json!({"title":"globalneedle alert","description":"sensitive alert"})))
            .await;
    assert_eq!(alert.status, StatusCode::CREATED, "{}", alert.text);
    let case = call(h, "POST", "/api/v1/cases", Some(json!({"title":"globalneedle case"}))).await;
    assert_eq!(case.status, StatusCode::CREATED, "{}", case.text);
    let builtin = h.state.rules.rules.first().unwrap();
    agf_api::rule_store::change(&h.state, h.tenant, &builtin.key, "test".into(), |old| {
        let mut r = old.unwrap();
        r.enabled = false;
        r.name = "globalneedle disabled rule".into();
        Ok(r)
    })
    .await
    .unwrap();
    let response = call(h, "GET", "/api/v1/search?q=GLOBALNEEDLE", None).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let hits = response.json();
    let hits = hits.as_array().unwrap();
    assert_eq!(hits.len(), 8);
    for kind in ["asset", "finding", "alert", "case", "rule"] {
        assert!(hits.iter().any(|r| r["kind"] == kind), "Missing {kind}: {hits:?}");
    }
    for (scope, kind) in [
        ("assets:read", "asset"),
        ("findings:read", "finding"),
        ("alerts:read", "alert"),
        ("cases:read", "case"),
        ("rules:read", "rule"),
    ] {
        let r = scoped(h, scope, "/api/v1/search?q=globalneedle").await;
        assert_eq!(r.status, StatusCode::OK, "{scope}: {}", r.text);
        let data = r.json();
        let data = data.as_array().unwrap();
        assert!(!data.is_empty());
        assert!(data.iter().all(|row| row["kind"] == kind), "{scope}: {data:?}");
    }
    assert_eq!(scoped(h, "sources:read", "/api/v1/search?q=globalneedle").await.status, StatusCode::FORBIDDEN);
    for hit in hits {
        let id = hit["id"].as_str().unwrap();
        let (detail, url) = match hit["kind"].as_str().unwrap() {
            "asset" => (format!("/api/v1/assets/{id}"), format!("/assets/{id}")),
            "finding" => (format!("/api/v1/findings/{id}"), format!("/findings?finding={id}")),
            "alert" => (format!("/api/v1/alerts/{id}"), format!("/alerts?alert={id}")),
            "case" => (format!("/api/v1/cases/{id}"), format!("/cases/{id}")),
            "rule" => (format!("/api/v1/rules/{id}"), format!("/rules?rule={id}")),
            _ => unreachable!(),
        };
        assert_eq!(hit["to"], url);
        assert_eq!(call(h, "GET", &detail, None).await.status, StatusCode::OK);
    }
    let exact = call(h, "GET", &format!("/api/v1/search?q={}&limit=1", finding.id), None).await;
    assert_eq!(exact.json()[0]["id"], finding.id.to_string());
    let key = &h.state.redteam_cases.cases().first().unwrap().key;
    assert_eq!(call(h, "GET", &format!("/api/v1/redteam/cases/{key}"), None).await.status, StatusCode::OK);
    let red = scoped(h, "redteam:read", &format!("/api/v1/search?q={key}")).await;
    assert_eq!(red.json()[0]["kind"], "redteam");
    assert!(red.json()[0]["to"].as_str().unwrap().contains("testCase="));
    for q in ["%25", "%5F", "no-such-search-value"] {
        assert_eq!(scoped(h, "assets:read", &format!("/api/v1/search?q={q}")).await.json(), json!([]));
    }
    for q in ["limit=0".into(), "limit=51".into(), "q=a%0Ab".into(), format!("q={}", "x".repeat(129))] {
        assert_eq!(call(h, "GET", &format!("/api/v1/search?{q}"), None).await.status, StatusCode::BAD_REQUEST);
    }
    assert_eq!(call(h, "GET", "/api/v1/search?q=", None).await.json(), json!([]));
}

#[tokio::test]
async fn search_respects_resource_permissions_and_links() {
    verify(&setup().await).await;
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn sql_search_filters_before_limit_and_preserves_tenant_boundaries() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let database =
        Database::from_pool(sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap());
    database.migrate().await.unwrap();
    let db = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::ApiStore::with_database(db.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
    let tenant = agf_api::tenant_directory::new(format!("search-{}", Id::new()), "Search tests".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.tenant = tenant.id;
    h.app = build_router(h.state.clone());
    verify(&h).await;
    // A fresh process cache must still find all SQL records.
    h.state.store = Arc::new(agf_api::ApiStore::with_database(db));
    h.app = build_router(h.state.clone());
    assert_eq!(
        call(&h, "GET", "/api/v1/search?q=globalneedle&limit=50", None).await.json().as_array().unwrap().len(),
        16
    );
    let other = agf_api::tenant_directory::new(format!("search-other-{}", Id::new()), "Other tenant".into());
    agf_api::tenant_directory::save(&h.state, other.clone(), true).await.unwrap();
    h.tenant = other.id;
    assert_eq!(call(&h, "GET", "/api/v1/search?q=globalneedle", None).await.json(), json!([]));
}
