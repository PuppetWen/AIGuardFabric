//! CNY compatibility, preserved pricing, mock separation and complete usage pagination.
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;
use agf_core::{enums::LlmProvider, ids::Id, model::UsageRecord};
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use common::*;

async fn verify(h: Harness, database: Option<Arc<Store>>) {
    let endpoint = Id::new();
    let agent = Id::new();
    let mut row = UsageRecord {
        id: Id::new(),
        tenant_id: h.tenant,
        session_id: "meter-validation".into(),
        agent_id: Some(agent),
        endpoint_id: endpoint,
        provider: LlmProvider::Ollama,
        model: "priced-model".into(),
        prompt_tokens: 100,
        completion_tokens: 20,
        cached_tokens: 0,
        cache_write_tokens: 3,
        cache_write_1h_tokens: 2,
        cache_hit: false,
        cost_micro: 1_250_000,
        mocked: false,
        latency_ms: 10,
        at: Timestamp::now(),
    };
    // Repeated persistence does not double-count a call; same endpoint/model can include mock runs.
    for index in 0..26 {
        row.id = Id::new();
        row.at = Timestamp::from_unix_secs(1_790_000_000 + index).unwrap();
        row.mocked = index == 25;
        row.cache_hit = index == 24;
        if row.mocked {
            row.cost_micro = 9_000_000;
        }
        h.state.configurations.put(h.tenant, agf_api::gateway_quota::USAGE, row.id, &row).await.unwrap();
        h.state.configurations.put(h.tenant, agf_api::gateway_quota::USAGE, row.id, &row).await.unwrap();
    }
    let root = "/api/v1/models/usage";
    let page1 = h.get(&format!("{root}?page=1&page_size=12")).await.json();
    let page3 = h.get(&format!("{root}?page=3&page_size=12")).await.json();
    assert_eq!(page1["total"], 26);
    assert_eq!(page1["items"].as_array().unwrap().len(), 12);
    assert_eq!(page3["items"].as_array().unwrap().len(), 2);
    assert_ne!(page1["items"][0]["id"], page3["items"][0]["id"]);
    assert_eq!(page1["items"][0]["mocked"], true);
    assert_eq!(page1["items"][1]["cache_hit"], true);
    assert_eq!(page1["items"][0]["cost_cny"], 9.0);
    assert_eq!(page1["items"][0]["cost_usd"], 9.0);
    assert_eq!(page1["items"][0]["currency"], "CNY");
    assert_eq!(page1["items"][0]["cache_write_tokens"], 3);
    assert_eq!(page1["items"][0]["cache_write_1h_tokens"], 2);
    let aggregates = h.get(&format!("{root}/aggregate")).await.json();
    let values = aggregates.as_array().unwrap();
    assert_eq!(values.len(), 2);
    let real = values.iter().find(|v| v["mocked"] == false).unwrap();
    assert_eq!(real["calls"], 25);
    assert_eq!(real["cost_cny"], 31.25);
    assert_eq!(real["currency"], "CNY");
    let other = h
        .request_with(
            "GET",
            root,
            &[("Authorization", &format!("Bearer {}", h.admin)), ("X-AGF-Tenant", &h.other_tenant.to_string())],
            None,
        )
        .await;
    assert_eq!(other.json()["total"], 0);

    // Old persisted budgets keep exactly their original numeric meaning.
    let policy_id = Id::new();
    let legacy = json!({"id":policy_id,"tenant_id":h.tenant,"name":"legacy-CNY",
        "primary_endpoint_id":endpoint,"fallback_endpoint_ids":[],"strategy":"priority",
        "weights":{},"budget_usd_per_day":12.5,"enabled":false});
    h.state.configurations.put(h.tenant, agf_api::model_routes::KIND, policy_id, &legacy).await.unwrap();
    let uri = format!("/api/v1/models/route-policies/{policy_id}");
    let list = h.get("/api/v1/models/route-policies").await.json();
    let old = list.as_array().unwrap().iter().find(|v| v["id"] == policy_id.to_string()).unwrap();
    assert_eq!(old["budget_cny_per_day"], 12.5);
    assert_eq!(old["budget_usd_per_day"], 12.5);
    assert_eq!(old["currency"], "CNY");
    let saved = h
        .request(
            "PUT",
            &uri,
            Some(&h.admin),
            Some(json!({"expectedVersion":0,"budgetCnyPerDay":3.25,"currency":"CNY"})),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.json()["budget_usd_per_day"], 3.25);
    for invalid in [
        json!({"budgetCnyPerDay":3,"budgetUsdPerDay":4}),
        json!({"budget_cny_per_day":-1}),
        json!({"budgetCnyPerDay":1_000_001}),
        json!({"currency":"USD"}),
    ] {
        assert_eq!(h.request("PUT", &uri, Some(&h.admin), Some(invalid)).await.status, StatusCode::BAD_REQUEST);
    }
    let raw: Value =
        h.state.configurations.get(h.tenant, agf_api::model_routes::KIND, policy_id).await.unwrap().unwrap();
    assert_eq!(raw["budget_cny_per_day"], 3.25);
    assert!(raw.get("budget_usd_per_day").is_none());
    if let Some(database) = database {
        let independent = agf_storage::configuration::ConfigStore::new(Some(database));
        let policy: agf_api::store::ModelRoutePolicy =
            independent.get(h.tenant, agf_api::model_routes::KIND, policy_id).await.unwrap().unwrap();
        assert_eq!(policy.budget_cny_per_day, 3.25);
        assert_eq!(independent.list::<UsageRecord>(h.tenant, agf_api::gateway_quota::USAGE).await.unwrap().len(), 26);
    }
}

#[tokio::test]
async fn currency_aliases_and_metering_are_consistent() {
    verify(setup().await, None).await;
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn sql_currency_and_budget_roundtrip() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let database =
        Database::from_pool(sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap());
    database.migrate().await.unwrap();
    let db = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
    let tenant = agf_api::tenant_directory::new(format!("model-cost-{}", Id::new()), "Model cost validation".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    let other = agf_api::tenant_directory::new(format!("model-other-{}", Id::new()), "Other model validation".into());
    agf_api::tenant_directory::save(&h.state, other.clone(), true).await.unwrap();
    h.other_tenant = other.id;
    // Harness auth belongs to default; superadmin selects the isolated tenant via request wrapper below.
    h.tenant = tenant.id;
    h.app = build_router(h.state.clone()).layer(axum::middleware::from_fn(
        move |mut request: axum::extract::Request, next: axum::middleware::Next| async move {
            if !request.headers().contains_key("X-AGF-Tenant") {
                request.headers_mut().insert("X-AGF-Tenant", tenant.id.to_string().parse().unwrap());
            }
            next.run(request).await
        },
    ));
    verify(h, Some(db)).await;
}

#[tokio::test]
async fn editing_an_endpoint_without_prices_preserves_rates_and_capabilities() {
    let h = setup().await;
    let body = json!({"name":"pricing-test","provider":"mock","model":"pricing-fixture",
        "base_url":"http://mock.invalid/v1","supports_streaming":false,"supports_tools":false,
        "priority":17,"pricing":{"prompt_micro_per_1k":1_250_001,"completion_micro_per_1k":3_500_000,
        "cached_prompt_micro_per_1k":250_000}});
    let created = h.post("/api/v1/gateway/endpoints", body).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let id = created.json()["id"].as_str().unwrap().to_string();
    let update = json!({"name":"renamed","provider":"mock","model":"pricing-fixture","base_url":"http://mock.invalid/v1","expected_version":created.json()["version"]});
    let saved = h.request("PUT", &format!("/api/v1/gateway/endpoints/{id}"), Some(&h.admin), Some(update)).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    for key in ["pricing", "supports_streaming", "supports_tools", "priority"] {
        assert_eq!(saved.json()[key], created.json()[key], "{key}");
    }
    let key = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":"model-reader","scopes":["models:read"],"expires_in_secs":3600}),
        )
        .await
        .json();
    let token = key["plaintext"].as_str().unwrap();
    assert_eq!(h.request("GET", "/api/v1/models/usage", Some(token), None).await.status, StatusCode::OK);
    assert_eq!(
        h.request("POST", "/api/v1/models/route-policies", Some(token), Some(json!({}))).await.status,
        StatusCode::FORBIDDEN
    );
}
