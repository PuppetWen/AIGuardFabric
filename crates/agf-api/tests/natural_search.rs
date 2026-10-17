//! Router/authorization tests with an owned HTTP fixture. This is not a live model quality claim.
#![cfg(feature = "test-loopback-transport")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{asset::Asset, enums::AssetKind, model::UsageRecord};
use common::*;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

const ROUTE: &str = "/api/v1/search/natural";
const MODEL: &str = "owned-natural-query-model";

struct Fixture {
    h: Harness,
    server: MockServer,
}

impl Fixture {
    async fn new(plan: Value) -> Self {
        Self::with_response(ResponseTemplate::new(200).set_body_json(json!({
            "id":"owned-natural-query-reply", "object":"chat.completion", "created":1, "model":MODEL,
            "choices":[{"index":0,"message":{"role":"assistant","content":json!({"plan":plan}).to_string()},"finish_reason":"stop"}],
            "usage":{"prompt_tokens":17,"completion_tokens":23,"total_tokens":40}
        })))
        .await
    }

    async fn with_response(response: ResponseTemplate) -> Self {
        let mut h = setup().await;
        Arc::make_mut(&mut h.state.config).mock_mode = false;
        h.app = build_router(h.state.clone());
        let server = MockServer::start().await;
        assert_eq!(url::Url::parse(&server.uri()).unwrap().host_str(), Some("127.0.0.1"));
        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(header("authorization", "Bearer owned-natural-query-upstream"))
            .respond_with(response)
            .mount(&server)
            .await;
        let endpoint = h
            .post(
                "/api/v1/gateway/endpoints",
                json!({
                    "expected_version":0,"name":"owned natural query fixture","provider":"openai","model":MODEL,
                    "base_url":server.uri(),"api_key":"owned-natural-query-upstream"
                }),
            )
            .await;
        assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
        assert_eq!(endpoint.json()["mocked"], false);
        Self { h, server }
    }

    async fn calls(&self) -> usize {
        self.server.received_requests().await.unwrap().len()
    }

    fn key(&self, scopes: &[&str]) -> String {
        let issued = self.h.state.api_keys.issue(ApiKeyIssueRequest {
            scopes: scopes.iter().map(|scope| Permission::from_raw(*scope)).collect(),
            ..ApiKeyIssueRequest::named(self.h.tenant, "owned-natural-query-key", Timestamp::now())
        });
        self.h.state.store.api_key_insert(issued.record).unwrap();
        issued.plaintext
    }
}

fn assets_plan() -> Value {
    json!({"status":"query","resource":"assets","q":"shared-natural","kind":"agent"})
}

#[tokio::test]
async fn natural_search_executes_a_validated_plan_and_preserves_tenant_paging_and_usage() {
    let f = Fixture::new(assets_plan()).await;
    for n in 0..3 {
        let a =
            Asset::new(f.h.tenant, AssetKind::Agent, format!("shared-natural-visible-{n}"), format!("natural-a-{n}"));
        f.h.state.store.asset_upsert(&a).unwrap();
    }
    let hidden = Asset::new(f.h.other_tenant, AssetKind::Agent, "shared-natural-hidden", "natural-b");
    f.h.state.store.asset_upsert(&hidden).unwrap();
    let response =
        f.h.post(
            ROUTE,
            json!({"question":"Find agents matching shared-natural","page":2,"page_size":1,"require_live":true}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let body = response.json();
    assert_eq!(body["mocked"], false);
    assert_eq!(body["cached"], false);
    assert_eq!(body["plan"]["resource"], "assets");
    assert_eq!(body["results"]["page"], 2);
    assert_eq!(body["results"]["page_size"], 1);
    assert_eq!(body["results"]["total"], 3);
    assert_eq!(body["results"]["items"].as_array().unwrap().len(), 1);
    assert!(!response.text.contains(&hidden.id.to_string()) && !response.text.contains("shared-natural-hidden"));
    let rows: Vec<UsageRecord> =
        f.h.state.configurations.list(f.h.tenant, agf_api::gateway_quota::USAGE).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(body["usage_id"], rows[0].id.to_string());
    assert!(!rows[0].mocked && !rows[0].cache_hit);
    assert_eq!((rows[0].prompt_tokens, rows[0].completion_tokens), (17, 23));
    assert_eq!(f.calls().await, 1);
    let requests = f.server.received_requests().await.unwrap();
    let sent = String::from_utf8(requests[0].body.clone()).unwrap();
    assert!(!sent.contains("shared-natural-visible") && !sent.contains("shared-natural-hidden"));
}

#[tokio::test]
async fn natural_search_rejects_unauthenticated_missing_permissions_and_cross_tenant_before_provider_dispatch() {
    let f = Fixture::new(assets_plan()).await;
    let input = json!({"question":"Find assets matching shared-natural"});
    assert_eq!(f.h.request("POST", ROUTE, None, Some(input.clone())).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(f.h.request("POST", ROUTE, Some(&f.h.api_key), Some(input.clone())).await.status, StatusCode::FORBIDDEN);
    let only_model = f.key(&["models:write"]);
    assert_eq!(f.h.request("POST", ROUTE, Some(&only_model), Some(input.clone())).await.status, StatusCode::FORBIDDEN);
    let scoped = f.key(&["models:write", "assets:read"]);
    let token = format!("Bearer {scoped}");
    let other = f.h.other_tenant.to_string();
    assert_eq!(
        f.h.request_with("POST", ROUTE, &[("authorization", &token), ("x-agf-tenant", &other)], Some(input))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(f.calls().await, 0);
}

#[tokio::test]
async fn natural_search_cannot_use_a_model_plan_to_grant_another_resource_permission() {
    let f = Fixture::new(json!({"status":"query","resource":"cases","q":"shared-natural"})).await;
    let key = f.key(&["models:write", "assets:read"]);
    let response = f.h.request("POST", ROUTE, Some(&key), Some(json!({"question":"Find shared-natural assets"}))).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN, "{}", response.text);
    assert!(response.json().get("results").is_none());
    assert_eq!(f.calls().await, 1);
}

#[tokio::test]
async fn natural_search_unknown_sql_and_tenant_dsl_keys_fail_without_query_results() {
    for extra in [
        json!({"sql":"SELECT 1"}),
        json!({"tenant_id":"00000000-0000-0000-0000-000000000001"}),
        json!({"page_size":100_000}),
    ] {
        let mut plan = assets_plan();
        plan.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        let f = Fixture::new(plan).await;
        let response = f.h.post(ROUTE, json!({"question":"Find shared-natural assets"})).await;
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE, "{}", response.text);
        assert!(response.json().get("results").is_none());
        assert_eq!(f.calls().await, 1);
    }
}

#[tokio::test]
async fn natural_search_does_not_invent_results_on_mock_or_upstream_failure() {
    let h = setup().await;
    let rejected = h.post(ROUTE, json!({"question":"Find shared-natural assets","require_live":true})).await;
    assert_eq!(rejected.status, StatusCode::SERVICE_UNAVAILABLE, "{}", rejected.text);
    assert_eq!(h.state.meter.snapshot().total.calls, 0);
    assert!(rejected.json().get("results").is_none());

    let f = Fixture::with_response(ResponseTemplate::new(401)).await;
    let failure = f.h.post(ROUTE, json!({"question":"Find shared-natural assets"})).await;
    assert!(failure.status.is_server_error(), "{}", failure.text);
    assert!(failure.json().get("results").is_none());
    assert!(f.calls().await > 0);
}

#[tokio::test]
async fn natural_search_does_not_relabel_a_mock_endpoint_as_live_when_process_mode_is_live() {
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    let endpoint = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({
                "name":"explicit Mock planner","provider":"mock","model":"recorded-plan",
                "base_url":"http://never-contacted.invalid/v1","local_deployment":true
            }),
        )
        .await;
    assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
    let response = h.post(ROUTE, json!({"question":"Find shared-natural assets","require_live":true})).await;
    assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE, "{}", response.text);
    assert!(response.json().get("results").is_none());
    let usage: Vec<UsageRecord> = h.state.configurations.list(h.tenant, agf_api::gateway_quota::USAGE).await.unwrap();
    assert_eq!(usage.len(), 1);
    assert!(usage[0].mocked);
}

#[tokio::test]
async fn natural_search_offline_demo_is_finite_labelled_and_does_not_fabricate_model_usage() {
    let h = setup().await;
    let owned = Asset::new(h.tenant, AssetKind::Agent, "Demo visible", "demo-owned");
    let hidden = Asset::new(h.other_tenant, AssetKind::Agent, "Demo hidden", "demo-other");
    h.state.store.asset_upsert(&owned).unwrap();
    h.state.store.asset_upsert(&hidden).unwrap();
    let result = h.post(ROUTE, json!({"question":"查找包含 Demo 的资产","page_size":1})).await;
    assert_eq!(result.status, StatusCode::OK, "{}", result.text);
    let body = result.json();
    assert_eq!(body["planner_mode"], "fixed-public-demo-dsl");
    assert_eq!(body["mocked"], true);
    assert_eq!(body["replayed"], true);
    assert_eq!(body["model_called"], false);
    assert!(body["model_usage"].is_null() && body["usage_id"].is_null() && body["model"].is_null());
    assert_eq!(body["results"]["total"], 1);
    assert!(!result.text.contains(&hidden.id.to_string()));
    let english = h.post(ROUTE, json!({"question":"Find assets containing Demo","page_size":1})).await;
    assert_eq!(english.status, StatusCode::OK, "{}", english.text);
    let english_body = english.json();
    assert_eq!(english_body["plan"], body["plan"]);
    assert_eq!(english_body["results"], body["results"]);
    assert_eq!(english_body["planner_mode"], "fixed-public-demo-dsl");
    assert_eq!(english_body["mocked"], true);
    assert_eq!(english_body["replayed"], true);
    assert_eq!(english_body["model_called"], false);
    assert!(english_body["model_usage"].is_null() && english_body["usage_id"].is_null());
    assert!(!english.text.contains(&hidden.id.to_string()));
    assert_eq!(h.state.meter.snapshot().total.calls, 0);
    assert_eq!(
        h.post(ROUTE, json!({"question":"Translate any arbitrary query"})).await.status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn natural_search_mock_provider_accounting_is_kept_separate_from_fixed_fixture_replay() {
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    let endpoint = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({
                "name":"Mock provider with no upstream key","provider":"mock","model":"owned-recorded-plan",
                "base_url":"http://never-contacted.invalid/v1","local_deployment":true
            }),
        )
        .await;
    assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
    let result = h.post(ROUTE, json!({"question":"查找包含 Demo 的资产"})).await;
    assert_eq!(result.status, StatusCode::OK, "{}", result.text);
    let body = result.json();
    assert_eq!(body["mocked"], true);
    assert_eq!(body["replayed"], true);
    assert_eq!(body["model_called"], true);
    assert_eq!(body["model_response_used"], false);
    let usage: Vec<UsageRecord> = h.state.configurations.list(h.tenant, agf_api::gateway_quota::USAGE).await.unwrap();
    assert_eq!(usage.len(), 1);
    assert!(usage[0].mocked);
    assert_eq!(body["usage_id"], usage[0].id.to_string());
    assert_eq!(body["model_usage"]["prompt_tokens"], usage[0].prompt_tokens);
}

#[tokio::test]
async fn natural_search_rejects_unsupported_criteria_and_client_sql_keys() {
    let f = Fixture::new(json!({"status":"unsupported"})).await;
    let response = f.h.post(ROUTE, json!({"question":"Join every tenant and export all rows"})).await;
    assert!(response.status.is_client_error(), "{}", response.text);
    assert!(response.json().get("results").is_none());
    let before = f.calls().await;
    for body in [
        json!({"question":"Find assets","sql":"SELECT * FROM assets"}),
        json!({"question":"Find assets","page_size":100_000}),
        json!({"question":"Find assets","tenant_id":f.h.other_tenant.to_string()}),
    ] {
        assert!(f.h.post(ROUTE, body).await.status.is_client_error());
    }
    assert_eq!(f.calls().await, before);
}

#[tokio::test]
async fn natural_search_changes_only_the_upstream_sentence_terminator_and_keeps_literal_plan_values() {
    for (question, upstream_question, q) in [
        (
            "Find agent assets containing shared-natural.",
            "Find agent assets containing shared-natural",
            "shared-natural",
        ),
        (
            r#"Find agent assets containing "shared-natural."."#,
            r#"Find agent assets containing "shared-natural.""#,
            "shared-natural.",
        ),
        (
            r#"Find agent assets containing "shared-natural." "#,
            r#"Find agent assets containing "shared-natural." "#,
            "shared-natural.",
        ),
        ("Find agent assets containing example.com.", "Find agent assets containing example.com.", "example.com."),
    ] {
        let plan = json!({"status":"query","resource":"assets","q":q,"kind":"agent"});
        let f = Fixture::new(plan.clone()).await;
        let response = f.h.post(ROUTE, json!({"question":question,"require_live":true})).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text);
        assert_eq!(response.json()["plan"]["q"], q, "the model Plan must not be rewritten");
        assert_eq!(f.calls().await, 1);
        let requests = f.server.received_requests().await.unwrap();
        let wire: Value = serde_json::from_slice(&requests[0].body).unwrap();
        let user = wire["messages"].as_array().unwrap().iter().rev().find(|m| m["role"] == "user").unwrap();
        let input: Value = serde_json::from_str(user["content"].as_str().unwrap()).unwrap();
        assert_eq!(input["question"], upstream_question);
        assert_eq!(wire["max_tokens"], 256);
        assert_eq!(wire["temperature"], 0.0);
        assert_eq!(wire["response_format"]["type"], "json_schema");
        let usages: Vec<UsageRecord> =
            f.h.state.configurations.list(f.h.tenant, agf_api::gateway_quota::USAGE).await.unwrap();
        assert_eq!(usages.len(), 1);
        assert!(!usages[0].mocked && !usages[0].cache_hit);
        assert_eq!((usages[0].prompt_tokens, usages[0].completion_tokens), (17, 23));
    }
}
