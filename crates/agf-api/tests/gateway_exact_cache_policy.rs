//! Current signed request policy still governs an exact hit. Owned loopback only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod policy_publication_support;
use common::*;
use policy_publication_support::loopback::Fixture;
use policy_publication_support::*;

#[tokio::test]
async fn signed_deny_after_real_exact_prime_rejects_before_cache_delivery_or_provider_dispatch() {
    let fixture = Fixture::attach(setup().await).await;
    let policy = create(&fixture.h, "owned-exact-cache-current-policy", "allow").await;
    let body = json!({"model":"owned-policy-model","temperature":0,"max_tokens":4,
        "messages":[{"role":"user","content":"hello owned policy"}]});
    let first = fixture.h.post("/v1/chat/completions", body.clone()).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    assert_eq!(first.header("x-agf-mocked"), "false");
    assert_eq!(first.header("x-agf-cached"), "false");
    let second = fixture.h.post("/v1/chat/completions", body.clone()).await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.text);
    assert_eq!(second.header("x-agf-cached"), "true");
    assert_eq!(second.json()["choices"][0]["message"]["content"], "owned response");
    assert_eq!(fixture.calls("/chat/completions").await, 1);
    let usage_count = fixture.h.state.meter.snapshot().total.calls;
    let changed = update(&fixture.h, &policy, "deny").await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    assert_signed(&fixture.h, &changed.json()["policy"]);
    assert_eq!(changed.json()["policy"]["version"], 2);
    let decisions_before: Vec<Value> =
        fixture.h.state.configurations.list(fixture.h.tenant, "runtime-interception").await.unwrap();

    let rejected = fixture.h.post("/v1/chat/completions", body).await;
    assert_eq!(rejected.status, StatusCode::FORBIDDEN, "{}", rejected.text);
    assert!(!rejected.text.contains("owned response"));
    assert_eq!(fixture.calls("/chat/completions").await, 1);
    assert_eq!(fixture.h.state.meter.snapshot().total.calls, usage_count);
    let decisions: Vec<Value> =
        fixture.h.state.configurations.list(fixture.h.tenant, "runtime-interception").await.unwrap();
    assert_eq!(decisions.len(), decisions_before.len() + 1);
    assert!(decisions.iter().any(|row| row["policy_name"] == policy["name"] && row["action"] == "deny"));
    intact_chain(&fixture.h).await;
    // Rejection-chain publication is the separate WP7 C slice, not claimed here.
}

#[tokio::test]
async fn positive_pricing_mock_http_records_zero_in_usage_aggregate_and_both_cost_ledgers() {
    let h = setup().await;
    let quota = h
        .post(
            "/api/v1/quotas",
            json!({"name":"owned-mock-cost","dimension":"cost",
        "scope":"tenant","window":"total","limit":1_000_000}),
        )
        .await;
    assert_eq!(quota.status, StatusCode::OK, "{}", quota.text);
    let quota_id = quota.json()["quota"]["id"].as_str().unwrap().to_string();
    let endpoint = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({"name":"owned-mock-positive-price",
        "provider":"mock","model":"owned-mock-cost","base_url":"http://never-contacted.invalid/v1",
        "local_deployment":true,"pricing":{"prompt_micro_per_1k":2000,
            "completion_micro_per_1k":8000,"cached_prompt_micro_per_1k":500}}),
        )
        .await;
    assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
    let response = h
        .post(
            "/v1/chat/completions",
            json!({"model":"owned-mock-cost","max_tokens":1024,
        "messages":[{"role":"user","content":"analyze event"}]}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.header("x-agf-mocked"), "true");
    let logical_tokens = response.json()["usage"]["total_tokens"].as_u64().unwrap();
    assert!(logical_tokens > 0);
    let totals = h.state.meter.snapshot().total;
    assert_eq!(totals.cost_micro, 0);
    assert_eq!(totals.calls, 1);
    assert_eq!(totals.mocked_calls, 1);
    assert_eq!(totals.total_tokens(), logical_tokens);
    let stored: Vec<agf_core::model::UsageRecord> =
        h.state.configurations.list(h.tenant, agf_api::gateway_quota::USAGE).await.unwrap();
    assert_eq!(stored.len(), 1);
    assert!(stored[0].mocked);
    assert_eq!(stored[0].cost_micro, 0);
    assert_eq!(stored[0].total_tokens(), logical_tokens);
    let aggregate = h.get("/api/v1/models/usage/aggregate").await.json();
    assert_eq!(aggregate[0]["cost_cny"], 0.0);
    assert_eq!(aggregate[0]["mocked"], true);
    let ledger_id = agf_api::model_routes::tenant_record_id(h.tenant);
    let gateway: Value = h.state.configurations.get(h.tenant, "gateway-ledger", ledger_id).await.unwrap().unwrap();
    assert_eq!(gateway["totals"]["cost"], 0);
    assert_eq!(gateway["totals"]["tokens"], logical_tokens);
    let runtime: Value =
        h.state.configurations.get(h.tenant, "runtime-quota-ledger", ledger_id).await.unwrap().unwrap();
    let counters = runtime["counters"].as_object().unwrap();
    let cost = counters.iter().find(|(key, _)| key.starts_with(&format!("{quota_id}:"))).unwrap();
    assert_eq!(cost.1["used"], 0);
    // These are real router/config-store paths with a memory backend, not PostgreSQL evidence.
}
