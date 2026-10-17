//! Overview distinguishes unavailable metrics from real zero and reads the tenant model ledger.
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;
use agf_core::{enums::LlmProvider, ids::Id, model::UsageRecord};
use common::*;

fn kpi(body: &Value, key: &str) -> Value {
    body["kpis"].as_array().unwrap().iter().find(|row| row["key"] == key).unwrap().clone()
}

#[tokio::test]
async fn overview_metrics_are_observed_currency_correct_and_tenant_scoped() {
    let h = setup().await;
    let empty = h.get("/api/v1/overview").await.json();
    assert_eq!(kpi(&empty, "assets")["value"], 0.0);
    for key in ["tokenSpend", "redteamSuccessRate"] {
        assert!(kpi(&empty, key)["value"].is_null());
    }
    assert!(empty["kpis"].as_array().unwrap().iter().all(|row| row["delta"].is_null()));
    assert_eq!(empty["risk_trend"].as_array().unwrap().len(), 1);
    assert!(empty["adapter_health"].as_array().unwrap().iter().all(|row| row["uptime_percent"].is_null()));
    let mut row = UsageRecord {
        id: Id::new(),
        tenant_id: h.tenant,
        session_id: "fixture".into(),
        agent_id: None,
        endpoint_id: Id::new(),
        provider: LlmProvider::Ollama,
        model: "fixture".into(),
        prompt_tokens: 10,
        completion_tokens: 4,
        cached_tokens: 0,
        cache_write_tokens: 0,
        cache_write_1h_tokens: 0,
        cache_hit: false,
        cost_micro: 1_250_000,
        mocked: false,
        latency_ms: 10,
        at: Timestamp::now(),
    };
    h.state.configurations.put(h.tenant, agf_api::gateway_quota::USAGE, row.id, &row).await.unwrap();
    // Replaying the same durable usage record must not double-count it.
    h.state.configurations.put(h.tenant, agf_api::gateway_quota::USAGE, row.id, &row).await.unwrap();
    row.id = Id::new();
    row.mocked = true;
    row.cost_micro = 9_000_000;
    h.state.configurations.put(h.tenant, agf_api::gateway_quota::USAGE, row.id, &row).await.unwrap();
    row.id = Id::new();
    row.mocked = false;
    row.tenant_id = h.other_tenant;
    h.state.configurations.put(h.other_tenant, agf_api::gateway_quota::USAGE, row.id, &row).await.unwrap();
    let summary = h.get("/api/v1/overview").await.json();
    assert_eq!(kpi(&summary, "tokenSpend")["value"], 1.25);
    assert_eq!(kpi(&summary, "tokenSpend")["unit"], "common.unit.cny");
    assert!(summary["generated_at"].as_str().unwrap().ends_with('Z'));
    let viewer = h.request("GET", "/api/v1/overview", Some(&h.viewer), None).await.json();
    assert!(kpi(&viewer, "tokenSpend")["value"].is_null());
    assert_eq!(viewer["access"]["models"], false);
}
