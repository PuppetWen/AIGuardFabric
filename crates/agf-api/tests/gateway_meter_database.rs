//! Actual priced gateway costs in a dedicated PostgreSQL database and fresh API instances.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod agentteams_quota_scope_support;
mod common;
mod configuration_audit_support;
use agentteams_quota_scope_support::*;
use common::*;
use configuration_audit_support::SqlCase;

async fn owned_case(label: &str) -> SqlCase {
    let owner = std::env::var("AGF_GATEWAY_METER_DATABASE_OWNER").unwrap();
    let run = owner.strip_prefix("AIGuardFabric gateway meter SQL ").unwrap();
    assert!(run.len() == 32 && run.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    let expected = format!("agf_requirements_test_gateway_meter_{}", &run[..12]);
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert_eq!(url::Url::parse(&url).unwrap().path(), format!("/{expected}"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&url).await.unwrap();
    let actual: (String, Option<String>) = sqlx::query_as(
        "SELECT current_database(),shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(actual, (expected, Some(owner))); // Before migrations or fixture writes.
    pool.close().await;
    SqlCase::open(label).await
}

async fn ledger_cost(h: &Harness) -> u64 {
    let id = agf_api::model_routes::tenant_record_id(h.tenant);
    let value: Value = h.state.configurations.get(h.tenant, "gateway-ledger", id).await.unwrap().unwrap();
    assert!(value["reservations"].as_object().unwrap().is_empty());
    value["totals"]["cost"].as_u64().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a dedicated exact-owned gateway meter SQL database; no production/vendor access"]
async fn mock_positive_price_is_zero_in_durable_usage_and_both_ledgers_after_restart() {
    let case = owned_case("meter-mock").await;
    let h = &case.h;
    let cost_quota = quota(h, "tenant", "cost", "total", 1_000_000).await;
    let response = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({
                "name":"owned-positive-mock", "provider":"mock", "model":"owned-positive-mock",
                "base_url":"http://never-contacted.invalid/v1", "local_deployment":true,
                "pricing":{"prompt_micro_per_1k":2000,"completion_micro_per_1k":8000,
                    "cached_prompt_micro_per_1k":500}
            }),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
    let reply = h
        .post(
            "/v1/chat/completions",
            json!({
                "model":"owned-positive-mock", "max_tokens":1024,
                "messages":[{"role":"user","content":"analyze event"}]
            }),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
    assert_eq!(reply.header("x-agf-mocked"), "true");
    let logical_tokens = reply.json()["usage"]["total_tokens"].as_u64().unwrap();
    assert!(logical_tokens > 0);
    let restarted = case.second_instance().await;
    for instance in [h, &restarted] {
        let rows = agf_api::gateway_quota::usage(&instance.state, instance.tenant).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].cost_micro, 0);
        assert!(rows[0].mocked);
        assert_eq!(rows[0].total_tokens(), logical_tokens);
        assert_eq!(ledger_cost(instance).await, 0);
        assert_eq!(used(instance, &cost_quota).await, 0);
        assert_eq!(instance.get("/api/v1/models/usage/aggregate").await.json()[0]["cost_cny"], 0.0);
        assert!(instance.state.store.audit_verify_durable(instance.tenant).await.unwrap().passed);
    }
    let totals = h.state.meter.snapshot().total;
    assert_eq!(totals.calls, 1);
    assert_eq!(totals.mocked_calls, 1);
    assert_eq!(totals.cost_micro, 0);
    assert_eq!(totals.total_tokens(), logical_tokens);
    case.pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a dedicated exact-owned gateway meter SQL database; no production/vendor access"]
async fn actual_paid_then_exact_hit_persists_only_first_charge_and_two_requests() {
    let case = owned_case("meter-paid").await;
    let h = live(case.h.clone());
    let provider = Loopback::start().await;
    let identities = configure(&h, &provider).await;
    let cost_quota = quota(&h, "tenant", "cost", "total", 1_000_000).await;
    let request_quota = quota(&h, "tenant", "requests", "total", 10).await;
    let bearer = format!("Bearer {}", identities[0].key);
    let body = json!({"model":MODEL,"max_tokens":4,"temperature":0,
        "messages":[{"role":"user","content":"hello"}]});
    for cached in [false, true] {
        let response = h
            .request_with(
                "POST",
                "/v1/chat/completions",
                &[("authorization", bearer.as_str()), ("x-agf-session", "owned-meter-exact")],
                Some(body.clone()),
            )
            .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text);
        assert_eq!(response.header("x-agf-cached"), if cached { "true" } else { "false" });
        assert_eq!(response.header("x-agf-mocked"), "false");
        assert_eq!(response.json()["usage"]["total_tokens"], 100);
    }
    assert_eq!(provider.calls(), 1);
    let restarted = live(case.second_instance().await);
    for instance in [&h, &restarted] {
        let rows = agf_api::gateway_quota::usage(&instance.state, instance.tenant).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows.iter().filter(|row| row.cache_hit).count(), 1);
        assert!(rows.iter().all(|row| !row.mocked));
        assert_eq!(rows.iter().map(|row| row.cost_micro).sum::<u64>(), 100);
        assert!(rows.iter().any(|row| row.cache_hit && row.cost_micro == 0));
        assert!(rows.iter().any(|row| !row.cache_hit && row.cost_micro == 100));
        assert_eq!(ledger_cost(instance).await, 100);
        assert_eq!(used(instance, &cost_quota).await, 100);
        assert_eq!(used(instance, &request_quota).await, 2);
        assert!(instance.state.store.audit_verify_durable(instance.tenant).await.unwrap().passed);
    }
    assert_eq!(h.state.meter.snapshot().total.cost_micro, 100);
    assert_eq!(h.state.meter.snapshot().total.calls, 2);
    assert_eq!(h.state.meter.snapshot().total.cache_hits, 1);
    case.pool.close().await;
}
