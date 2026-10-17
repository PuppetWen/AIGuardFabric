//! 配额需覆盖真实请求、并发归还、配置热更新和多维度原子拒绝。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_aigw::{
    AiGateway, gateway::CallContext, meter::BudgetGuard, provider::StaticCredentialResolver, router::RoutingStrategy,
    wire::ChatRequest,
};
use agf_core::{
    enums::{DataClass, LlmProvider, QuotaDimension},
    ids::Id,
    model::{Modality, ModelEndpoint, ModelPricing},
    quota::{Quota, QuotaConsumption},
};
use agf_runtime::audit::InterceptionVerdict;
use common::*;

async fn reserve(h: &Harness, tokens: i64) -> agf_core::error::DomainResult<agf_api::runtime_quota::Lease> {
    agf_api::runtime_quota::Lease::acquire(
        &h.state,
        h.tenant,
        None,
        "atomic",
        "test",
        &QuotaConsumption { tokens, requests: 1, concurrency: 1, cost_micro: 0 },
    )
    .await
}

#[tokio::test]
async fn mcp_concurrency_is_held_until_response_and_finish_is_idempotent() {
    let h = setup().await;
    let quota = h
        .post(
            "/api/v1/quotas",
            json!({"name":"one-mcp","scope":"session",
        "dimension":"concurrency","window":"total","limit":1}),
        )
        .await;
    assert_eq!(quota.status, StatusCode::OK, "{}", quota.text);
    let body = json!({"session_id":"hold","frame":{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query","arguments":{"query":"hello"}}}});
    let first = h.post("/api/v1/runtime/mcp/check", body.clone()).await;
    assert_eq!(first.json()["allowed"], true, "{}", first.text);
    assert_eq!(h.post("/api/v1/runtime/mcp/check", body.clone()).await.status, StatusCode::TOO_MANY_REQUESTS);
    let finish = json!({"session_id":"hold","lease_id":first.json()["lease_id"],"response":true,
        "frame":{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}});
    assert_eq!(h.post("/api/v1/runtime/mcp/check", finish.clone()).await.status, StatusCode::OK);
    assert_eq!(h.post("/api/v1/runtime/mcp/check", finish).await.status, StatusCode::OK);
    assert_eq!(h.post("/api/v1/runtime/mcp/check", body).await.status, StatusCode::OK);
}

#[tokio::test]
async fn failed_multi_dimension_reservation_does_not_consume_other_dimensions() {
    let h = setup().await;
    let calls = agf_api::quota_definitions::save(
        &h.state,
        h.tenant,
        Quota::tenant_default(h.tenant, QuotaDimension::Requests, 1),
    )
    .await
    .unwrap();
    agf_api::quota_definitions::save(&h.state, h.tenant, Quota::tenant_default(h.tenant, QuotaDimension::Tokens, 2))
        .await
        .unwrap();
    assert!(reserve(&h, 3).await.is_err());
    assert_eq!(agf_api::runtime_quota::usage(&h.state, h.tenant).await.unwrap()[&calls.id], 0);
    let lease = reserve(&h, 2).await.unwrap();
    lease.finish(None).await.unwrap();
    assert_eq!(agf_api::runtime_quota::usage(&h.state, h.tenant).await.unwrap()[&calls.id], 1);
    let saved = h
        .post("/api/v1/runtime/blacklists", json!({"kind":"command","pattern":"unused-command","action":"deny"}))
        .await;
    assert_eq!(saved.status, StatusCode::OK);
    h.state.runtime_registry.get(&h.state, h.tenant).await.unwrap();
    assert!(reserve(&h, 1).await.is_err(), "规则热重载不能清空配额");
}

#[tokio::test]
async fn model_requests_really_consume_runtime_request_quota() {
    let h = setup().await;
    h.post(
        "/api/v1/gateway/endpoints",
        json!({"name":"test","provider":"mock","model":"m","base_url":"http://mock.invalid"}),
    )
    .await;
    let quota = h
        .post(
            "/api/v1/quotas",
            json!({"name":"one-model","scope":"tenant","dimension":"requests","window":"total","limit":1}),
        )
        .await;
    assert_eq!(quota.status, StatusCode::OK);
    let body = json!({"model":"auto","max_tokens":4,"messages":[{"role":"user","content":"hello"}]});
    let first = h.post("/api/v1/chat/completions", body.clone()).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    assert_eq!(h.post("/api/v1/chat/completions", body).await.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(h.state.meter.recent(10).len(), 1);
    let records = h.state.runtime.audit().by_tenant(h.tenant);
    assert!(
        records.iter().any(|row| {
            row.intercept_point == agf_core::enums::InterceptPoint::AiGateway
                && row.verdict == InterceptionVerdict::Throttled
                && row.policy_name.as_deref() == Some("gateway-quota")
        }),
        "配额拒绝必须进入运行时审计，不能只留下放行预检: {records:?}"
    );
    let visible = h.get("/api/v1/runtime/events").await;
    assert_eq!(visible.status, StatusCode::OK, "{}", visible.text);
    assert!(
        visible.json().as_array().unwrap().iter().any(|row| {
            row["point"] == "ai-gateway" && row["action"] == "throttle" && row["policy_name"] == "gateway-quota"
        }),
        "控制台事件接口必须显示实际配额拒绝: {}",
        visible.text
    );
}

#[tokio::test]
async fn long_stream_renews_its_gateway_reservation_and_rejects_expired_lease() {
    let h = setup().await;
    let created = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({"name":"lease-test","provider":"mock","model":"test-model","base_url":"http://mock.invalid"}),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let gateway = h.state.model_gateway.for_tenant(&h.state, h.tenant).await.unwrap();
    let request = ChatRequest::simple("test-model", "test prompt");
    let context = CallContext::new(h.tenant).with_session("stream");
    let lease = agf_api::gateway_quota::Lease::acquire(&h.state, &context, &gateway, &request, None).await.unwrap();
    let id = agf_api::model_routes::tenant_record_id(h.tenant);
    let kind = "gateway-ledger";
    let near_expiry = Timestamp::now().unix_secs() + 1;
    h.state
        .configurations
        .mutate::<Value, _>(h.tenant, kind, id, |ledger| {
            for row in ledger["reservations"].as_object_mut().unwrap().values_mut() {
                row["expires"] = json!(near_expiry);
            }
            Ok(())
        })
        .await
        .unwrap();
    lease.renew().await.unwrap();
    let ledger: Value = h.state.configurations.get(h.tenant, kind, id).await.unwrap().unwrap();
    let renewed = ledger["reservations"].as_object().unwrap().values().next().unwrap()["expires"].as_i64().unwrap();
    assert!(renewed >= Timestamp::now().unix_secs() + 898);

    h.state
        .configurations
        .mutate::<Value, _>(h.tenant, kind, id, |ledger| {
            for row in ledger["reservations"].as_object_mut().unwrap().values_mut() {
                row["expires"] = json!(Timestamp::now().unix_secs() - 1);
            }
            Ok(())
        })
        .await
        .unwrap();
    assert!(lease.renew().await.is_err(), "过期租约不能被重新激活");
    lease.finish(None).await.unwrap();
}

#[tokio::test]
async fn gateway_reserves_only_models_in_the_actual_routing_chain() {
    let h = setup().await;
    let endpoint = |model: &str, prompt_rate: u64| ModelEndpoint {
        id: Id::new(),
        tenant_id: h.tenant,
        asset_id: Id::new(),
        name: model.into(),
        provider: LlmProvider::OpenAi,
        base_url: "https://example.invalid/v1".into(),
        model: model.into(),
        modalities: vec![Modality::Text],
        context_window: Some(16_000),
        max_output_tokens: Some(1_000),
        supports_streaming: true,
        supports_tools: true,
        credential_ref: Some(Id::new()),
        local_deployment: false,
        max_data_class: DataClass::Confidential,
        pricing: ModelPricing {
            prompt_micro_per_1k: prompt_rate,
            completion_micro_per_1k: prompt_rate,
            cached_prompt_micro_per_1k: 0,
        },
        enabled: true,
        fallback: true,
        priority: 1,
        extra_headers: std::collections::BTreeMap::default(),
        created_at: agf_core::time::Timestamp::now(),
        updated_at: agf_core::time::Timestamp::now(),
    };
    let cheap = endpoint("cheap", 1_000);
    let expensive = endpoint("expensive", 100_000);
    let credentials = StaticCredentialResolver::new()
        .with_key(cheap.credential_ref.unwrap(), "test-key")
        .with_key(expensive.credential_ref.unwrap(), "test-key");
    let gateway = AiGateway::new(vec![cheap.clone(), expensive.clone()])
        .with_credentials(std::sync::Arc::new(credentials))
        .with_mock_mode(false);
    let context = CallContext::new(h.tenant).with_session("pinned-model");
    let mut request = ChatRequest::simple("cheap", "hello");
    request.max_tokens = Some(100);
    let lease = agf_api::gateway_quota::Lease::acquire(&h.state, &context, &gateway, &request, None).await.unwrap();
    let ledger: Value = h
        .state
        .configurations
        .get(h.tenant, "gateway-ledger", agf_api::model_routes::tenant_record_id(h.tenant))
        .await
        .unwrap()
        .unwrap();
    let reserved = ledger["reservations"].as_object().unwrap().values().next().unwrap()["cost"].as_u64().unwrap();
    assert_eq!(reserved, BudgetGuard::projected_micro_for_request(&cheap, &request));
    assert!(reserved < BudgetGuard::projected_micro_for_request(&expensive, &request));
    lease.finish(None).await.unwrap();

    // Without a pinned model the expensive fallback can run, so it must be reserved.
    request.model.clear();
    let fallback = agf_api::gateway_quota::Lease::acquire(&h.state, &context, &gateway, &request, None).await.unwrap();
    let ledger: Value = h
        .state
        .configurations
        .get(h.tenant, "gateway-ledger", agf_api::model_routes::tenant_record_id(h.tenant))
        .await
        .unwrap()
        .unwrap();
    let reserved = ledger["reservations"].as_object().unwrap().values().next().unwrap()["cost"].as_u64().unwrap();
    assert_eq!(reserved, BudgetGuard::projected_micro_for_request(&expensive, &request));
    fallback.finish(None).await.unwrap();

    let round_robin =
        CallContext::new(h.tenant).with_session("round-robin").with_strategy(RoutingStrategy::RoundRobin).no_fallback();
    let before = gateway.router().round_robin_counter();
    let lease = agf_api::gateway_quota::Lease::acquire(&h.state, &round_robin, &gateway, &request, None).await.unwrap();
    assert_eq!(gateway.router().round_robin_counter(), before, "预留不能消耗轮询位置");
    let ledger: Value = h
        .state
        .configurations
        .get(h.tenant, "gateway-ledger", agf_api::model_routes::tenant_record_id(h.tenant))
        .await
        .unwrap()
        .unwrap();
    let reserved = ledger["reservations"].as_object().unwrap().values().next().unwrap()["cost"].as_u64().unwrap();
    assert_eq!(reserved, BudgetGuard::projected_micro_for_request(&expensive, &request));
    lease.finish(None).await.unwrap();

    let missing = ChatRequest::simple("missing-model", "hello");
    assert!(agf_api::gateway_quota::Lease::acquire(&h.state, &context, &gateway, &missing, None).await.is_err());
    let ledger: Value = h
        .state
        .configurations
        .get(h.tenant, "gateway-ledger", agf_api::model_routes::tenant_record_id(h.tenant))
        .await
        .unwrap()
        .unwrap();
    assert!(ledger["reservations"].as_object().unwrap().is_empty());
}
