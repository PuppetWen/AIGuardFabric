//! No test-only provider replacement: use the real router, stored endpoint and actual owned listener.
use crate::common::*;

pub(crate) fn live(mut h: Harness) -> Harness {
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    h
}

pub(crate) fn endpoint_body(provider: &str, model: &str, origin: &str, key: Option<&str>, local: bool) -> Value {
    let mut body = json!({"expected_version":0,"name":format!("no-key-{provider}"),"provider":provider,
        "model":model,"base_url":origin,"local_deployment":local,"pricing":{
            "prompt_micro_per_1k":2000,"completion_micro_per_1k":8000,"cached_prompt_micro_per_1k":500}});
    if let Some(key) = key {
        body["api_key"] = json!(key);
    }
    body
}

pub(crate) async fn add(
    h: &Harness,
    provider: &str,
    model: &str,
    origin: &str,
    key: Option<&str>,
    local: bool,
) -> Value {
    let response = h.post("/api/v1/gateway/endpoints", endpoint_body(provider, model, origin, key, local)).await;
    assert_eq!(response.status, StatusCode::CREATED, "Endpoint creation must reach the actual store");
    response.json()
}

pub(crate) fn chat(model: &str, stream: bool) -> Value {
    json!({"model":model,"max_tokens":32,"temperature":1,"stream":stream,"messages":[{"role":"user","content":"hello no key"}]})
}
pub(crate) async fn call(h: &Harness, model: &str, stream: bool) -> Resp {
    h.post("/v1/chat/completions", chat(model, stream)).await
}
pub(crate) fn assert_mock(response: &Resp, model: &str) {
    assert_eq!(response.status, StatusCode::OK, "No-key cloud endpoint must select the existing Mock adapter");
    assert_eq!(response.header("x-agf-mocked"), "true");
    assert_eq!(response.json()["object"], "chat.completion");
    assert_eq!(response.json()["model"], model);
    assert!(response.json()["usage"]["total_tokens"].as_u64().unwrap() > 0);
}
pub(crate) async fn usages(h: &Harness) -> Vec<agf_core::model::UsageRecord> {
    h.state.configurations.list(h.tenant, agf_api::gateway_quota::USAGE).await.unwrap()
}
pub(crate) fn reply(model: &str) -> Value {
    json!({"id":"owned-no-key-live-control","object":"chat.completion","created":1,"model":model,
        "choices":[{"index":0,"message":{"role":"assistant","content":"owned real local response"},"finish_reason":"stop"}],
        "usage":{"prompt_tokens":4,"completion_tokens":5,"total_tokens":9}})
}
