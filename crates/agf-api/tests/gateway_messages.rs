//! Native Messages clients must use the same auth, tenant boundary and metering as OpenAI clients.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;

#[tokio::test]
async fn default_claude_code_extension_request_reaches_mock_without_disabling_thinking() {
    let h = setup().await;
    let endpoint = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({"name":"claude-default-mock",
        "provider":"mock","model":"recorded-claude","base_url":"http://mock.invalid",
        "local_deployment":true}),
        )
        .await;
    assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
    let key = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":"claude-default",
        "scopes":["models:read","models:write"]}),
        )
        .await
        .json();
    let headers = [("x-api-key", key["plaintext"].as_str().unwrap()), ("anthropic-version", "2023-06-01")];
    let body = json!({"model":"auto","max_tokens":4096,"stream":true,
        "thinking":{"type":"enabled","budget_tokens":1024},
        "context_management":{"edits":[{"type":"clear_thinking_20251015"}]},
        "messages":[{"role":"user","content":"hello"}]});
    let result = h.request_with("POST", "/v1/messages", &headers, Some(body)).await;
    assert_eq!(result.status, StatusCode::OK, "{}", result.text);
    assert_eq!(result.header("x-agf-mocked"), "true");
    assert!(result.text.contains("message_stop"));
    assert_eq!(h.state.meter.recent(5).len(), 1);
}

#[tokio::test]
async fn messages_sdk_keys_streams_and_count_estimates_work_without_external_credentials() {
    let h = setup().await;
    let created = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({"name":"native-test","provider":"mock",
        "model":"recorded-claude","base_url":"http://mock.invalid","local_deployment":true}),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let key = h
        .post("/api/v1/settings/api-keys", json!({"name":"messages-client","scopes":["models:read","models:write"]}))
        .await
        .json();
    let token = key["plaintext"].as_str().unwrap();
    let headers = [("x-api-key", token), ("anthropic-version", "2023-06-01")];
    let mut body = json!({"model":"auto","max_tokens":64,"temperature":1,
        "system":[{"type":"text","text":"Be helpful","cache_control":{"type":"ephemeral"}}],
        "metadata":{"user_id":"claude-code-smoke"},
        "tools":[{"name":"Read","description":"Read a test file","input_schema":{
            "type":"object","properties":{"path":{"type":"string"}}}}],
        "messages":[{"role":"user","content":"hello"}]});
    let answer = h.request_with("POST", "/v1/messages?beta=true", &headers, Some(body.clone())).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text);
    assert_eq!(answer.json()["type"], "message");
    assert_eq!(answer.json()["model"], "recorded-claude");
    assert_eq!(answer.json()["content"][0]["type"], "text");
    assert_eq!(answer.header("x-agf-mocked"), "true");
    assert_eq!(h.state.meter.recent(5).len(), 1);
    body["stream"] = json!(true);
    let stream = h.request_with("POST", "/v1/messages", &headers, Some(body.clone())).await;
    assert_eq!(stream.status, StatusCode::OK, "{}", stream.text);
    let events: Vec<Value> = stream
        .text
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.first().unwrap()["type"], "message_start");
    assert_eq!(events.last().unwrap()["type"], "message_stop");
    assert!(events.iter().any(|event| event["type"] == "content_block_delta"));
    assert!(!stream.text.contains("[DONE]"));
    assert_eq!(h.state.meter.recent(5).len(), 2);
    let policy = h
        .post(
            "/api/v1/policies",
            json!({"name":"deny-native-gateway","language":"cel",
        "source":"{\"action\":\"deny\",\"reason\":\"native denial\"}","action":"deny",
        "enabled":true,"intercept_points":["ai-gateway"]}),
        )
        .await;
    assert_eq!(policy.status, StatusCode::CREATED, "{}", policy.text);
    let denied = h.request_with("POST", "/v1/messages", &headers, Some(body.clone())).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN, "{}", denied.text);
    assert_eq!(h.state.meter.recent(5).len(), 2, "denied request must not call upstream");
    body.as_object_mut().unwrap().remove("max_tokens");
    let count = h.request_with("POST", "/v1/messages/count_tokens", &headers, Some(body.clone())).await;
    assert_eq!(count.status, StatusCode::OK, "{}", count.text);
    assert_eq!(count.header("x-agf-token-count"), "estimated");
    assert!(count.json()["input_tokens"].as_u64().unwrap() > 0);
    assert_eq!(
        h.request_with("POST", "/v1/messages", &headers, Some(body.clone())).await.status,
        StatusCode::BAD_REQUEST
    );
    body["max_tokens"] = json!(32);
    assert_eq!(
        h.request("POST", "/v1/messages", Some(&h.viewer), Some(body.clone())).await.status,
        StatusCode::FORBIDDEN
    );
    let other = h.other_tenant.to_string();
    assert_eq!(
        h.request_with("POST", "/v1/messages", &[("x-api-key", token), ("x-agf-tenant", &other)], Some(body.clone()))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let key_id = key["api_key"]["id"].as_str().unwrap();
    assert_eq!(
        h.request("DELETE", &format!("/api/v1/settings/api-keys/{key_id}"), Some(&h.admin), None).await.status,
        StatusCode::OK
    );
    assert_eq!(h.request_with("POST", "/v1/messages", &headers, Some(body)).await.status, StatusCode::UNAUTHORIZED);
}
