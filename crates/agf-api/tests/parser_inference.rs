//! Local inference and a real loopback model transport produce validated drafts without publishing.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

#[tokio::test]
async fn offline_draft_is_redacted_and_never_published() {
    let h = setup().await;
    let before = h.get("/api/v1/parsers").await.json()["total"].clone();
    let response = h
        .post("/api/v1/parsers/suggest", json!({"sample":"{\"message\":\"failed\",\"email\":\"alice@example.com\"}"}))
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.json()["mocked"], true);
    assert!(!response.text.contains("alice@example.com"));
    let definition: Value = serde_json::from_str(response.json()["definition_json"].as_str().unwrap()).unwrap();
    assert_eq!(definition["ai_inferred"], true);
    assert_eq!(h.get("/api/v1/parsers").await.json()["total"], before);
    assert_eq!(
        h.request("POST", "/api/v1/parsers/suggest", Some(&h.viewer), Some(json!({"sample":"{}"}))).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        h.post("/api/v1/parsers/suggest", json!({"sample":"x".repeat(16385)})).await.status,
        StatusCode::BAD_REQUEST
    );
}
#[tokio::test]
async fn configured_model_draft_uses_gateway_metering_and_validates_output() {
    let upstream = MockServer::start().await;
    let definition = json!({"key":"model-output","name":"Model draft","engine":"json-path","pattern":"$",
        "required_fields":["message"],"mapping":{"map":{"message":"message"}}});
    Mock::given(method("POST")).and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id":"chatcmpl-fixture","object":"chat.completion","created":0,"model":"parser-model",
            "choices":[{"index":0,"message":{"role":"assistant","content":definition.to_string()},"finish_reason":"stop"}],
            "usage":{"prompt_tokens":120,"completion_tokens":50,"total_tokens":170}
        }))).expect(1).mount(&upstream).await;
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    let endpoint = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({"name":"loopback-model","provider":"ollama",
        "model":"parser-model","base_url":format!("{}/v1",upstream.uri()),"local_deployment":true,"max_data_class":"restricted"}),
        )
        .await;
    assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
    let result = h
        .post(
            "/api/v1/parsers/suggest",
            json!({"sample":"{\"message\":\"contact alice@example.com\"}","model":"parser-model"}),
        )
        .await;
    assert_eq!(result.status, StatusCode::OK, "{}", result.text);
    assert_eq!(result.json()["mocked"], false);
    assert_eq!(h.state.meter.recent(10).len(), 1);
    let requests = upstream.received_requests().await.unwrap();
    assert!(!String::from_utf8_lossy(&requests[0].body).contains("alice@example.com"));
    upstream.verify().await;
}
