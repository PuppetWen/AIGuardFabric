//! Probe errors from an upstream must not reveal its raw diagnostic message or data.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

#[tokio::test]
async fn streamable_http_probe_reports_only_safe_upstream_error_details() {
    let h = setup().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0","id":1,"error":{
                "code":-32601,
                "message":"private-upstream-message",
                "data":{"credential":"private-upstream-credential","url":"https://internal.example/private"}
            }
        })))
        .mount(&server)
        .await;
    let saved = h
        .post(
            "/api/v1/mcp/endpoints",
            json!({
                "expected_version":0,"name":"Probe errors","url":format!("{}/mcp", server.uri()),
                "enabled":true,"idle_timeout_secs":5
            }),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let url = format!("/api/v1/mcp/endpoints/{}/probe", saved.json()["id"].as_str().unwrap());
    for protocol in ["2025-11-25", "2026-07-28"] {
        let response = h.post(&url, json!({"protocol":protocol})).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{}", response.text);
        assert!(response.text.contains("JSON-RPC code -32601"), "{}", response.text);
        for secret in ["private-upstream-message", "private-upstream-credential", "internal.example"] {
            assert!(!response.text.contains(secret), "{secret} leaked: {}", response.text);
        }
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}
