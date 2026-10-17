//! The key issued by Settings must be usable with the scopes shown in the MCP guide.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

#[tokio::test]
async fn a_minimal_platform_key_reaches_mcp_and_a_read_only_key_cannot() {
    let h = setup().await;
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0","id":7,"result":{"tools":[{"name":"read_only"}]}
        })))
        .mount(&upstream)
        .await;
    let endpoint = h
        .post(
            "/api/v1/mcp/endpoints",
            json!({
                "expected_version":0,"name":"Key flow fixture",
                "url":format!("{}/mcp", upstream.uri()),"enabled":true,"idle_timeout_secs":5
            }),
        )
        .await;
    assert_eq!(endpoint.status, StatusCode::OK, "{}", endpoint.text);
    let id = endpoint.json()["id"].as_str().unwrap().to_owned();

    let key = h
        .post(
            "/api/v1/settings/api-keys",
            json!({
                "name":"MCP client fixture","scopes":["mcps:execute","policies:read"]
            }),
        )
        .await;
    assert_eq!(key.status, StatusCode::CREATED, "{}", key.text);
    let bearer = format!("Bearer {}", key.json()["plaintext"].as_str().unwrap());
    let frame = json!({"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}});
    let url = format!("/api/v1/mcp/proxy/{id}");
    let headers = [
        ("authorization", bearer.as_str()),
        ("mcp-protocol-version", "2025-11-25"),
        ("accept", "application/json, text/event-stream"),
    ];
    let allowed = h.request_with("POST", &url, &headers, Some(frame.clone())).await;
    assert_eq!(allowed.status, StatusCode::OK, "{}", allowed.text);
    assert_eq!(allowed.json()["result"]["tools"][0]["name"], "read_only");

    let limited = h
        .post(
            "/api/v1/settings/api-keys",
            json!({
                "name":"Read-only fixture","scopes":["mcps:read","policies:read"]
            }),
        )
        .await;
    assert_eq!(limited.status, StatusCode::CREATED, "{}", limited.text);
    let limited_bearer = format!("Bearer {}", limited.json()["plaintext"].as_str().unwrap());
    let denied_headers = [("authorization", limited_bearer.as_str()), ("mcp-protocol-version", "2025-11-25")];
    let denied = h.request_with("POST", &url, &denied_headers, Some(frame)).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN, "{}", denied.text);
    assert_eq!(upstream.received_requests().await.unwrap().len(), 1);
}
