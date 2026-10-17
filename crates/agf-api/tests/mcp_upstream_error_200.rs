//! Successful HTTP status can still carry a private JSON-RPC error from an upstream.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

#[tokio::test]
async fn proxy_replaces_private_json_rpc_errors_in_json_and_sse() {
    let h = setup().await;
    let quota = h
        .post(
            "/api/v1/quotas",
            json!({
                "name":"one-mcp-error-at-a-time","scope":"session","dimension":"concurrency",
                "window":"total","limit":1
            }),
        )
        .await;
    assert_eq!(quota.status, StatusCode::OK, "{}", quota.text);

    for protocol in ["2025-11-25", "2026-07-28"] {
        for streaming in [false, true] {
            let server = MockServer::start().await;
            let private = json!({"jsonrpc":"2.0","id":7,"error":{
                "code":-32603,"message":"private-mcp-stack-trace",
                "data":{"credential":"private-mcp-credential","url":"https://internal.example/tool"}
            }});
            let reply = if streaming {
                ResponseTemplate::new(200)
                    .set_body_raw(format!("event: message\ndata: {private}\n\n"), "text/event-stream")
            } else {
                ResponseTemplate::new(200).set_body_json(private)
            };
            Mock::given(method("POST")).respond_with(reply).mount(&server).await;
            let saved = h
                .post(
                    "/api/v1/mcp/endpoints",
                    json!({
                        "expected_version":0,"name":"Private error upstream",
                        "url":format!("{}/mcp",server.uri()),"enabled":true,"idle_timeout_secs":5
                    }),
                )
                .await;
            assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
            let url = format!("/api/v1/mcp/proxy/{}", saved.json()["id"].as_str().unwrap());
            let mut headers =
                vec![("authorization", format!("Bearer {}", h.admin)), ("mcp-protocol-version", protocol.to_string())];
            let mut params = json!({"name":"read","arguments":{}});
            if protocol == "2026-07-28" {
                headers.push(("mcp-method", "tools/call".into()));
                headers.push(("mcp-name", "read".into()));
                params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":protocol,
                    "io.modelcontextprotocol/clientInfo":{"name":"error-test","version":"1"}});
            }
            let header_refs = headers.iter().map(|(key, value)| (*key, value.as_str())).collect::<Vec<_>>();
            let frame = json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":params});
            for _ in 0..2 {
                let response = h.request_with("POST", &url, &header_refs, Some(frame.clone())).await;
                assert_eq!(response.status, StatusCode::OK, "{}", response.text);
                assert!(response.text.contains("-32603"), "{}", response.text);
                assert!(response.text.contains("check its server logs"), "{}", response.text);
                for secret in ["private-mcp-stack-trace", "private-mcp-credential", "internal.example"] {
                    assert!(!response.text.contains(secret), "{secret} leaked: {}", response.text);
                }
            }
            assert_eq!(server.received_requests().await.unwrap().len(), 2);
        }
    }
}
