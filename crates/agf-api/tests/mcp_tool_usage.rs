//! Completed tool outcomes are durable per endpoint and do not expose payloads.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, method, path},
};

const VERSION: &str = "2026-07-28";

async fn endpoint(h: &Harness, url: &str) -> Value {
    let response = h
        .post(
            "/api/v1/mcp/endpoints",
            json!({"expected_version":0,"name":"Metered MCP",
        "url":url,"enabled":true,"idle_timeout_secs":5,"allowed_origins":[]}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    response.json()
}

async fn tool(h: &Harness, id: &str, name: &str, modern: bool) -> Resp {
    let mut params = json!({"name":name,"arguments":{}});
    let token = format!("Bearer {}", h.admin);
    let mut headers = vec![("authorization", token.as_str())];
    if modern {
        params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":VERSION});
        headers.extend([("mcp-protocol-version", VERSION), ("mcp-method", "tools/call"), ("mcp-name", name)]);
    }
    h.request_with(
        "POST",
        &format!("/api/v1/mcp/proxy/{id}"),
        &headers,
        Some(json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":params})),
    )
    .await
}

#[tokio::test]
async fn http_tool_outcomes_are_counted_per_endpoint_and_name() {
    let h = setup().await;
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"params":{"name":"lookup"}})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":7,
            "result":{"content":[{"type":"text","text":"ok"}]}})))
        .mount(&upstream)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"params":{"name":"explode"}})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":7,
            "error":{"code":-32603,"message":"private upstream secret"}})))
        .mount(&upstream)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"params":{"name":"rejected"}})))
        .respond_with(ResponseTemplate::new(503).set_body_raw("private upstream failure", "text/plain"))
        .mount(&upstream)
        .await;
    let first = endpoint(&h, &format!("{}/mcp", upstream.uri())).await;
    let second = endpoint(&h, &format!("{}/mcp", upstream.uri())).await;
    let id = first["id"].as_str().unwrap();
    assert_eq!(tool(&h, id, "lookup", true).await.status, StatusCode::OK);
    assert_eq!(tool(&h, id, "lookup", false).await.status, StatusCode::OK);
    let error = tool(&h, id, "explode", true).await;
    assert_eq!(error.status, StatusCode::OK);
    assert!(!error.text.contains("private upstream secret"));
    let rejected = tool(&h, id, "rejected", true).await;
    assert_eq!(rejected.status, StatusCode::BAD_GATEWAY);
    assert!(!rejected.text.contains("private upstream failure"));
    let usage = h.get(&format!("/api/v1/mcp/endpoints/{id}/usage")).await;
    assert_eq!(usage.status, StatusCode::OK, "{}", usage.text);
    assert_eq!(usage.json()["endpoint_id"], first["id"]);
    let items = usage.json()["items"].as_array().unwrap().clone();
    let named = |name: &str| items.iter().find(|item| item["name"] == name).unwrap().clone();
    assert_eq!(named("lookup")["attempts"], 2);
    assert_eq!(named("lookup")["succeeded"], 2);
    assert_eq!(named("lookup")["inflight"], 0);
    for name in ["explode", "rejected"] {
        assert_eq!(named(name)["attempts"], 1);
        assert_eq!(named(name)["failed"], 1);
        assert_eq!(named(name)["inflight"], 0);
    }
    assert!(!usage.text.contains("private"));
    let second_id = second["id"].as_str().unwrap();
    assert_eq!(h.get(&format!("/api/v1/mcp/endpoints/{second_id}/usage")).await.json()["items"], json!([]));
    assert_eq!(
        h.request("GET", &format!("/api/v1/mcp/endpoints/{id}/usage"), None, None).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn stream_result_is_metered_but_a_connection_refusal_is_not_a_forwarded_attempt() {
    let h = setup().await;
    let upstream = MockServer::start().await;
    let frame = json!({"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"ok"}]}});
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(format!("event: message\ndata: {frame}\n\n"), "text/event-stream"),
        )
        .mount(&upstream)
        .await;
    let working = endpoint(&h, &format!("{}/mcp", upstream.uri())).await;
    let working_id = working["id"].as_str().unwrap();
    let reply = tool(&h, working_id, "stream_read", true).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
    assert!(reply.text.contains("ok"));
    let counted = h.get(&format!("/api/v1/mcp/endpoints/{working_id}/usage")).await.json();
    assert_eq!(counted["items"][0]["succeeded"], 1);
    assert_eq!(counted["items"][0]["inflight"], 0);

    let unreachable = endpoint(&h, "http://127.0.0.1:1/mcp").await;
    let unreachable_id = unreachable["id"].as_str().unwrap();
    assert_eq!(tool(&h, unreachable_id, "never_sent", true).await.status, StatusCode::SERVICE_UNAVAILABLE);
    let count = h.get(&format!("/api/v1/mcp/endpoints/{unreachable_id}/usage")).await.json();
    assert_eq!(count["items"][0]["attempts"], 0);
    assert_eq!(count["items"][0]["inflight"], 0);
}

#[tokio::test]
async fn rejected_sse_frames_count_as_failed_and_release_concurrency() {
    for modern in [true, false] {
        for (name, body, reason) in [
            (
                "wrong_id",
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":8,\"result\":{}}\n\n".into(),
                "response ID",
            ),
            ("bad_json", "event: message\ndata: {invalid}\n\n".into(), "not a JSON-RPC message"),
            ("oversized", format!("data: {}\n\n", "x".repeat(1024 * 1024 + 1)), "frame exceeds"),
        ] {
            let h = setup().await;
            let upstream = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/mcp"))
                .respond_with(ResponseTemplate::new(200).set_body_raw(body, "text/event-stream"))
                .mount(&upstream)
                .await;
            let saved = endpoint(&h, &format!("{}/mcp", upstream.uri())).await;
            let id = saved["id"].as_str().unwrap();
            let quota = agf_api::quota_definitions::save(
                &h.state,
                h.tenant,
                agf_core::quota::Quota::tenant_default(h.tenant, agf_core::enums::QuotaDimension::Concurrency, 1),
            )
            .await
            .unwrap();
            let response = tool(&h, id, name, modern).await;
            assert_eq!(response.status, StatusCode::OK, "{}", response.text);
            assert!(response.text.contains(reason), "{}", response.text);
            let usage = h.get(&format!("/api/v1/mcp/endpoints/{id}/usage")).await.json();
            let row = &usage["items"][0];
            assert_eq!(row["attempts"], 1);
            assert_eq!(row["failed"], 1);
            assert_eq!(row["unknown"], 0);
            assert_eq!(row["inflight"], 0);
            assert_eq!(agf_api::runtime_quota::usage(&h.state, h.tenant).await.unwrap()[&quota.id], 0);
        }
    }
}

#[tokio::test]
async fn stream_without_a_final_result_is_unknown_not_successful() {
    let h = setup().await;
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(": upstream stream ended\n\n", "text/event-stream"))
        .mount(&upstream)
        .await;
    let saved = endpoint(&h, &format!("{}/mcp", upstream.uri())).await;
    let id = saved["id"].as_str().unwrap();
    let response = tool(&h, id, "unfinished", true).await;
    assert_eq!(response.status, StatusCode::OK);
    assert!(response.text.contains("closed before returning"));
    let path = format!("/api/v1/mcp/endpoints/{id}/usage");
    for _ in 0..20 {
        let usage = h.get(&path).await.json();
        if usage["items"][0]["unknown"] == 1 {
            assert_eq!(usage["items"][0]["attempts"], 1);
            assert_eq!(usage["items"][0]["succeeded"], 0);
            assert_eq!(usage["items"][0]["inflight"], 0);
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("disconnected tool result was not classified as unknown");
}
