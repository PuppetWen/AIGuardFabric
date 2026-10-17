//! A valid MCP tool error is a failed attempt across every supported transport.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{enums::QuotaDimension, quota::Quota};
use axum::{
    Json,
    body::Bytes,
    extract::State,
    response::IntoResponse,
    routing::{get, post},
};
use common::*;
use futures::StreamExt;
use std::{convert::Infallible, time::Duration};
use tokio::sync::broadcast;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

fn tool_error(id: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":{"isError":true,
        "content":[{"type":"text","text":"Tool execution failed."}]}})
}

#[tokio::test]
async fn endpoint_cannot_claim_the_runtime_usage_record_id() {
    let h = setup().await;
    let response = h
        .post(
            "/api/v1/mcp/endpoints",
            json!({
                "id":h.tenant,"expected_version":0,"name":"Reserved ID fixture",
                "url":"http://127.0.0.1:41234/mcp","transport":"streamable-http",
                "enabled":true,"idle_timeout_secs":5,"allowed_origins":[]
            }),
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST, "{}", response.text);
    let endpoints = h.get("/api/v1/mcp/endpoints").await.json();
    assert!(endpoints["items"].as_array().unwrap().iter().all(|endpoint| endpoint["id"] != json!(h.tenant)));
    assert!(h.get("/api/v1/runtime/mcp/usage").await.json()["items"].as_array().unwrap().is_empty());
}

async fn limits(h: &Harness) -> (Quota, Quota) {
    let requests = agf_api::quota_definitions::save(
        &h.state,
        h.tenant,
        Quota::tenant_default(h.tenant, QuotaDimension::Requests, 2),
    )
    .await
    .unwrap();
    let concurrency = agf_api::quota_definitions::save(
        &h.state,
        h.tenant,
        Quota::tenant_default(h.tenant, QuotaDimension::Concurrency, 1),
    )
    .await
    .unwrap();
    (requests, concurrency)
}

async fn assert_failed_usage(h: &Harness, path: &str, quotas: &(Quota, Quota)) {
    let response = h.get(path).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let usage = response.json();
    let rows = usage["items"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["name"], "failing_tool");
    assert_eq!(rows[0]["attempts"], 2);
    assert_eq!(rows[0]["failed"], 2);
    assert_eq!(rows[0]["succeeded"], 0);
    assert_eq!(rows[0]["unknown"], 0);
    assert_eq!(rows[0]["inflight"], 0);
    let used = agf_api::runtime_quota::usage(&h.state, h.tenant).await.unwrap();
    assert_eq!(used[&quotas.0.id], 2);
    assert_eq!(used[&quotas.1.id], 0);
}

async fn endpoint(h: &Harness, url: &str, transport: &str) -> String {
    let response = h
        .post(
            "/api/v1/mcp/endpoints",
            json!({
                "expected_version":0,"name":"Tool error fixture","url":url,
                "transport":transport,"enabled":true,"idle_timeout_secs":5,"allowed_origins":[]
            }),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    response.json()["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn tool_errors_remain_protocol_results_and_release_quota_over_http_json_and_sse() {
    for modern in [false, true] {
        for streaming in [false, true] {
            let h = setup().await;
            let quotas = limits(&h).await;
            let upstream = MockServer::start().await;
            let error = tool_error(json!(7));
            let reply = if streaming {
                ResponseTemplate::new(200).set_body_raw(format!("data: {error}\n\n"), "text/event-stream")
            } else {
                ResponseTemplate::new(200).set_body_json(error)
            };
            Mock::given(method("POST")).respond_with(reply).expect(2).mount(&upstream).await;
            let id = endpoint(&h, &format!("{}/mcp", upstream.uri()), "streamable-http").await;
            let token = format!("Bearer {}", h.admin);
            let mut headers = vec![("authorization", token.as_str())];
            let mut params = json!({"name":"failing_tool","arguments":{}});
            if modern {
                params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28"});
                headers.extend([
                    ("mcp-protocol-version", "2026-07-28"),
                    ("mcp-method", "tools/call"),
                    ("mcp-name", "failing_tool"),
                ]);
            }
            for _ in 0..2 {
                let response = h
                    .request_with(
                        "POST",
                        &format!("/api/v1/mcp/proxy/{id}"),
                        &headers,
                        Some(json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":params})),
                    )
                    .await;
                assert_eq!(response.status, StatusCode::OK, "{}", response.text);
                assert!(response.text.contains("\"isError\":true"), "{}", response.text);
            }
            assert_failed_usage(&h, &format!("/api/v1/mcp/endpoints/{id}/usage"), &quotas).await;
        }
    }
}

#[tokio::test]
async fn stdio_tool_error_completion_is_failed_and_duplicate_completion_is_idempotent() {
    let h = setup().await;
    let quotas = limits(&h).await;
    for id in [7, 8] {
        let start = h
            .post(
                "/api/v1/runtime/mcp/check",
                json!({
                    "session_id":"tool-error-stdio","frame":{"jsonrpc":"2.0","id":id,
                        "method":"tools/call","params":{"name":"failing_tool","arguments":{}}}
                }),
            )
            .await;
        assert_eq!(start.status, StatusCode::OK, "{}", start.text);
        let completion = json!({"session_id":"tool-error-stdio","response":true,
            "lease_id":start.json()["lease_id"],"frame":tool_error(json!(id))});
        for _ in 0..2 {
            let response = h.post("/api/v1/runtime/mcp/check", completion.clone()).await;
            assert_eq!(response.status, StatusCode::OK, "{}", response.text);
            assert_eq!(response.json()["frame"]["result"]["isError"], true);
        }
    }
    assert_failed_usage(&h, "/api/v1/runtime/mcp/usage", &quotas).await;
}

async fn legacy_stream(State(tx): State<broadcast::Sender<Value>>) -> impl IntoResponse {
    let receiver = tx.subscribe();
    let stream = futures::stream::unfold((true, receiver), |(first, mut receiver)| async move {
        let text = if first {
            "event: endpoint\ndata: /messages\n\n".into()
        } else {
            format!("event: message\ndata: {}\n\n", receiver.recv().await.ok()?)
        };
        Some((Ok::<_, Infallible>(Bytes::from(text)), (false, receiver)))
    });
    ([("content-type", "text/event-stream")], Body::from_stream(stream))
}

async fn legacy_post(State(tx): State<broadcast::Sender<Value>>, Json(frame): Json<Value>) -> StatusCode {
    tx.send(tool_error(frame["id"].clone())).unwrap();
    StatusCode::ACCEPTED
}

struct AbortServer(tokio::task::JoinHandle<()>);
impl Drop for AbortServer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn read(stream: &mut axum::body::BodyDataStream) -> String {
    let bytes = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("legacy SSE timed out")
        .expect("legacy SSE closed")
        .expect("legacy SSE failed");
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn legacy_sse_tool_errors_are_failed_only_after_the_matching_stream_result() {
    let h = setup().await;
    let quotas = limits(&h).await;
    let (tx, _) = broadcast::channel(8);
    let app = Router::new().route("/sse", get(legacy_stream)).route("/messages", post(legacy_post)).with_state(tx);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let _server = AbortServer(tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    }));
    let id = endpoint(&h, &format!("http://{address}/sse"), "legacy-sse").await;
    let response = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/mcp/legacy/{id}/sse"))
                .header("authorization", format!("Bearer {}", h.admin))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.into_body().into_data_stream();
    let announcement = read(&mut stream).await;
    let post_url = announcement.lines().find_map(|line| line.strip_prefix("data: ")).unwrap();
    let usage_path = format!("/api/v1/mcp/endpoints/{id}/usage");
    for request_id in [7, 8] {
        let response = h
            .post(
                post_url,
                json!({"jsonrpc":"2.0","id":request_id,"method":"tools/call",
            "params":{"name":"failing_tool","arguments":{}}}),
            )
            .await;
        assert_eq!(response.status, StatusCode::ACCEPTED, "{}", response.text);
        let pending = h.get(&usage_path).await.json();
        assert_eq!(pending["items"][0]["inflight"], 1);
        assert_eq!(agf_api::runtime_quota::usage(&h.state, h.tenant).await.unwrap()[&quotas.1.id], 1);
        assert!(read(&mut stream).await.contains("\"isError\":true"));
    }
    assert_failed_usage(&h, &usage_path, &quotas).await;
}
