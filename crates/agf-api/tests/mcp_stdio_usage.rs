//! Stdio proxy usage is bound to a verified quota lease and survives duplicate completion.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;

const CHECK: &str = "/api/v1/runtime/mcp/check";
const USAGE: &str = "/api/v1/runtime/mcp/usage";

async fn start(h: &Harness, id: u32, name: &str) -> Value {
    let response = h
        .post(
            CHECK,
            json!({"session_id":"stdio-test","frame":{"jsonrpc":"2.0","id":id,
                "method":"tools/call","params":{"name":name,
                "arguments":{"secret":"private input"}}}}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.json()["allowed"], true);
    response.json()["lease_id"].clone()
}

#[tokio::test]
async fn stdio_tool_results_errors_and_disconnects_are_counted_once() {
    let h = setup().await;
    let succeeded = start(&h, 1, "read_file").await;
    let failed = start(&h, 2, "write_file").await;
    let unknown = start(&h, 3, "slow_tool").await;
    let success_frame = json!({"session_id":"stdio-test","response":true,"lease_id":succeeded,
        "frame":{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"private output"}]}}});
    let error_frame = json!({"session_id":"stdio-test","response":true,"lease_id":failed,
        "frame":{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"private failure"}}});
    assert_eq!(h.post(CHECK, success_frame.clone()).await.status, StatusCode::OK);
    assert_eq!(h.post(CHECK, success_frame).await.status, StatusCode::OK);
    let error_result = h.post(CHECK, error_frame).await;
    assert_eq!(error_result.status, StatusCode::OK);
    assert_eq!(error_result.json()["frame"]["error"]["code"], -32000);
    assert!(!error_result.text.contains("private failure"));
    let closed = json!({"session_id":"stdio-test","lease_id":unknown,"finished":true,"frame":null});
    assert_eq!(h.post(CHECK, closed.clone()).await.status, StatusCode::OK);
    assert_eq!(h.post(CHECK, closed).await.status, StatusCode::OK);

    let response = h.get(USAGE).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let usage = response.json();
    assert_eq!(usage["source"], "runtime-check");
    let rows = usage["items"].as_array().unwrap();
    let row = |name: &str| rows.iter().find(|item| item["name"] == name).unwrap();
    assert_eq!(row("read_file")["attempts"], 1);
    assert_eq!(row("read_file")["succeeded"], 1);
    assert_eq!(row("write_file")["failed"], 1);
    assert_eq!(row("slow_tool")["unknown"], 1);
    assert!(rows.iter().all(|item| item["inflight"] == 0));
    for private in ["private input", "private output", "private failure"] {
        assert!(!response.text.contains(private));
    }
    assert_eq!(h.request("GET", USAGE, None, None).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rejected_stdio_call_does_not_create_a_usage_attempt() {
    let h = setup().await;
    h.post(
        "/api/v1/quotas",
        json!({"name":"single stdio call","scope":"session","dimension":"concurrency",
            "window":"total","limit":1}),
    )
    .await;
    let lease = start(&h, 1, "first").await;
    let rejected = h
        .post(
            CHECK,
            json!({"session_id":"stdio-test","frame":{"jsonrpc":"2.0","id":2,
                "method":"tools/call","params":{"name":"rejected","arguments":{}}}}),
        )
        .await;
    assert_eq!(rejected.status, StatusCode::TOO_MANY_REQUESTS);
    let usage = h.get(USAGE).await.json();
    assert_eq!(usage["items"].as_array().unwrap().len(), 1);
    assert_eq!(usage["items"][0]["name"], "first");
    assert_eq!(usage["items"][0]["inflight"], 1);
    assert_eq!(
        h.post(CHECK, json!({"session_id":"stdio-test","lease_id":lease,"finished":true,"frame":null})).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_result_with_another_request_id_cannot_settle_a_tool_lease() {
    let h = setup().await;
    let quota = h
        .post(
            "/api/v1/quotas",
            json!({"name":"one correlated call","scope":"session","dimension":"concurrency",
                "window":"total","limit":1}),
        )
        .await;
    assert_eq!(quota.status, StatusCode::OK, "{}", quota.text);
    let lease = start(&h, 1, "first").await;
    let wrong = h
        .post(
            CHECK,
            json!({"session_id":"stdio-test","response":true,"lease_id":lease,
                "frame":{"jsonrpc":"2.0","id":2,"result":{"content":[]}}}),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::CONFLICT, "{}", wrong.text);
    assert_eq!(
        h.post(
            CHECK,
            json!({"session_id":"stdio-test","frame":{"jsonrpc":"2.0","id":2,
                "method":"tools/call","params":{"name":"second","arguments":{}}}}),
        )
        .await
        .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    let before = h.get(USAGE).await.json();
    assert_eq!(before["items"][0]["inflight"], 1);
    assert_eq!(before["items"][0]["succeeded"], 0);
    let correct = h
        .post(
            CHECK,
            json!({"session_id":"stdio-test","response":true,"lease_id":lease,
                "frame":{"jsonrpc":"2.0","id":1,"result":{"content":[]}}}),
        )
        .await;
    assert_eq!(correct.status, StatusCode::OK, "{}", correct.text);
    let after = h.get(USAGE).await.json();
    assert_eq!(after["items"][0]["succeeded"], 1);
    assert_eq!(after["items"][0]["inflight"], 0);
}

#[tokio::test]
async fn invalid_request_id_is_rejected_before_creating_a_usage_lease() {
    let h = setup().await;
    let response = h
        .post(
            CHECK,
            json!({"session_id":"stdio-test","frame":{"jsonrpc":"2.0","id":{"nested":"bad"},
                "method":"tools/call","params":{"name":"read_file","arguments":{}}}}),
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST, "{}", response.text);
    assert!(h.get(USAGE).await.json()["items"].as_array().unwrap().is_empty());
}
