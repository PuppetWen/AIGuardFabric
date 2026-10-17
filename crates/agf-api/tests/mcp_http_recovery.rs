//! Legacy Streamable HTTP recovery uses opaque, caller-bound SSE cursors.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, method},
};

#[tokio::test]
async fn session_recovery_maps_event_ids_without_exposing_upstream_ids() {
    let h = setup().await;
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"initialize"})))
        .respond_with(
            ResponseTemplate::new(200).insert_header("mcp-session-id", "private-upstream-session").set_body_json(
                json!({"jsonrpc":"2.0","id":1,"result":{
                "protocolVersion":"2025-11-25","capabilities":{},
                "serverInfo":{"name":"recovery-loopback","version":"1"}}}),
            ),
        )
        .mount(&upstream)
        .await;
    let event = json!({"jsonrpc":"2.0","method":"notifications/progress",
        "params":{"progressToken":"recovery-test","progress":1}});
    let sse = format!("id: private-upstream-event\nevent: message\ndata: {event}\n\n");
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(sse, "text/event-stream"))
        .mount(&upstream)
        .await;
    let saved = h
        .post(
            "/api/v1/mcp/endpoints",
            json!({"expected_version":0,
        "name":"Recovery loopback","url":format!("{}/mcp",upstream.uri()),
        "enabled":true,"idle_timeout_secs":5,"allowed_origins":[]}),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let url = format!("/api/v1/mcp/proxy/{}", saved.json()["id"].as_str().unwrap());
    let initialized = h
        .post(
            &url,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion":"2025-11-25","capabilities":{},
        "clientInfo":{"name":"test","version":"1"}}}),
        )
        .await;
    assert_eq!(initialized.status, StatusCode::OK, "{}", initialized.text);
    let session = initialized.header("mcp-session-id");
    assert!(!session.is_empty());
    assert_ne!(session, "private-upstream-session");
    let bearer = format!("Bearer {}", h.admin);
    let headers = [
        ("authorization", bearer.as_str()),
        ("mcp-session-id", session.as_str()),
        ("mcp-protocol-version", "2025-11-25"),
    ];
    let first = h.request_with("GET", &url, &headers, None).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    assert!(!first.text.contains("private-upstream-event"));
    let cursor = first.text.lines().find_map(|line| line.strip_prefix("id: ")).unwrap().to_owned();
    assert!(cursor.starts_with("agf1."));
    let resumed_headers = [
        ("authorization", bearer.as_str()),
        ("mcp-session-id", session.as_str()),
        ("mcp-protocol-version", "2025-11-25"),
        ("last-event-id", cursor.as_str()),
    ];
    let resumed = h.request_with("GET", &url, &resumed_headers, None).await;
    assert_eq!(resumed.status, StatusCode::OK, "{}", resumed.text);
    let requests = upstream.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[2].headers["last-event-id"], "private-upstream-event");
    assert_eq!(requests[2].headers["mcp-session-id"], "private-upstream-session");

    let forged = format!("{cursor}x");
    let bad_headers = [
        ("authorization", bearer.as_str()),
        ("mcp-session-id", session.as_str()),
        ("mcp-protocol-version", "2025-11-25"),
        ("last-event-id", forged.as_str()),
    ];
    assert_eq!(h.request_with("GET", &url, &bad_headers, None).await.status, StatusCode::BAD_REQUEST);
    let other = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("mcps:execute"), Permission::from_raw("policies:read")],
        ..ApiKeyIssueRequest::named(h.tenant, "other-recovery-caller", Timestamp::now())
    });
    h.state.store.api_key_insert(other.record.clone()).unwrap();
    let foreign_headers = [
        ("x-agf-key", other.plaintext.as_str()),
        ("mcp-session-id", session.as_str()),
        ("mcp-protocol-version", "2025-11-25"),
        ("last-event-id", cursor.as_str()),
    ];
    assert_eq!(h.request_with("GET", &url, &foreign_headers, None).await.status, StatusCode::NOT_FOUND);
    let second = h
        .post(
            &url,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion":"2025-11-25","capabilities":{},
        "clientInfo":{"name":"test","version":"1"}}}),
        )
        .await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.text);
    let second_session = second.header("mcp-session-id");
    assert_ne!(second_session, session);
    let wrong_session = [
        ("authorization", bearer.as_str()),
        ("mcp-session-id", second_session.as_str()),
        ("mcp-protocol-version", "2025-11-25"),
        ("last-event-id", cursor.as_str()),
    ];
    assert_eq!(h.request_with("GET", &url, &wrong_session, None).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(upstream.received_requests().await.unwrap().len(), 4);
}

#[tokio::test]
async fn modern_protocol_rejects_legacy_recovery_header_before_forwarding() {
    let h = setup().await;
    let upstream = MockServer::start().await;
    let saved = h
        .post(
            "/api/v1/mcp/endpoints",
            json!({"expected_version":0,
        "name":"Modern loopback","url":format!("{}/mcp",upstream.uri()),
        "enabled":true,"idle_timeout_secs":5,"allowed_origins":[]}),
        )
        .await;
    let url = format!("/api/v1/mcp/proxy/{}", saved.json()["id"].as_str().unwrap());
    let bearer = format!("Bearer {}", h.admin);
    let headers = [
        ("authorization", bearer.as_str()),
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/list"),
        ("last-event-id", "forged"),
    ];
    let response = h
        .request_with(
            "POST",
            &url,
            &headers,
            Some(json!({"jsonrpc":"2.0","id":2,
        "method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}})),
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST, "{}", response.text);
    assert!(upstream.received_requests().await.unwrap().is_empty());
}
