//! Real loopback MCP upstreams exercise proxy headers, sessions, policy checks and secret isolation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, method, path},
};

const VERSION: &str = "2026-07-28";

#[tokio::test]
async fn case_containment_blocks_one_http_service_without_blocking_same_named_tools() {
    let h = setup().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":7,"result":{"content":[]}})))
        .mount(&server)
        .await;
    let first = endpoint(&h, &server).await;
    let second = endpoint(&h, &server).await;
    let case = h.post("/api/v1/cases", json!({"title":"Scoped MCP containment","asset_ids":[first["id"]]})).await;
    assert_eq!(case.status, StatusCode::CREATED, "{}", case.text);
    let case_id = case.json()["case"]["id"].as_str().unwrap().to_owned();
    let run = h
        .post(
            &format!("/api/v1/cases/{case_id}/playbook"),
            json!({"dry_run":false,"playbook":{
                "key":"disable-http-mcp","name":"Contain one HTTP service","trigger":{},
                "steps":[{"name":"Disable endpoint","action":"disable-mcp-server","params":{"asset_id":first["id"]}}]
            }}),
        )
        .await;
    assert_eq!(run.json()["has_failure"], false, "{}", run.text);
    let tools = modern("tools/call", json!({"name":"query","arguments":{}}));
    assert_eq!(call(&h, &first["id"], tools.clone(), &[]).await.status, StatusCode::FORBIDDEN);
    assert_eq!(call(&h, &first["id"], modern("server/discover", json!({})), &[]).await.status, StatusCode::FORBIDDEN);
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
    assert_eq!(call(&h, &second["id"], tools.clone(), &[]).await.status, StatusCode::OK);
    let controls = h.get(&format!("/api/v1/cases/{case_id}/containments")).await.json();
    let control = &controls["items"][0];
    assert_eq!(control["endpoint_id"], first["id"]);
    assert_eq!(
        h.post(&format!("/api/v1/cases/{case_id}/containments/{}/release", control["id"].as_str().unwrap()), json!({}))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(call(&h, &first["id"], tools, &[]).await.status, StatusCode::OK);
}

#[tokio::test]
async fn empty_acceptance_is_not_a_completed_tool_call() {
    let h = setup().await;
    let server = MockServer::start().await;
    Mock::given(method("POST")).respond_with(ResponseTemplate::new(202)).mount(&server).await;
    let row = endpoint(&h, &server).await;
    let response = call(&h, &row["id"], modern("tools/call", json!({"name":"query","arguments":{}})), &[]).await;
    assert_eq!(response.status, StatusCode::BAD_GATEWAY);
    assert_eq!(response.json()["error"]["code"], -32000);
}

#[tokio::test]
async fn upstream_auth_rejections_release_concurrency_without_leaking_challenges() {
    for (upstream_status, expected_message) in
        [(401, "configured credential (401)"), (403, "token audience and tool scopes")]
    {
        let h = setup().await;
        let quota = h
            .post(
                "/api/v1/quotas",
                json!({"name":"one-mcp","scope":"session",
                    "dimension":"concurrency","window":"total","limit":1}),
            )
            .await;
        assert_eq!(quota.status, StatusCode::OK, "{}", quota.text);
        let requests = h
            .post(
                "/api/v1/quotas",
                json!({"name":"two-mcp-attempts","scope":"session",
                    "dimension":"requests","window":"total","limit":2}),
            )
            .await;
        assert_eq!(requests.status, StatusCode::OK, "{}", requests.text);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(upstream_status)
                    .insert_header("www-authenticate", "Bearer resource_metadata=\"https://secret.example/metadata\"")
                    .set_body_raw("upstream secret and login details", "text/plain"),
            )
            .mount(&server)
            .await;
        let row = endpoint(&h, &server).await;
        let frame = modern("tools/call", json!({"name":"query","arguments":{}}));
        for _ in 0..2 {
            let response = call(&h, &row["id"], frame.clone(), &[]).await;
            assert_eq!(response.status, StatusCode::BAD_GATEWAY, "{}", response.text);
            assert!(response.json()["error"]["message"].as_str().unwrap().contains(expected_message));
            assert!(!response.text.contains("upstream secret"));
            assert!(!response.text.contains("secret.example"));
            assert!(response.header("www-authenticate").is_empty());
        }
        let probe = h
            .post(&format!("/api/v1/mcp/endpoints/{}/probe", row["id"].as_str().unwrap()), json!({"protocol": VERSION}))
            .await;
        assert_eq!(probe.status, StatusCode::BAD_REQUEST, "{}", probe.text);
        assert!(probe.text.contains(expected_message), "{}", probe.text);
        assert!(!probe.text.contains("secret.example"));
        assert!(!probe.text.contains("upstream secret"));
        assert_eq!(call(&h, &row["id"], frame, &[]).await.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }
}

#[tokio::test]
async fn legacy_http_explicit_upstream_failures_release_concurrency() {
    for upstream_status in [302, 500] {
        let h = setup().await;
        let quota = h
            .post(
                "/api/v1/quotas",
                json!({"name":"one-mcp","scope":"session",
                    "dimension":"concurrency","window":"total","limit":1}),
            )
            .await;
        assert_eq!(quota.status, StatusCode::OK, "{}", quota.text);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(upstream_status)
                    .insert_header("location", "https://secret.example/redirect")
                    .set_body_raw("private upstream failure", "text/plain"),
            )
            .mount(&server)
            .await;
        let row = endpoint(&h, &server).await;
        let url = format!("/api/v1/mcp/proxy/{}", row["id"].as_str().unwrap());
        let frame = json!({"jsonrpc":"2.0","id":7,"method":"tools/call",
            "params":{"name":"query","arguments":{}}});
        for _ in 0..2 {
            let response = h.post(&url, frame.clone()).await;
            assert_eq!(response.status, StatusCode::BAD_GATEWAY, "{}", response.text);
            assert!(!response.text.contains("private upstream failure"));
            assert!(!response.text.contains("secret.example"));
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }
}

#[tokio::test]
async fn legacy_http_completed_malformed_responses_release_concurrency() {
    for body in
        ["private upstream text", r#"{"unexpected":"frame"}"#, r#"{"jsonrpc":"2.0","id":8,"result":{"content":[]}}"#]
    {
        let h = setup().await;
        let quota = h
            .post(
                "/api/v1/quotas",
                json!({"name":"one-mcp","scope":"session",
                    "dimension":"concurrency","window":"total","limit":1}),
            )
            .await;
        assert_eq!(quota.status, StatusCode::OK, "{}", quota.text);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .mount(&server)
            .await;
        let row = endpoint(&h, &server).await;
        let url = format!("/api/v1/mcp/proxy/{}", row["id"].as_str().unwrap());
        let frame = json!({"jsonrpc":"2.0","id":7,"method":"tools/call",
            "params":{"name":"query","arguments":{}}});
        for _ in 0..2 {
            let response = h.post(&url, frame.clone()).await;
            assert_eq!(response.status, StatusCode::BAD_GATEWAY, "{}", response.text);
            assert!(!response.text.contains("private upstream text"));
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }
}

#[tokio::test]
async fn valid_upstream_error_frames_are_not_exposed_and_release_concurrency() {
    let h = setup().await;
    let quota = h
        .post(
            "/api/v1/quotas",
            json!({"name":"one-mcp","scope":"session",
        "dimension":"concurrency","window":"total","limit":1}),
        )
        .await;
    assert_eq!(quota.status, StatusCode::OK, "{}", quota.text);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"jsonrpc":"2.0","id":7,
            "error":{"code":-32603,"message":"private upstream credential and stack trace"}})))
        .mount(&server)
        .await;
    let row = endpoint(&h, &server).await;
    let url = format!("/api/v1/mcp/proxy/{}", row["id"].as_str().unwrap());
    let legacy = json!({"jsonrpc":"2.0","id":7,"method":"tools/call",
        "params":{"name":"query","arguments":{}}});
    for _ in 0..2 {
        let response = h.post(&url, legacy.clone()).await;
        assert_eq!(response.status, StatusCode::BAD_GATEWAY, "{}", response.text);
        assert!(!response.text.contains("private upstream credential"));
    }
    for _ in 0..2 {
        let response = call(&h, &row["id"], modern("tools/call", json!({"name":"query","arguments":{}})), &[]).await;
        assert_eq!(response.status, StatusCode::BAD_GATEWAY, "{}", response.text);
        assert!(!response.text.contains("private upstream credential"));
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 4);
}

#[tokio::test]
async fn console_probe_discovers_both_protocols_without_invoking_tools() {
    let h = setup().await;
    let server = MockServer::start().await;
    Mock::given(method("POST")).respond_with(|request: &wiremock::Request| {
        let frame: Value = serde_json::from_slice(&request.body).unwrap();
        match frame["method"].as_str().unwrap() {
            "initialize" => ResponseTemplate::new(200).insert_header("mcp-session-id","probe-session")
                .set_body_json(json!({"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"probe","version":"1"}}})),
            "server/discover" => ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"probe","version":"1"},"capabilities":{}}})),
            "notifications/initialized" => ResponseTemplate::new(202),
            "tools/list" => ResponseTemplate::new(200).set_body_raw("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}\n\n","text/event-stream"),
            _ => ResponseTemplate::new(500),
        }
    }).mount(&server).await;
    Mock::given(method("DELETE")).respond_with(ResponseTemplate::new(204)).mount(&server).await;
    let row = endpoint(&h, &server).await;
    for protocol in [VERSION, "2025-11-25"] {
        let probe = h
            .post(&format!("/api/v1/mcp/endpoints/{}/probe", row["id"].as_str().unwrap()), json!({"protocol":protocol}))
            .await;
        assert_eq!(probe.status, StatusCode::OK, "{}", probe.text);
        assert_eq!(probe.json()["session_closed"], true);
        assert_eq!(probe.json()["tools"]["tools"], json!([]));
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 6);
}

async fn endpoint(h: &Harness, upstream: &MockServer) -> Value {
    let response = h
        .post(
            "/api/v1/mcp/endpoints",
            json!({"expected_version":0,"name":"Loopback MCP",
        "url":format!("{}/mcp",upstream.uri()),"enabled":true,"idle_timeout_secs":5,
        "allowed_origins":["https://allowed.example"],"bearer_token":"upstream-private-token"}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert!(!response.text.contains("upstream-private-token"));
    response.json()
}

fn modern(method: &str, params: Value) -> Value {
    let mut params = params;
    params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":VERSION,"io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}});
    json!({"jsonrpc":"2.0","id":7,"method":method,"params":params})
}

async fn call(h: &Harness, id: &Value, frame: Value, extra: &[(&str, &str)]) -> Resp {
    let token = format!("Bearer {}", h.admin);
    let method = frame["method"].as_str().unwrap();
    let mut headers = vec![
        ("authorization", token.as_str()),
        ("mcp-protocol-version", VERSION),
        ("mcp-method", method),
        ("accept", "application/json, text/event-stream"),
    ];
    if let Some(name) = frame["params"]["name"].as_str() {
        headers.push(("mcp-name", name));
    }
    headers.extend_from_slice(extra);
    h.request_with("POST", &format!("/api/v1/mcp/proxy/{}", id.as_str().unwrap()), &headers, Some(frame.clone())).await
}

#[tokio::test]
async fn metadata_auth_tenant_origin_policy_and_version_checks() {
    let h = setup().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":7,"result":{"tools":[]}})))
        .mount(&server)
        .await;
    let row = endpoint(&h, &server).await;
    let id = &row["id"];
    let frame = modern("tools/list", json!({}));
    assert_eq!(
        call(&h, id, frame.clone(), &[("origin", "https://invalid.example")]).await.status,
        StatusCode::FORBIDDEN
    );
    let good = call(
        &h,
        id,
        frame.clone(),
        &[("origin", "https://allowed.example"), ("cookie", "never=forward"), ("x-api-key", "never-forward")],
    )
    .await;
    assert_eq!(good.status, StatusCode::OK, "{}", good.text);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].headers["authorization"], "Bearer upstream-private-token");
    assert!(requests[0].headers.get("cookie").is_none());
    assert!(requests[0].headers.get("x-api-key").is_none());
    assert!(requests[0].headers.get("x-agf-key").is_none());
    assert!(requests[0].headers.get("origin").is_none());
    let url = format!("/api/v1/mcp/proxy/{}", id.as_str().unwrap());
    let bearer = format!("Bearer {}", h.admin);
    let bad = h
        .request_with(
            "POST",
            &url,
            &[("authorization", &bearer), ("mcp-protocol-version", VERSION), ("mcp-method", "tools/call")],
            Some(frame.clone()),
        )
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert_eq!(bad.json()["error"]["code"], -32020);
    assert_eq!(h.request("POST", &url, Some(&h.viewer), Some(frame.clone())).await.status, StatusCode::FORBIDDEN);
    assert_eq!(h.request("POST", &url, None, Some(frame.clone())).await.status, StatusCode::UNAUTHORIZED);
    let foreign = h
        .request_with(
            "POST",
            &url,
            &[("authorization", &bearer), ("x-agf-tenant", &h.other_tenant.to_string())],
            Some(frame.clone()),
        )
        .await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND);
    let rule = h
        .post("/api/v1/runtime/blacklists", json!({"kind":"command","pattern":"http-test-denied","action":"deny"}))
        .await;
    assert_eq!(rule.status, StatusCode::OK);
    assert_eq!(
        call(&h, id, modern("tools/call", json!({"name":"query","arguments":{"command":"http-test-denied"}})), &[])
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1, "blocked tool must never reach upstream");
    let mut updated = row.clone();
    updated.as_object_mut().unwrap().remove("credential_configured");
    updated.as_object_mut().unwrap().remove("updated_at");
    updated.as_object_mut().unwrap().remove("version");
    updated["expected_version"] = json!(1);
    updated["enabled"] = json!(false);
    let saved = h.post("/api/v1/mcp/endpoints", updated.clone()).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.json()["credential_configured"], true);
    assert_eq!(h.post("/api/v1/mcp/endpoints", updated).await.status, StatusCode::CONFLICT);
    assert_eq!(call(&h, id, frame, &[]).await.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        h.state
            .store
            .asset_get(h.tenant, agf_core::ids::Id::parse(id.as_str().unwrap()).unwrap())
            .unwrap()
            .unwrap()
            .protocol,
        Some(agf_core::enums::Protocol::McpHttp)
    );
    let dedicated = agf_api::build_mcp_router(h.state.clone());
    assert_eq!(
        send(&dedicated, Request::builder().uri("/api/v1/settings").body(Body::empty()).unwrap()).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn changing_mcp_destination_requires_an_explicit_credential_decision() {
    let h = setup().await;
    let old_server = MockServer::start().await;
    let next_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":7,"result":{"tools":[]}})))
        .mount(&next_server)
        .await;
    let row = endpoint(&h, &old_server).await;
    let mut changed = json!({"id":row["id"],"expected_version":1,"name":"New destination",
        "url":format!("{}/mcp",next_server.uri()),"enabled":true,"idle_timeout_secs":5});
    assert_eq!(h.post("/api/v1/mcp/endpoints", changed.clone()).await.status, StatusCode::BAD_REQUEST);
    changed["bearer_token"] = json!("");
    let saved = h.post("/api/v1/mcp/endpoints", changed).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.json()["credential_configured"], false);
    let result = call(&h, &row["id"], modern("tools/list", json!({})), &[]).await;
    assert_eq!(result.status, StatusCode::OK, "{}", result.text);
    let requests = next_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].headers.get("authorization").is_none());
    assert!(old_server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn legacy_sessions_are_opaque_bound_and_closed() {
    let h = setup().await;
    let server = MockServer::start().await;
    Mock::given(method("POST")).and(body_partial_json(json!({"method":"initialize"})))
        .respond_with(ResponseTemplate::new(200).insert_header("mcp-session-id","upstream-private-session")
            .set_body_json(json!({"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"loopback","version":"1"}}}))).mount(&server).await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"tools/list"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":2,"result":{"tools":[]}})))
        .mount(&server)
        .await;
    Mock::given(method("DELETE")).respond_with(ResponseTemplate::new(204)).mount(&server).await;
    let row = endpoint(&h, &server).await;
    let url = format!("/api/v1/mcp/proxy/{}", row["id"].as_str().unwrap());
    let initialized = h.post(&url,json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}})).await;
    assert_eq!(initialized.status, StatusCode::OK, "{}", initialized.text);
    let session = initialized.header("mcp-session-id");
    assert!(!session.is_empty());
    assert_ne!(session, "upstream-private-session");
    let token = format!("Bearer {}", h.admin);
    let headers = [
        ("authorization", token.as_str()),
        ("mcp-session-id", session.as_str()),
        ("mcp-protocol-version", "2025-11-25"),
    ];
    assert_eq!(
        h.request_with("POST", &url, &headers, Some(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})))
            .await
            .status,
        StatusCode::OK
    );
    let other_key = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("mcps:execute"), Permission::from_raw("policies:read")],
        ..ApiKeyIssueRequest::named(h.tenant, "other-mcp-caller", Timestamp::now())
    });
    h.state.store.api_key_insert(other_key.record.clone()).unwrap();
    let foreign = h
        .request_with("GET", &url, &[("x-agf-key", &other_key.plaintext), ("mcp-session-id", session.as_str())], None)
        .await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND, "{}", foreign.text);
    assert_eq!(h.request_with("DELETE", &url, &headers, None).await.status, StatusCode::NO_CONTENT);
    assert_eq!(h.request_with("GET", &url, &headers, None).await.status, StatusCode::NOT_FOUND);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[1].headers["mcp-session-id"], "upstream-private-session");
}

#[tokio::test]
async fn sse_inspection_preserves_metadata_and_does_not_buffer_idempotency() {
    let h = setup().await;
    let server = MockServer::start().await;
    let event = json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"p","progress":1}});
    let final_response = json!({"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"safe output sk-proj-abcdefghijklmnopqrstuvwx"}],"_meta":{"vendor":"preserve"}}});
    let sse =
        format!(": ping\r\n\r\nevent: message\r\ndata: {event}\r\n\r\nevent: message\ndata: {final_response}\n\n");
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(sse, "text/event-stream"))
        .mount(&server)
        .await;
    let row = endpoint(&h, &server).await;
    let body = modern("tools/call", json!({"name":"query","arguments":{"query":"hello"}}));
    let response = call(&h, &row["id"], body.clone(), &[("idempotency-key", "repeated-mcp")]).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.header("x-accel-buffering"), "no");
    assert!(response.text.contains("safe output"), "{}", response.text);
    assert!(response.text.contains("preserve"));
    assert!(
        !response.text.contains("sk-proj-abcdefghijklmnopqrstuvwx"),
        "SSE secrets must be redacted: {}",
        response.text
    );
    assert!(response.text.contains("notifications/progress"));
    assert_eq!(call(&h, &row["id"], body, &[("idempotency-key", "repeated-mcp")]).await.status, StatusCode::OK);
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}
