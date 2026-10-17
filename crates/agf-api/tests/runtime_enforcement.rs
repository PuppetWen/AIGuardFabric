//! 真实请求入口回归：黑名单 CRUD、租户隔离、MCP 拦截与模型策略。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;

async fn check(h: &Harness, command: &str) -> Resp {
    h.post("/api/v1/runtime/mcp/check", json!({"session_id":"test-mcp",
        "frame":{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query","arguments":{"command":command}}}})).await
}
#[tokio::test]
async fn saved_blacklist_blocks_until_disabled_and_does_not_affect_other_tenants() {
    let h = setup().await;
    let added = h
        .post(
            "/api/v1/runtime/blacklists",
            json!({"kind":"command","pattern":"unique-test-command",
        "action":"deny","scope":"tenant","note":"test"}),
        )
        .await;
    assert_eq!(added.status, StatusCode::OK, "{}", added.text);
    let id = added.json()["id"].as_str().unwrap().to_string();
    let blocked = check(&h, "unique-test-command").await;
    assert_eq!(blocked.status, StatusCode::OK, "{}", blocked.text);
    assert_eq!(blocked.json()["allowed"], false);
    let token = format!("Bearer {}", h.admin);
    let other = h.other_tenant.to_string();
    let response = h
        .request_with(
            "POST",
            "/api/v1/runtime/mcp/check",
            &[("Authorization", &token), ("X-AGF-Tenant", &other)],
            Some(json!({"session_id":"other","frame":{"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"query","arguments":{"command":"unique-test-command"}}}})),
        )
        .await;
    assert_eq!(response.json()["allowed"], true, "{}", response.text);
    let toggled = h
        .request(
            "PATCH",
            &format!("/api/v1/runtime/blacklists/{id}"),
            Some(&h.admin),
            Some(json!({"enabled":false,"expected_version":added.json()["version"]})),
        )
        .await;
    assert_eq!(toggled.status, StatusCode::OK, "{}", toggled.text);
    assert_eq!(check(&h, "unique-test-command").await.json()["allowed"], true);
    let rows = h.get("/api/v1/runtime/blacklists").await.json();
    assert_eq!(rows.as_array().unwrap().iter().find(|row| row["id"] == id).unwrap()["enabled"], false);
    assert_eq!(
        h.request(
            "DELETE",
            &format!("/api/v1/runtime/blacklists/{id}?expected_version={}", toggled.json()["version"]),
            Some(&h.admin),
            None
        )
        .await
        .status,
        StatusCode::OK
    );
    let rows = h.get("/api/v1/runtime/blacklists").await.json();
    assert!(!rows.as_array().unwrap().iter().any(|row| row["id"] == id));
    assert_eq!(
        h.post("/api/v1/runtime/blacklists", json!({"kind":"command","pattern":"re:[","action":"deny"})).await.status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn gateway_uses_saved_cel_policy_before_calling_provider() {
    let h = setup().await;
    h.post(
        "/api/v1/gateway/endpoints",
        json!({"name":"test","provider":"mock","model":"offline","base_url":"http://mock.invalid"}),
    )
    .await;
    let policy = h
        .post(
            "/api/v1/policies",
            json!({"name":"deny-gateway","language":"cel","source":"{\"action\":\"deny\",\"reason\":\"test deny\"}",
        "action":"deny","enabled":true,"intercept_points":["ai-gateway"]}),
        )
        .await;
    assert_eq!(policy.status, StatusCode::CREATED, "{}", policy.text);
    let response = h
        .post("/api/v1/chat/completions", json!({"model":"auto","messages":[{"role":"user","content":"hello"}]}))
        .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN, "{}", response.text);
    assert!(h.state.meter.recent(10).is_empty());
    assert!(!h.state.runtime.audit().by_tenant(h.tenant).is_empty());
}
