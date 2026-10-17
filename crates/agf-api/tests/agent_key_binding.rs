//! Agent API keys carry the administrator's binding through gateway and MCP quota enforcement.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::enums::AssetKind;
use agf_core::ids::Id;
use common::*;

async fn key(h: &Harness, agent: Id) -> String {
    let created = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":"bound-agent",
        "scopes":["policies:read","models:read","models:write"],"bound_agent_id":agent,"expires_in_secs":3600}),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    assert_eq!(created.json()["api_key"]["bound_agent_id"], agent.to_string());
    created.json()["plaintext"].as_str().unwrap().to_owned()
}
#[tokio::test]
async fn bound_key_authenticates_and_cannot_bypass_agent_quota_with_a_new_session() {
    let h = setup().await;
    assert_eq!(seed_ai_assets(&h).await.status, StatusCode::OK);
    let agent = asset_id_of(&h, AssetKind::Agent);
    let key = key(&h, agent).await;
    let quota = h
        .post(
            "/api/v1/quotas",
            json!({"name":"agent-limit","scope":"agent","dimension":"requests","window":"total","limit":1}),
        )
        .await;
    assert!(quota.status.is_success(), "{}", quota.text);
    let one = h
        .request(
            "POST",
            "/api/v1/runtime/mcp/check",
            Some(&key),
            Some(json!({"session_id":"one",
        "frame":{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}})),
        )
        .await;
    assert_eq!(one.status, StatusCode::OK, "{}", one.text);
    assert_eq!(one.json()["allowed"], true);
    let two = h
        .request(
            "POST",
            "/api/v1/runtime/mcp/check",
            Some(&key),
            Some(json!({"session_id":"two",
        "frame":{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"world"}}}})),
        )
        .await;
    assert_eq!(two.status, StatusCode::TOO_MANY_REQUESTS, "{}", two.text);
    let spoof = h
        .request(
            "POST",
            "/api/v1/runtime/mcp/check",
            Some(&key),
            Some(json!({"session_id":"spoof","agent_id":Id::new(),
        "frame":{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{}}}})),
        )
        .await;
    assert_eq!(spoof.status, StatusCode::FORBIDDEN, "{}", spoof.text);
}
#[tokio::test]
async fn gateway_uses_binding_without_client_agent_header_and_rejects_impersonation() {
    let h = setup().await;
    seed_ai_assets(&h).await;
    let agent = asset_id_of(&h, AssetKind::Agent);
    let key = key(&h, agent).await;
    let endpoint = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({"name":"offline","provider":"mock","model":"bound-model","base_url":"http://mock.invalid"}),
        )
        .await;
    assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
    let quota = h
        .post(
            "/api/v1/quotas",
            json!({"name":"agent-model-limit","scope":"agent","dimension":"requests","window":"total","limit":1}),
        )
        .await;
    assert!(quota.status.is_success(), "{}", quota.text);
    let body = json!({"model":"bound-model","messages":[{"role":"user","content":"hello"}],"max_tokens":16});
    assert_eq!(h.request("POST", "/v1/chat/completions", Some(&key), Some(body.clone())).await.status, StatusCode::OK);
    assert_eq!(
        h.request("POST", "/v1/chat/completions", Some(&key), Some(body.clone())).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    let spoof = h
        .request_with(
            "POST",
            "/v1/chat/completions",
            &[
                ("Authorization", &format!("Bearer {key}")),
                ("X-AGF-Agent", &asset_id_of(&h, AssetKind::Skill).to_string()),
            ],
            Some(body),
        )
        .await;
    assert_eq!(spoof.status, StatusCode::FORBIDDEN, "{}", spoof.text);
}
#[tokio::test]
async fn binding_requires_an_agent_owned_by_the_selected_tenant() {
    let h = setup().await;
    seed_ai_assets(&h).await;
    for agent in [Id::new(), asset_id_of(&h, AssetKind::Skill)] {
        let result = h
            .post(
                "/api/v1/settings/api-keys",
                json!({"name":"invalid","scopes":["models:read"],"bound_agent_id":agent}),
            )
            .await;
        assert_eq!(result.status, StatusCode::BAD_REQUEST);
    }
    let agent = asset_id_of(&h, AssetKind::Agent);
    let result = h
        .request_with(
            "POST",
            "/api/v1/settings/api-keys",
            &[("Authorization", &format!("Bearer {}", h.admin)), ("X-AGF-Tenant", &h.other_tenant.to_string())],
            Some(json!({"name":"foreign","scopes":["models:read"],"bound_agent_id":agent})),
        )
        .await;
    assert_eq!(result.status, StatusCode::BAD_REQUEST);
}
