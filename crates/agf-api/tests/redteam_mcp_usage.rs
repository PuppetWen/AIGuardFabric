//! Direct red-team MCP calls share quota enforcement and tenant-scoped usage.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{
    asset::Asset,
    enums::{AssetKind, QuotaDimension},
    ids::Id,
    quota::Quota,
    redteam::RedteamCase,
};
use agf_scan::redteam::CaseLibrary;
use common::*;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

const CANARY: &str = "MCP_MeterProtected_aec294183";
const TOKEN: &str = "private-meter-test-token";

async fn fixture() -> Harness {
    let mut h = setup().await;
    let case: RedteamCase =
        serde_yaml::from_str(include_str!("../../../redteam/credential-theft/RT-MCP-001.yaml")).unwrap();
    h.state.redteam_cases = Arc::new(CaseLibrary::from_cases(vec![case]));
    h.app = build_router(h.state.clone());
    h
}

async fn profile(h: &Harness, server: &MockServer) -> String {
    profile_with_id(h, server, None).await
}

async fn profile_with_id(h: &Harness, server: &MockServer, id: Option<&str>) -> String {
    let asset = Asset::new(h.tenant, AssetKind::McpServer, "metered MCP", "test");
    h.state.store.asset_upsert(&asset).unwrap();
    let saved = h
        .post(
            "/api/v1/redteam/mcp-targets",
            json!({
                "id":id,"expected_version":0,"asset_id":asset.id,"name":"Metered MCP fixture",
                "url":format!("{}/mcp",server.uri()),"tool_name":"safe_query",
                "argument_name":"query","enabled":true,"protected_canary":CANARY,"bearer_token":TOKEN
            }),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    saved.json()["id"].as_str().unwrap().to_owned()
}

async fn list_tools(server: &MockServer, expected: u64) {
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(header("mcp-method", "tools/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0","id":1,"result":{"tools":[{
                "name":"safe_query","annotations":{"readOnlyHint":true},
                "inputSchema":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}
            }]}
        })))
        .expect(expected)
        .mount(server)
        .await;
}

async fn tool_response(server: &MockServer, response: ResponseTemplate, expected: u64) {
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(header("mcp-method", "tools/call"))
        .and(header("mcp-name", "safe_query"))
        .respond_with(response)
        .expect(expected)
        .mount(server)
        .await;
}

async fn launch(h: &Harness, id: &str) -> Value {
    let started = h
        .post(
            "/api/v1/redteam/campaigns",
            json!({
                "name":"MCP usage fixture","execution_mode":"mcp-http","target_profile_id":id,
                "target_profile_version":1,"case_keys":["RT-MCP-001"],"max_cases":1,"ci_gate":true
            }),
        )
        .await;
    assert_eq!(started.status, StatusCode::ACCEPTED, "{}", started.text);
    let task = started.json()["task_id"].as_str().unwrap().to_owned();
    for _ in 0..100 {
        let status = h.get(&format!("/api/v1/redteam/campaigns/{task}")).await;
        let value = status.json();
        if matches!(value["campaign"]["state"].as_str(), Some("completed" | "failed" | "cancelled")) {
            return value;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("MCP campaign did not finish");
}

async fn quota(h: &Harness, dimension: QuotaDimension) -> Id {
    agf_api::quota_definitions::save(&h.state, h.tenant, Quota::tenant_default(h.tenant, dimension, 1))
        .await
        .unwrap()
        .id
}

async fn usage(h: &Harness, id: &str) -> Value {
    let response = h.get(&format!("/api/v1/redteam/mcp-targets/{id}/usage")).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert!(!response.text.contains(CANARY));
    assert!(!response.text.contains(TOKEN));
    let value = response.json();
    assert_eq!(value["source"], "redteam-mcp");
    assert_eq!(value["target_profile_id"], id);
    assert!(value.get("endpoint_id").is_none());
    value
}

fn failed_responses() -> Vec<(&'static str, ResponseTemplate)> {
    let json = |body| ResponseTemplate::new(200).set_body_json(body);
    vec![
        (
            "tool error",
            json(json!({"jsonrpc":"2.0","id":1,"result":{
                "isError":true,"content":[{"type":"text","text":"private upstream failure"}]
            }})),
        ),
        ("HTTP failure", ResponseTemplate::new(503)),
        (
            "JSON-RPC error",
            json(json!({"jsonrpc":"2.0","id":1,"error":{
                "code":-32603,"message":"private upstream failure"
            }})),
        ),
        ("missing result", json(json!({"jsonrpc":"2.0","id":1}))),
        ("null result", json(json!({"jsonrpc":"2.0","id":1,"result":null}))),
        ("array result", json(json!({"jsonrpc":"2.0","id":1,"result":[]}))),
        ("server request", json(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","result":{"content":[]}}))),
        ("invalid content", json(json!({"jsonrpc":"2.0","id":1,"result":{"content":{}}}))),
        ("invalid error flag", json(json!({"jsonrpc":"2.0","id":1,"result":{"content":[],"isError":"false"}}))),
        ("wrong request ID", json(json!({"jsonrpc":"2.0","id":2,"result":{"content":[]}}))),
        ("invalid JSON", ResponseTemplate::new(200).set_body_raw("{broken", "application/json")),
    ]
}

#[tokio::test]
async fn received_tool_failures_are_failed_and_release_concurrency() {
    for (name, response) in failed_responses() {
        let h = fixture().await;
        let concurrency = quota(&h, QuotaDimension::Concurrency).await;
        let requests = quota(&h, QuotaDimension::Requests).await;
        let server = MockServer::start().await;
        list_tools(&server, 1).await;
        tool_response(&server, response, 1).await;
        let id = profile(&h, &server).await;
        let finished = launch(&h, &id).await;
        assert_eq!(finished["campaign"]["state"], "completed", "{name}: {finished}");
        assert_eq!(finished["campaign"]["ci_passed"], false, "{name}: {finished}");
        let value = usage(&h, &id).await;
        let items = value["items"].as_array().unwrap();
        assert_eq!(items.len(), 1, "tools/list must not create a usage row: {name}: {value}");
        let row = &items[0];
        assert_eq!(row["name"], "safe_query", "{name}: {value}");
        assert_eq!(row["attempts"], 1, "{name}: {value}");
        assert_eq!(row["failed"], 1, "{name}: {value}");
        assert_eq!(row["succeeded"], 0, "{name}: {value}");
        assert_eq!(row["unknown"], 0, "{name}: {value}");
        assert_eq!(row["inflight"], 0, "{name}: {value}");
        let consumed = agf_api::runtime_quota::usage(&h.state, h.tenant).await.unwrap();
        assert_eq!(consumed[&concurrency], 0, "{name}: {consumed:?}");
        assert_eq!(consumed[&requests], 1, "{name}: {consumed:?}");
        assert_eq!(server.received_requests().await.unwrap().len(), 2, "{name}");
    }
}

#[tokio::test]
async fn exhausted_request_quota_allows_discovery_but_sends_no_second_tool_call() {
    let h = fixture().await;
    let concurrency = quota(&h, QuotaDimension::Concurrency).await;
    let requests = quota(&h, QuotaDimension::Requests).await;
    let server = MockServer::start().await;
    list_tools(&server, 2).await;
    tool_response(
        &server,
        ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"safe fixture output"}]}
        })),
        1,
    )
    .await;
    let id = profile(&h, &server).await;
    assert_eq!(launch(&h, &id).await["campaign"]["ci_passed"], true);
    let before = usage(&h, &id).await;
    assert_eq!(before["items"][0]["attempts"], 1);
    assert_eq!(before["items"][0]["succeeded"], 1);
    let second = launch(&h, &id).await;
    assert_eq!(second["campaign"]["state"], "completed", "{second}");
    assert_eq!(second["campaign"]["ci_passed"], false, "{second}");
    let after = usage(&h, &id).await;
    assert_eq!(after["items"], before["items"], "a rejected tool call must not be counted: {after}");
    let consumed = agf_api::runtime_quota::usage(&h.state, h.tenant).await.unwrap();
    assert_eq!(consumed[&requests], 1);
    assert_eq!(consumed[&concurrency], 0);
    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 3);
    assert_eq!(received.iter().filter(|call| call.headers["mcp-method"] == "tools/list").count(), 2);
    assert_eq!(received.iter().filter(|call| call.headers["mcp-method"] == "tools/call").count(), 1);
}

#[tokio::test]
async fn target_usage_requires_read_scopes_and_is_isolated_from_other_tenants() {
    let h = fixture().await;
    let server = MockServer::start().await;
    list_tools(&server, 1).await;
    tool_response(
        &server,
        ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"safe fixture output"}]}
        })),
        1,
    )
    .await;
    let id = profile(&h, &server).await;
    launch(&h, &id).await;
    let uri = format!("/api/v1/redteam/mcp-targets/{id}/usage");
    assert_eq!(h.request("GET", &uri, None, None).await.status, StatusCode::UNAUTHORIZED);
    for (tenant, scopes, expected) in [
        (h.tenant, vec!["redteam:read", "mcps:read"], StatusCode::OK),
        (h.tenant, vec!["redteam:read"], StatusCode::FORBIDDEN),
        (h.tenant, vec!["mcps:read"], StatusCode::FORBIDDEN),
        (h.other_tenant, vec!["redteam:read", "mcps:read"], StatusCode::NOT_FOUND),
    ] {
        let key = h.state.api_keys.issue(ApiKeyIssueRequest {
            scopes: scopes.into_iter().map(Permission::from_raw).collect(),
            ..ApiKeyIssueRequest::named(tenant, "redteam-usage-reader", Timestamp::now())
        });
        h.state.store.api_key_insert(key.record.clone()).unwrap();
        let response = h.request_with("GET", &uri, &[("x-agf-key", &key.plaintext)], None).await;
        assert_eq!(response.status, expected, "{}", response.text);
        if expected == StatusCode::OK {
            assert_eq!(response.json()["items"][0]["succeeded"], 1);
        } else {
            assert!(!response.text.contains("safe_query"));
            assert!(!response.text.contains("Metered MCP fixture"));
        }
        assert!(!response.text.contains(CANARY));
        assert!(!response.text.contains(TOKEN));
    }
}

#[tokio::test]
async fn proxy_and_redteam_usage_remain_separate_when_their_ids_and_tool_names_overlap() {
    let h = fixture().await;
    let server = MockServer::start().await;
    list_tools(&server, 1).await;
    tool_response(
        &server,
        ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"safe fixture output"}]}
        })),
        2,
    )
    .await;
    let proxy = h
        .post(
            "/api/v1/mcp/endpoints",
            json!({"expected_version":0,"name":"Overlapping proxy ID","url":format!("{}/mcp",server.uri()),
                "enabled":true,"idle_timeout_secs":5,"allowed_origins":[],"bearer_token":TOKEN}),
        )
        .await;
    assert_eq!(proxy.status, StatusCode::OK, "{}", proxy.text);
    let endpoint_id = proxy.json()["id"].as_str().unwrap().to_owned();
    let profile_id = profile_with_id(&h, &server, Some(&endpoint_id)).await;
    assert_eq!(profile_id, endpoint_id);
    assert_eq!(launch(&h, &profile_id).await["campaign"]["ci_passed"], true);
    let redteam_before = usage(&h, &profile_id).await;
    assert_eq!(redteam_before["items"][0]["attempts"], 1);
    let proxy_usage_path = format!("/api/v1/mcp/endpoints/{endpoint_id}/usage");
    let untouched_proxy = h.get(&proxy_usage_path).await;
    assert_eq!(untouched_proxy.status, StatusCode::OK, "{}", untouched_proxy.text);
    assert_eq!(untouched_proxy.json()["items"], json!([]));
    let token = format!("Bearer {}", h.admin);
    let response = h
        .request_with(
            "POST",
            &format!("/api/v1/mcp/proxy/{endpoint_id}"),
            &[
                ("authorization", &token),
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "tools/call"),
                ("mcp-name", "safe_query"),
            ],
            Some(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
                "name":"safe_query","arguments":{"query":"safe proxy query"},
                "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}})),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let proxy_usage = h.get(&proxy_usage_path).await;
    assert_eq!(proxy_usage.status, StatusCode::OK, "{}", proxy_usage.text);
    let proxy_counts = proxy_usage.json();
    assert_eq!(proxy_counts["endpoint_id"], endpoint_id);
    assert_eq!(proxy_counts["items"][0]["name"], "safe_query");
    assert_eq!(proxy_counts["items"][0]["attempts"], 1);
    assert_eq!(proxy_counts["items"][0]["succeeded"], 1);
    assert_eq!(usage(&h, &profile_id).await["items"], redteam_before["items"]);
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}
