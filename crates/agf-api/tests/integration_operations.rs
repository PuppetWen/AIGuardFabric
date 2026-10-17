//! The API uses saved tenant configuration for real calls, receipts and deduplication.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::ids::Id;
use common::*;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

async fn configure(h: &Harness, vendor: &str, settings: Value, secrets: Value, mock: bool) {
    let result = h
        .request(
            "PUT",
            &format!("/api/v1/integrations/adapters/{vendor}/configuration"),
            Some(&h.admin),
            Some(json!({"expected_version":0,"enabled":true,"mock":mock,"settings":settings,"secrets":secrets})),
        )
        .await;
    assert_eq!(result.status, StatusCode::OK, "{}", result.text);
}
fn request(action: &str, payload: Value) -> Value {
    json!({"request_id":Id::new(),"configuration_version":1,"confirm_live":true,"operation":action,"payload":payload})
}
fn message(key: &str) -> Value {
    json!({"kind":"notification","event_type":"notify.alert","title":"Local integration test",
        "summary":"No external delivery","severity":"medium","idempotency_key":key,
        "occurred_at":"2026-09-20T10:00:00Z","body":{},"labels":{}})
}
#[tokio::test]
async fn saved_webhook_is_called_once_and_version_permission_and_disabled_guards_hold() {
    let mut h = setup().await;
    std::sync::Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = agf_api::build_router(h.state.clone());
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":"remote-123"})))
        .expect(1)
        .mount(&server)
        .await;
    configure(&h, "webhook", json!({}), json!({"webhook_url":format!("{}/hook",server.uri())}), false).await;
    let endpoint = "/api/v1/integrations/adapters/webhook/operations";
    let body = request("send", message("local-once"));
    let mut unconfirmed = body.clone();
    unconfirmed["confirm_live"] = json!(false);
    assert_eq!(h.post(endpoint, unconfirmed).await.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(h.request("POST", endpoint, Some(&h.viewer), Some(body.clone())).await.status, StatusCode::FORBIDDEN);
    let first = h.post(endpoint, body.clone()).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    assert_eq!(first.json()["status"], "succeeded");
    assert_eq!(first.json()["mocked"], false);
    assert_eq!(first.json()["receipt"]["accepted"], true);
    let repeat = h.post(endpoint, body.clone()).await;
    assert_eq!(repeat.json(), first.json(), "duplicate request reuses the durable receipt");
    let mut collision = body.clone();
    collision["payload"]["title"] = json!("Changed");
    assert_eq!(h.post(endpoint, collision).await.status, StatusCode::CONFLICT);
    let mut stale = body.clone();
    stale["configuration_version"] = json!(0);
    assert_eq!(h.post(endpoint, stale).await.status, StatusCode::CONFLICT);
    let history = h.get(endpoint).await.json();
    assert_eq!(history["items"].as_array().unwrap().len(), 1);
    assert!(history["items"][0].get("receipt").is_none());
    let mut row = agf_api::integration_store::load(&h.state, h.tenant, "webhook").await.unwrap().unwrap();
    row.enabled = false;
    row.version += 1;
    h.state.configurations.put(h.tenant, agf_api::integration_store::KIND, row.id, &row).await.unwrap();
    assert_eq!(h.post(endpoint, request("send", message("disabled"))).await.status, StatusCode::PRECONDITION_FAILED);
}
#[tokio::test]
async fn jira_send_pull_push_and_sync_reach_local_transport_and_preserve_tenant_history() {
    let mut h = setup().await;
    std::sync::Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = agf_api::build_router(h.state.clone());
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/api/2/issue"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id":"1","key":"SEC-1"})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/rest/api/2/issue/SEC-1/comment"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id":"comment-1"})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET")).and(path("/rest/api/2/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"issues":[{"key":"SEC-1","fields":{"updated":"2026-09-20T10:00:00Z","status":{"name":"Open"}}}],"total":1})))
        .expect(2).mount(&server).await;
    configure(
        &h,
        "jira",
        json!({"base_url":server.uri(),"project_key":"SEC"}),
        json!({"user_email":"local@example.test","api_token":"LOCAL-ONLY"}),
        false,
    )
    .await;
    let endpoint = "/api/v1/integrations/adapters/jira/operations";
    for body in [
        request("send", message("jira-local")),
        request("push", json!({"entity":"ticket.status","entity_id":"SEC-1","body":{"comment":"Verified"}})),
        request("pull", json!({"resource":"issues","limit":10})),
        request("sync", json!({"resource":"issues","limit":10,"local":[]})),
    ] {
        let result = h.post(endpoint, body).await;
        assert_eq!(result.status, StatusCode::OK, "{}", result.text);
        assert_eq!(result.json()["status"], "succeeded", "{}", result.text);
        assert_eq!(result.json()["mocked"], false);
    }
    let foreign = h
        .request_with(
            "GET",
            endpoint,
            &[("Authorization", &format!("Bearer {}", h.admin)), ("X-AGF-Tenant", &h.other_tenant.to_string())],
            None,
        )
        .await;
    assert_eq!(foreign.json()["items"].as_array().unwrap().len(), 0);
}
#[tokio::test]
async fn mock_calls_and_upstream_failures_are_distinguished_in_receipts() {
    let mut h = setup().await;
    std::sync::Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = agf_api::build_router(h.state.clone());
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/failed"))
        .respond_with(ResponseTemplate::new(400).set_body_string("rejected LOCAL-SECRET"))
        .expect(1)
        .mount(&server)
        .await;
    configure(
        &h,
        "webhook",
        json!({}),
        json!({"webhook_url":format!("{}/failed",server.uri()),"auth_header_value":"LOCAL-SECRET"}),
        false,
    )
    .await;
    let failed = h.post("/api/v1/integrations/adapters/webhook/operations", request("send", message("failure"))).await;
    assert_eq!(failed.status, StatusCode::OK, "{}", failed.text);
    assert_eq!(failed.json()["status"], "failed");
    assert!(!failed.text.contains("LOCAL-SECRET"));
    configure(&h, "feishu", json!({}), json!({}), true).await;
    let mocked = h.post("/api/v1/integrations/adapters/feishu/operations", request("send", message("mock"))).await;
    assert_eq!(mocked.json()["status"], "succeeded", "{}", mocked.text);
    assert_eq!(mocked.json()["mocked"], true);
    assert_eq!(mocked.json()["receipt"]["mocked"], true);
}
