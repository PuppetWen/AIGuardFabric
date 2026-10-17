//! 配置持久化、密钥脱敏，以及本地 HTTP 接收端上的真实投递/业务失败。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::notification_config::{self, StoredChannel};
use agf_core::notify::ChannelKind;
use common::*;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

#[tokio::test]
async fn notification_configuration_is_encrypted_and_blank_preserves_secrets() {
    let h = setup().await;
    let saved = h
        .request(
            "PUT",
            "/api/v1/settings/notifications/webhook",
            Some(&h.admin),
            Some(json!({
        "enabled":true,"target":"https://example.test/hook?token=private-test-value","settings":{},
        "secrets":{"auth_header_value":"Bearer private-test-token"}})),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert!(!saved.text.contains("private-test"));
    let raw = h.state.configurations.list::<Value>(h.tenant, "notification-channel").await.unwrap();
    assert!(!serde_json::to_string(&raw).unwrap().contains("private-test"));
    let saved = h
        .request(
            "PUT",
            "/api/v1/settings/notifications/webhook",
            Some(&h.admin),
            Some(json!({
        "expectedVersion":1,"enabled":true,"target":"","settings":{},"secrets":{}})),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let delivery = h.post("/api/v1/settings/notifications/webhook/test", json!({})).await;
    assert_eq!(delivery.status, StatusCode::OK, "{}", delivery.text);
    assert_eq!(delivery.json()["mocked"], true);
    assert_eq!(delivery.json()["any_delivered"], true);
    assert_eq!(
        h.request("PUT", "/api/v1/settings/notifications/webhook", Some(&h.viewer), Some(json!({"enabled":false})))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn notification_destination_change_requires_fresh_secret_and_rejects_stale_edits() {
    let h = setup().await;
    let uri = "/api/v1/settings/notifications/webhook";
    let initial = h
        .request(
            "PUT",
            uri,
            Some(&h.admin),
            Some(json!({
                "enabled":true,"target":"https://first.invalid/hook","settings":{},
                "secrets":{"auth_header_value":"Bearer first-secret"}
            })),
        )
        .await;
    assert_eq!(initial.status, StatusCode::OK, "{}", initial.text);
    assert_eq!(initial.json()["version"], 1);
    let change = json!({"expectedVersion":1,"enabled":true,"target":"https://second.invalid/hook",
        "settings":{},"secrets":{}});
    assert_eq!(h.request("PUT", uri, Some(&h.admin), Some(change.clone())).await.status, StatusCode::BAD_REQUEST);
    let row = h
        .state
        .configurations
        .get::<StoredChannel>(
            h.tenant,
            notification_config::KIND,
            notification_config::id(h.tenant, ChannelKind::Webhook),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.version, 1);
    assert_eq!(notification_config::decrypt(&h.state, h.tenant, &row).unwrap().target, "https://first.invalid/hook");
    let mut fresh = change.clone();
    fresh["secrets"] = json!({"auth_header_value":"Bearer second-secret"});
    let saved = h.request("PUT", uri, Some(&h.admin), Some(fresh)).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.json()["version"], 2);
    assert_eq!(h.request("PUT", uri, Some(&h.admin), Some(change)).await.status, StatusCode::CONFLICT);
    let row = h
        .state
        .configurations
        .get::<StoredChannel>(
            h.tenant,
            notification_config::KIND,
            notification_config::id(h.tenant, ChannelKind::Webhook),
        )
        .await
        .unwrap()
        .unwrap();
    let private = notification_config::decrypt(&h.state, h.tenant, &row).unwrap();
    assert_eq!(private.target, "https://second.invalid/hook");
    assert_eq!(private.secrets["auth_header_value"], "Bearer second-secret");
    let update = || {
        serde_json::from_value(json!({"expectedVersion":2,"enabled":false,
        "target":"","settings":{},"secrets":{}}))
        .unwrap()
    };
    let (left, right) = tokio::join!(
        notification_config::save(&h.state, h.tenant, ChannelKind::Webhook, update()),
        notification_config::save(&h.state, h.tenant, ChannelKind::Webhook, update()),
    );
    assert_eq!(u8::from(left.is_ok()) + u8::from(right.is_ok()), 1);
    assert_eq!(u8::from(left.is_err()) + u8::from(right.is_err()), 1);
}

#[tokio::test]
async fn configured_live_channel_reaches_local_receiver_and_persists_receipt() {
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = agf_api::build_router(h.state.clone());
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/agf"))
        .and(header("authorization", "Bearer test-only"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":"local-receipt"})))
        .expect(1)
        .mount(&server)
        .await;
    let saved = h.request("PUT", "/api/v1/settings/notifications/webhook", Some(&h.admin), Some(json!({
        "enabled":true,"target":format!("{}/agf",server.uri()),"settings":{},"secrets":{"auth_header_value":"Bearer test-only"}}))).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let sent = h
        .post("/api/v1/notifications/send", json!({"subject_kind":"custom","title":"Local test","severity":"high"}))
        .await;
    assert_eq!(sent.status, StatusCode::OK, "{}", sent.text);
    assert_eq!(sent.json()["mocked"], false);
    assert_eq!(sent.json()["any_delivered"], true, "{}", sent.text);
    let requests = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["title"], "Local test");
    assert!(!h.get("/api/v1/notifications/history").await.json().as_array().unwrap().is_empty());
}

#[tokio::test]
async fn live_sms_business_failure_is_not_success_and_inbox_is_persisted() {
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = agf_api::build_router(h.state.clone());
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"accepted":false})))
        .mount(&server)
        .await;
    let saved = h
        .request(
            "PUT",
            "/api/v1/settings/notifications/sms",
            Some(&h.admin),
            Some(json!({
        "enabled":true,"target":"+15550000000","settings":{"endpoint":server.uri()},"secrets":{}})),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let sent = h.post("/api/v1/settings/notifications/sms/test", json!({})).await;
    assert_eq!(sent.json()["any_delivered"], false, "{}", sent.text);
    assert_eq!(sent.json()["deliveries"][0]["outcome"], "failed");
    let saved =
        h.request("PUT", "/api/v1/settings/notifications/in-app", Some(&h.admin), Some(json!({"enabled":true}))).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(h.post("/api/v1/settings/notifications/in-app/test", json!({})).await.json()["any_delivered"], true);
    assert_eq!(h.get("/api/v1/notifications/inbox").await.json().as_array().unwrap().len(), 1);
}
