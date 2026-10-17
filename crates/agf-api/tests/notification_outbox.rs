//! Notification persistence, retries, tenant isolation and severity escalation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::{
    notification_config::{self, StoredChannel},
    notification_outbox as queue,
};
use agf_core::{enums::Severity, ids::Id};
use common::*;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

async fn channel(h: &Harness, kind: &str, extra: Value) -> StoredChannel {
    let mut body = json!({"enabled":true,"minSeverity":"info","settings":{},"secrets":{}});
    body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    let key = notification_config::id(h.tenant, notification_config::parse(kind).unwrap());
    let current: Option<StoredChannel> =
        h.state.configurations.get(h.tenant, notification_config::KIND, key).await.unwrap();
    body["expectedVersion"] = json!(current.map_or(0, |row| row.version));
    let saved = h.request("PUT", &format!("/api/v1/settings/notifications/{kind}"), Some(&h.admin), Some(body)).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    h.state
        .configurations
        .get(
            h.tenant,
            notification_config::KIND,
            notification_config::id(h.tenant, notification_config::parse(kind).unwrap()),
        )
        .await
        .unwrap()
        .unwrap()
}
async fn enqueue(h: &Harness, row: StoredChannel, subject: Id, severity: Severity) -> Id {
    queue::enqueue(
        &h.state,
        h.tenant,
        vec![row],
        "custom",
        subject,
        "private-outbox-title",
        "private-outbox-message",
        severity,
    )
    .await
    .unwrap()[0]
}

#[tokio::test]
async fn concurrent_delivery_is_idempotent_and_escalation_delivers_again() {
    let h = setup().await;
    let row = channel(&h, "in-app", json!({})).await;
    let subject = Id::new();
    let id = enqueue(&h, row.clone(), subject, Severity::Low).await;
    let raw = h.state.configurations.list::<Value>(h.tenant, queue::KIND).await.unwrap();
    assert!(!serde_json::to_string(&raw).unwrap().contains("private-outbox"));
    let (a, b) = tokio::join!(
        queue::attempt(&h.state, h.tenant, id, Timestamp::now()),
        queue::attempt(&h.state, h.tenant, id, Timestamp::now())
    );
    assert!(a.is_ok() && b.is_ok());
    assert_eq!(h.get("/api/v1/notifications/inbox").await.json().as_array().unwrap().len(), 1);
    assert_eq!(enqueue(&h, row.clone(), subject, Severity::Low).await, id);
    let escalation = enqueue(&h, row, subject, Severity::Critical).await;
    assert_ne!(escalation, id);
    queue::attempt(&h.state, h.tenant, escalation, Timestamp::now()).await.unwrap();
    assert_eq!(h.get("/api/v1/notifications/inbox").await.json().as_array().unwrap().len(), 2);
    assert!(queue::attempt(&h.state, h.other_tenant, id, Timestamp::now()).await.is_err());
    assert!(queue::history(&h.state, h.other_tenant).await.unwrap().is_empty());
}

#[tokio::test]
async fn failed_delivery_retries_after_restart_and_keeps_idempotency_key() {
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"accepted":false})))
        .expect(1)
        .mount(&server)
        .await;
    let row = channel(&h, "sms", json!({"target":"+15550000000","settings":{"endpoint":server.uri()}})).await;
    let id = enqueue(&h, row, Id::new(), Severity::High).await;
    let failed = queue::attempt(&h.state, h.tenant, id, Timestamp::now()).await.unwrap();
    assert_eq!(failed["status"], "retrying");
    assert_eq!(failed["attempts"], 1);
    let requests = server.received_requests().await.unwrap();
    let first: Value = serde_json::from_slice(&requests[0].body).unwrap();
    let mut restarted = setup().await;
    Arc::make_mut(&mut restarted.state.config).mock_mode = false;
    restarted.state.configurations = h.state.configurations.clone();
    // Same persisted configuration + encryption key, with a new dispatcher and state.
    let pending = queue::attempt(&restarted.state, h.tenant, id, Timestamp::now()).await.unwrap();
    assert_eq!(pending["attempts"], 1);
    server.reset().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"accepted":true})))
        .expect(1)
        .mount(&server)
        .await;
    let done = queue::attempt(&restarted.state, h.tenant, id, Timestamp::now().offset_secs(31)).await.unwrap();
    assert_eq!(done["status"], "delivered", "{done}");
    assert_eq!(done["attempts"], 2);
    let requests = server.received_requests().await.unwrap();
    let second: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(first["idempotency_key"], second["idempotency_key"]);
    assert!(queue::retry(&h.state, h.tenant, id).await.is_err());
}

#[tokio::test]
async fn disabled_channels_and_mode_changes_cancel_queued_work() {
    let mut h = setup().await;
    let row = channel(&h, "sms", json!({"target":"+15550000000","settings":{"endpoint":"http://127.0.0.1:9"}})).await;
    let id = enqueue(&h, row.clone(), Id::new(), Severity::High).await;
    channel(&h, "sms", json!({"enabled":false})).await;
    let result = queue::attempt(&h.state, h.tenant, id, Timestamp::now()).await.unwrap();
    assert_eq!(result["status"], "suppressed");
    let id = enqueue(&h, row, Id::new(), Severity::High).await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    let result = queue::attempt(&h.state, h.tenant, id, Timestamp::now()).await.unwrap();
    assert_eq!(result["status"], "suppressed");
    assert!(result["error"].as_str().unwrap().contains("模式"));
}

#[tokio::test]
async fn slow_external_channel_does_not_block_inbox_delivery() {
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"accepted":true}))
                .set_delay(std::time::Duration::from_millis(900)),
        )
        .mount(&server)
        .await;
    let external = channel(&h, "sms", json!({"target":"+15550000000","settings":{"endpoint":server.uri()}})).await;
    let inbox = channel(&h, "in-app", json!({})).await;
    let slow_id = enqueue(&h, external, Id::new(), Severity::High).await;
    let fast_id = enqueue(&h, inbox, Id::new(), Severity::High).await;
    let state = h.state.clone();
    let tenant = h.tenant;
    let slow = tokio::spawn(async move { queue::attempt(&state, tenant, slow_id, Timestamp::now()).await });
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while server.received_requests().await.unwrap().is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let fast = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        queue::attempt(&h.state, tenant, fast_id, Timestamp::now()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(fast["status"], "delivered");
    assert_eq!(slow.await.unwrap().unwrap()["status"], "delivered");
}

#[tokio::test]
async fn exhausted_retries_remain_visible_and_operator_can_retry_with_rbac() {
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"accepted":false})))
        .expect(8)
        .mount(&server)
        .await;
    let row = channel(&h, "sms", json!({"target":"+15550000000","settings":{"endpoint":server.uri()}})).await;
    let id = enqueue(&h, row, Id::new(), Severity::High).await;
    let now = Timestamp::now();
    for round in 0..8 {
        queue::attempt(&h.state, h.tenant, id, now.offset_secs(round * 1000)).await.unwrap();
    }
    let final_state = queue::history(&h.state, h.tenant).await.unwrap();
    assert_eq!(final_state[0]["status"], "failed");
    assert_eq!(final_state[0]["attempts"], 8);
    let path = format!("/api/v1/notifications/{id}/retry");
    assert_eq!(h.request("POST", &path, Some(&h.viewer), None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(h.post(&path, json!({})).await.status, StatusCode::OK);
    server.reset().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"accepted":true})))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(queue::attempt(&h.state, h.tenant, id, Timestamp::now()).await.unwrap()["status"], "delivered");
}
