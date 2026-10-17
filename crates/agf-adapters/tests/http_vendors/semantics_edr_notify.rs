//! 设备类（EDR）与通知类（Slack 消息维度回写）的 `push` / `pull` / `sync` **真实往返**（wiremock）。
//!
//! - EDR：隔离状态回写（带 dry-run 保护标记）、主机清单增量拉取（`action` 由 `isolation_state` 推导）、
//!   本地资产 ↔ EDR 主机对账；
//! - Slack：`chat.update` 更新已投递消息、`chat.delete` 撤回，并核对上游 `ok=false` 的业务错误分类。
use super::*;

/// EDR 适配器（指向本地假服务端；默认 dry-run，故断言里必须看到 dry-run 标记）。
async fn edr_at(server: &MockServer, timeout_secs: u64, retry_cfg: RetryConfig) -> VendorAdapterImpl<EdrIsolation> {
    adapter::<EdrIsolation>(
        &[("endpoint", json!(server.uri()))],
        &[("api_token", "edr-token-abcdef")],
        timeout_secs,
        retry_cfg,
        circuit(3, 30),
        false,
    )
    .await
}

/// Slack 适配器（Webhook 走本地假服务端，`api_base` 同样指向它）。
async fn slack_at(server: &MockServer, timeout_secs: u64, retry_cfg: RetryConfig) -> VendorAdapterImpl<Slack> {
    let hook = format!("{}/services/T00000000/B00000000/abcdefghijklmnopqrstuvwx", server.uri());
    adapter::<Slack>(
        &[("allow_custom_host", json!(true)), ("api_base", json!(server.uri())), ("channel", json!("#sec-alerts"))],
        &[("webhook_url", hook.as_str()), ("bot_token", "xoxb-test-bot-token")],
        timeout_secs,
        retry_cfg,
        circuit(3, 30),
        false,
    )
    .await
}

// ---------------------------------------------------------------------------
// EDR
// ---------------------------------------------------------------------------

#[tokio::test]
pub(crate) async fn edr_push_patches_host_isolation_state_with_dry_run_marker() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/v1/hosts/host-42/isolation"))
        .and(header("authorization", "Bearer edr-token-abcdef"))
        .and(header("x-agf-edr-vendor", "generic-edr"))
        .and(header("x-agf-dry-run", "true"))
        .and(body_partial_json(json!({"action": "isolate", "host_id": "host-42", "dry_run": true})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "host_id": "host-42", "isolation_state": "isolated", "dry_run": true
        })))
        .expect(1)
        .mount(&server)
        .await;

    let edr = edr_at(&server, 5, retry_once()).await;
    let payload = PushPayload {
        entity: "host.isolation".to_string(),
        entity_id: "host-42".to_string(),
        body: json!({"action": "isolate", "reason": "检出 C2 回连", "case_id": "CASE-2026-0001"}),
        idempotency_key: None,
    };
    let outcome = edr.push(&payload).await.expect("回写应成功");
    assert_eq!(outcome.requests, 1);
    assert_eq!(outcome.remote_id.as_deref(), Some("host-42"));
    assert_eq!(outcome.origin, format!("{}/v1/hosts/host-42/isolation", server.uri()));
    server.verify().await;

    let request = single_request(&server).await;
    assert_eq!(request.method.as_str(), "PATCH");
    let body: Value = request.body_json().expect("JSON 体");
    assert_eq!(body["action"], "isolate");
    assert_eq!(body["case_id"], "CASE-2026-0001");
    assert_eq!(body["requested_by"], "aiguardfabric");
    assert_eq!(body["dry_run"], true, "默认必须带 dry-run 保护");
    assert!(request.headers.contains_key("idempotency-key"), "回写必须带确定性幂等键（缺省由实体+id+载荷派生）");
}

#[tokio::test]
pub(crate) async fn edr_pull_reads_hosts_incrementally_and_normalizes_action() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/hosts"))
        .and(header("authorization", "Bearer edr-token-abcdef"))
        .and(query_param("updated_since", "2026-01-05T00:00:00+00:00"))
        .and(query_param("limit", "50"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hosts": [
                {"host_id": "host-42", "isolation_state": "isolated", "updated_at": "2026-01-06T00:00:00+00:00"},
                {"host_id": "host-77", "isolation_state": "released", "updated_at": "2026-01-07T00:00:00+00:00"}
            ],
            "next_cursor": "2026-01-07T00:00:00+00:00"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let edr = edr_at(&server, 5, retry_once()).await;
    let response = edr
        .pull(&PullRequest {
            resource: "hosts".to_string(),
            cursor: Some("2026-01-05T00:00:00+00:00".to_string()),
            limit: None,
            filter: BTreeMap::new(),
        })
        .await
        .expect("拉取应成功");
    assert_eq!(response.items.len(), 2);
    assert_eq!(response.items[0]["agf_remote_id"], "host-42");
    assert_eq!(response.items[0]["agf_state"], json!({"action": "isolate"}), "隔离态归一到可回写动作");
    assert_eq!(response.items[1]["agf_state"], json!({"action": "release"}));
    assert_eq!(response.next_cursor.as_deref(), Some("2026-01-07T00:00:00+00:00"), "上游游标优先");
    server.verify().await;
}

#[tokio::test]
pub(crate) async fn edr_sync_reconciles_local_assets_with_edr_hosts() {
    let server = MockServer::start().await;
    // EDR 侧该主机仍是 released，而本地资产要求 isolate（本地更新且策略为本地优先）⇒ 必须回写
    Mock::given(method("GET"))
        .and(path("/v1/hosts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hosts": [{"host_id": "host-42", "isolation_state": "released", "updated_at": "2026-01-05T00:00:00+00:00"}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/v1/hosts/host-42/isolation"))
        .and(body_partial_json(json!({"action": "isolate", "host_id": "host-42"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "host_id": "host-42", "isolation_state": "isolated"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let edr = edr_at(&server, 5, retry_once()).await;
    let outcome = edr
        .sync(
            &SyncRequest::new("hosts")
                .with_local(vec![
                    LocalSnapshot::new("host-42", json!({"action": "isolate", "reason": "本地资产要求隔离"}))
                        .with_updated_at(Timestamp::parse_rfc3339("2026-01-06T00:00:00+00:00").expect("合法时间戳")),
                ])
                .with_conflict_policy(ConflictPolicy::LocalWins),
        )
        .await
        .expect("对账应成功");
    assert_eq!(outcome.pulled, 1);
    assert_eq!(outcome.pushed, 1);
    assert_eq!(outcome.changes.get("push_local").copied(), Some(1), "本地更新且外部未变 ⇒ 非冲突回写");
    assert!(outcome.warnings.iter().any(|w| w.contains("push-local")), "{:?}", outcome.warnings);
    server.verify().await;
}

// ---------------------------------------------------------------------------
// Slack（消息维度回写）
// ---------------------------------------------------------------------------

#[tokio::test]
pub(crate) async fn slack_push_updates_message_via_chat_update() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/chat.update"))
        .and(header("authorization", "Bearer xoxb-test-bot-token"))
        .and(header("content-type", "application/json"))
        .and(body_partial_json(json!({
            "channel": "#sec-alerts", "ts": "1700000000.000100", "text": "【已处置】提示词注入命中"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true, "channel": "C123", "ts": "1700000000.000100"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let slack = slack_at(&server, 5, retry_once()).await;
    let outcome = slack
        .push(&PushPayload {
            entity: "message.update".to_string(),
            entity_id: "1700000000.000100".to_string(),
            body: json!({"text": "【已处置】提示词注入命中"}),
            idempotency_key: Some("idem-slack-1".to_string()),
        })
        .await
        .expect("消息更新应成功");
    assert_eq!(outcome.requests, 1);
    assert_eq!(outcome.remote_id.as_deref(), Some("1700000000.000100"));
    assert_eq!(outcome.origin, format!("{}/api/chat.update", server.uri()));
    server.verify().await;

    let request = single_request(&server).await;
    assert_eq!(request.method.as_str(), "POST");
    let body: Value = request.body_json().expect("JSON 体");
    assert_eq!(body["channel"], "#sec-alerts", "频道来自设置项（body 未给时回退）");
    assert_eq!(body["ts"], "1700000000.000100", "ts 来自 send 回执的 remote_id（entity_id）");
}

#[tokio::test]
pub(crate) async fn slack_push_revoke_deletes_message_and_reports_business_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/chat.delete"))
        .and(body_partial_json(json!({"channel": "#sec-alerts", "ts": "1700000000.000100"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": false, "error": "message_not_found"})))
        .expect(1)
        .mount(&server)
        .await;

    let slack = slack_at(&server, 5, retry(3)).await;
    let error = slack
        .push(&PushPayload {
            entity: "message.revoke".to_string(),
            entity_id: "1700000000.000100".to_string(),
            body: json!({}),
            idempotency_key: None,
        })
        .await
        .expect_err("上游 ok=false 必须如实报错");
    assert!(matches!(error, DomainError::Validation(_)), "{error}");
    assert!(error.to_string().contains("message_not_found"), "{error}");
    assert!(!error.is_degradable(), "Slack 业务错误不得重试");
    assert_eq!(requests(&server).await.len(), 1, "业务错误只发一次");
    server.verify().await;
}
