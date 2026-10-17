//! 由 `http_vendors.rs` 拆分：`wecom_posts_markdown_and_reads_errcode` 等 12 个函数（纯搬移，逻辑不变）。
use super::*;

// ---------------------------------------------------------------------------
// 企业微信：Markdown 体 + errcode
// ---------------------------------------------------------------------------

#[tokio::test]
pub(crate) async fn wecom_posts_markdown_and_reads_errcode() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/cgi-bin/webhook/send"))
        .and(query_param("key", "abcdef1234567890"))
        .and(body_partial_json(json!({"msgtype": "markdown"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"errcode": 0, "errmsg": "ok"})))
        .expect(1)
        .mount(&server)
        .await;

    let hook = format!("{}/cgi-bin/webhook/send?key=abcdef1234567890", server.uri());
    let mut wecom = adapter::<WeCom>(
        &[("allow_custom_host", json!(true))],
        &[("webhook_url", &hook)],
        5,
        retry_once(),
        circuit(3, 30),
        false,
    )
    .await;

    let receipt = wecom.send(&alerts()).await.expect("真实 HTTP 下发应成功");
    assert!(receipt.accepted && !receipt.mocked);
    assert!(receipt.remote_id.is_none());
    server.verify().await;

    let body: Value = single_request(&server).await.body_json().expect("JSON 体");
    let content = body["markdown"]["content"].as_str().unwrap_or_default();
    assert!(content.contains("发现明文 API Key"), "{content}");
    assert!(content.contains("high"), "正文必须带等级: {content}");
}

#[tokio::test]
pub(crate) async fn wecom_business_error_code_is_reported() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"errcode": 93000, "errmsg": "invalid webhook url"})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let hook = format!("{}/cgi-bin/webhook/send?key=abcdef1234567890", server.uri());
    let mut wecom = adapter::<WeCom>(
        &[("allow_custom_host", json!(true))],
        &[("webhook_url", &hook)],
        5,
        retry(3),
        circuit(3, 30),
        false,
    )
    .await;

    let error = wecom.send(&alerts()).await.expect_err("业务错误码必须报错");
    assert!(error.to_string().contains("93000"), "{error}");
    server.verify().await;
}

// ---------------------------------------------------------------------------
// Slack：Block Kit + 纯文本 ok
// ---------------------------------------------------------------------------

#[tokio::test]
pub(crate) async fn slack_posts_blocks_and_accepts_ok_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/services/T00000000/B00000000/abcdefghijklmnopqrstuvwx"))
        .and(header("content-type", "application/json"))
        .and(body_partial_json(json!({"channel": "#sec-alerts"})))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;

    let hook = format!("{}/services/T00000000/B00000000/abcdefghijklmnopqrstuvwx", server.uri());
    let mut slack = adapter::<Slack>(
        &[("channel", json!("#sec-alerts")), ("allow_custom_host", json!(true))],
        &[("webhook_url", &hook)],
        5,
        retry_once(),
        circuit(3, 30),
        false,
    )
    .await;

    let receipt = slack.send(&alerts()).await.expect("真实 HTTP 下发应成功");
    assert!(receipt.accepted && !receipt.mocked);
    server.verify().await;

    let body: Value = single_request(&server).await.body_json().expect("JSON 体");
    assert_eq!(body["text"], "【high】发现明文 API Key");
    let blocks = body["blocks"].as_array().cloned().unwrap_or_default();
    assert_eq!(blocks.len(), 3);
    assert_eq!(blocks[0]["type"], "header");
    assert_eq!(blocks[2]["type"], "context");
}

#[tokio::test]
pub(crate) async fn slack_non_ok_body_is_rejected_without_retry() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("invalid_payload"))
        .expect(1)
        .mount(&server)
        .await;

    let hook = format!("{}/services/T00000000/B00000000/abcdefghijklmnopqrstuvwx", server.uri());
    let mut slack = adapter::<Slack>(
        &[("allow_custom_host", json!(true))],
        &[("webhook_url", &hook)],
        5,
        retry(3),
        circuit(3, 30),
        false,
    )
    .await;

    let error = slack.send(&alerts()).await.expect_err("非 ok 响应必须报错");
    assert!(matches!(error, DomainError::Validation(_)), "{error}");
    assert!(error.to_string().contains("invalid_payload"), "{error}");
    server.verify().await;
}

// ---------------------------------------------------------------------------
// 通用 Webhook：信封 + 幂等头 + 重试 + 断路器半开恢复
// ---------------------------------------------------------------------------

#[tokio::test]
pub(crate) async fn webhook_posts_envelope_with_idempotency_and_auth_headers() {
    let server = MockServer::start().await;
    let msg = alerts();
    Mock::given(method("POST"))
        .and(path("/hooks/agf"))
        .and(header("Idempotency-Key", msg.idempotency_key.as_str()))
        .and(header("X-AGF-Event-Type", "ai.credential.leak"))
        .and(header("X-AGF-Severity", "high"))
        .and(header("X-AGF-Token", "Bearer super-secret-token"))
        .and(body_partial_json(json!({
            "schema": "agf.webhook.v1",
            "source": "aiguardfabric",
            "event_type": "ai.credential.leak",
            "asset": "cursor@host1",
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "run-42"})))
        .expect(1)
        .mount(&server)
        .await;

    let hook = format!("{}/hooks/agf", server.uri());
    let mut webhook = adapter::<Webhook>(
        &[("auth_header_name", json!("X-AGF-Token"))],
        &[("webhook_url", &hook), ("auth_header_value", "Bearer super-secret-token")],
        5,
        retry_once(),
        circuit(3, 30),
        false,
    )
    .await;

    let receipt = webhook.send(&msg).await.expect("真实 HTTP 下发应成功");
    assert_eq!(receipt.remote_id.as_deref(), Some("run-42"), "远端 id 必须从响应体解析");
    server.verify().await;

    let request = single_request(&server).await;
    assert_eq!(request.url.path(), "/hooks/agf");
    let body: Value = request.body_json().expect("JSON 体");
    assert_eq!(body["kind"], "event");
    assert_eq!(body["labels"]["team"], "soc");
    assert_eq!(body["payload"]["file"], "/home/u/.cursor/mcp.json");
}

#[tokio::test]
pub(crate) async fn webhook_retries_5xx_then_succeeds() {
    let server = MockServer::start().await;
    // wiremock 按注册顺序匹配（同优先级）：先挂"仅前 1 次生效"的 500，耗尽后落到成功响应
    Mock::given(any())
        .respond_with(ResponseTemplate::new(500).set_body_string("transient"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "retry-ok"})))
        .mount(&server)
        .await;

    let hook = format!("{}/hooks/agf", server.uri());
    let mut webhook = adapter::<Webhook>(&[], &[("webhook_url", &hook)], 5, retry(3), circuit(5, 30), false).await;

    let receipt = webhook.send(&alerts()).await.expect("首次失败后重试应成功");
    assert_eq!(receipt.attempts, 2, "第一次 500 + 第二次成功 ⇒ 2 次尝试");
    assert_eq!(receipt.remote_id.as_deref(), Some("retry-ok"));
    assert_eq!(requests(&server).await.len(), 2);
    assert_eq!(webhook.build_record().status, agf_adapters::HealthStatus::Available);
}

#[tokio::test]
pub(crate) async fn webhook_5xx_error_text_masks_webhook_token() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(500).set_body_string("server error"))
        .expect(1)
        .mount(&server)
        .await;

    let token = "9f8e7d6c5b4a3210";
    let hook = format!("{}/hooks/agf?access_token={token}", server.uri());
    let mut webhook = adapter::<Webhook>(&[], &[("webhook_url", &hook)], 5, retry_once(), circuit(3, 30), false).await;

    let error = webhook.send(&alerts()).await.expect_err("5xx 必须如实报错");
    let text = error.to_string();
    assert!(!text.contains(token), "错误文本不得泄露 Webhook token: {text}");
    assert!(text.contains("access_token="), "但应保留键名便于排障: {text}");
    server.verify().await;
}

#[tokio::test]
pub(crate) async fn webhook_circuit_half_open_recovers_on_success() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(500).set_body_string("down"))
        .up_to_n_times(2)
        .mount(&server)
        .await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "recovered"})))
        .mount(&server)
        .await;

    let hook = format!("{}/hooks/agf", server.uri());
    let mut webhook = adapter::<Webhook>(&[], &[("webhook_url", &hook)], 5, retry_once(), circuit(2, 1), false).await;

    for _ in 0..2 {
        assert!(webhook.send(&alerts()).await.is_err());
    }
    assert_eq!(webhook.circuit().state, CircuitState::Open);
    // 开路时长 1s：等待到期后允许半开探测
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let receipt = webhook.send(&alerts()).await.expect("半开探测成功应闭合熔断器");
    assert_eq!(receipt.remote_id.as_deref(), Some("recovered"));
    assert_eq!(webhook.circuit().state, CircuitState::Closed);
    assert_eq!(webhook.circuit().consecutive_failures, 0);
    assert_eq!(requests(&server).await.len(), 3);
}

// ---------------------------------------------------------------------------
// Jira：REST v2 建单
// ---------------------------------------------------------------------------

#[tokio::test]
pub(crate) async fn jira_creates_issue_with_basic_auth_and_reads_ticket_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/api/2/issue"))
        .and(header("authorization", Jira::basic_auth("soc@example.invalid", "jira-token-abcdef").as_str()))
        .and(header("content-type", "application/json"))
        .and(body_partial_json(json!({
            "fields": {
                "project": {"key": "SEC"},
                "issuetype": {"name": "Task"},
                // `alerts()` 为 high 等级 ⇒ Jira priority 映射为 High（Critical 才是 Highest）
                "priority": {"name": "High"},
            }
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": "10001", "key": "SEC-7"})))
        .expect(1)
        .mount(&server)
        .await;

    let base_url = server.uri();
    let mut jira = adapter::<Jira>(
        &[("base_url", json!(base_url)), ("project_key", json!("SEC"))],
        &[("api_token", "jira-token-abcdef"), ("user_email", "soc@example.invalid")],
        5,
        retry_once(),
        circuit(3, 30),
        false,
    )
    .await;

    let receipt = jira.send(&alerts()).await.expect("真实 HTTP 建单应成功");
    assert_eq!(receipt.remote_id.as_deref(), Some("SEC-7"), "远端 id 优先取人读工单号 key");
    assert_eq!(receipt.origin, format!("{}/rest/api/2/issue", server.uri()));
    server.verify().await;

    let body: Value = single_request(&server).await.body_json().expect("JSON 体");
    let labels = body["fields"]["labels"].as_array().cloned().unwrap_or_default();
    assert!(labels.contains(&json!("aiguardfabric")));
    assert!(labels.contains(&json!("agf-high")));
    assert!(body["fields"]["description"].as_str().unwrap_or_default().contains("ai.credential.leak"));
}

#[tokio::test]
pub(crate) async fn jira_4xx_is_not_retried() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(
            ResponseTemplate::new(400).set_body_json(json!({"errorMessages": ["Field 'summary' is required"]})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let base_url = server.uri();
    let mut jira = adapter::<Jira>(
        &[("base_url", json!(base_url)), ("project_key", json!("SEC"))],
        &[("api_token", "t"), ("user_email", "soc@example.invalid")],
        5,
        retry(3),
        circuit(3, 30),
        false,
    )
    .await;

    let error = jira.send(&alerts()).await.expect_err("4xx 必须如实报错");
    assert!(matches!(error, DomainError::Validation(_)), "{error}");
    assert!(error.to_string().contains("summary"), "{error}");
    server.verify().await;
    assert_eq!(jira.build_record().last_attempts, 1, "业务错误不得重试");
}

// ---------------------------------------------------------------------------
// ServiceNow：Table API 建单
// ---------------------------------------------------------------------------

#[tokio::test]
pub(crate) async fn servicenow_creates_incident_with_bearer_and_reads_number() {
    let server = MockServer::start().await;
    let msg = alerts();
    Mock::given(method("POST"))
        .and(path("/api/now/table/incident"))
        .and(header("authorization", "Bearer sn-token-abcdef"))
        .and(header("accept", "application/json"))
        .and(body_partial_json(json!({
            "urgency": "1",
            "category": "security",
            "correlation_id": msg.idempotency_key.clone(),
        })))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(json!({"result": {"sys_id": "abc123", "number": "INC0010001"}})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let instance = server.uri();
    let mut servicenow = adapter::<ServiceNow>(
        &[("instance_url", json!(instance)), ("allow_custom_host", json!(true)), ("insecure_http", json!(true))],
        &[("api_token", "sn-token-abcdef")],
        5,
        retry_once(),
        circuit(3, 30),
        false,
    )
    .await;

    let receipt = servicenow.send(&msg).await.expect("真实 HTTP 建单应成功");
    assert_eq!(
        receipt.remote_id.as_deref(),
        Some("abc123"),
        "远端 id 取 sys_id：它是 Table API 的定位键（push/pull 都用它），number 只是人读单号"
    );
    server.verify().await;

    let body: Value = single_request(&server).await.body_json().expect("JSON 体");
    assert!(body["short_description"].as_str().unwrap_or_default().contains("发现明文 API Key"));
    assert_eq!(body["subcategory"], "ai.credential.leak");
}

// ---------------------------------------------------------------------------
// 禅道：REST v1 缺陷提交
// ---------------------------------------------------------------------------

#[tokio::test]
pub(crate) async fn zentao_creates_bug_with_token_header() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api.php/v1/bugs"))
        .and(header("Token", "zentao-token-abcdef"))
        .and(body_partial_json(json!({"product": 7, "severity": 2, "type": "ai-security"})))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": 123, "title": "发现明文 API Key"})))
        .expect(1)
        .mount(&server)
        .await;

    let base_url = server.uri();
    let mut zentao = adapter::<Zentao>(
        &[("base_url", json!(base_url)), ("product_id", json!(7))],
        &[("api_token", "zentao-token-abcdef")],
        5,
        retry_once(),
        circuit(3, 30),
        false,
    )
    .await;

    let receipt = zentao.send(&alerts()).await.expect("真实 HTTP 建单应成功");
    assert_eq!(receipt.remote_id.as_deref(), Some("123"));
    server.verify().await;

    let body: Value = single_request(&server).await.body_json().expect("JSON 体");
    assert_eq!(body["pri"], 2);
    assert!(body["steps"].as_str().unwrap_or_default().contains("idempotency_key="));
}
