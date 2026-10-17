//! 由 `http_vendors.rs` 拆分：`retry_once` 等 19 个函数（纯搬移，逻辑不变）。
use super::*;

// ---------------------------------------------------------------------------
// 构造辅助
// ---------------------------------------------------------------------------

/// 单次尝试（不重试）——用于精确断言"只发了一个请求"。
pub(crate) fn retry_once() -> RetryConfig {
    RetryConfig { max_attempts: 1, initial_backoff_ms: 1, multiplier: 1.0, max_backoff_ms: 2, jitter: false }
}

/// 指定尝试次数的重试配置（退避压到 1ms，保证测试快速确定）。
pub(crate) fn retry(max_attempts: u32) -> RetryConfig {
    RetryConfig { max_attempts, initial_backoff_ms: 1, multiplier: 1.0, max_backoff_ms: 2, jitter: false }
}

/// 熔断配置。
pub(crate) fn circuit(failure_threshold: u32, open_secs: i64) -> CircuitBreakerConfig {
    CircuitBreakerConfig { enabled: true, failure_threshold, open_secs, half_open_probes: 1 }
}

/// 内存凭据。
pub(crate) fn secrets(pairs: &[(&str, &str)]) -> StaticSecrets {
    let mut lookup = StaticSecrets::new();
    for (key, value) in pairs {
        lookup = lookup.with(key, value);
    }
    lookup
}

/// 构造配置（走与生产一致的 `AdapterConfig` 形态）。
pub(crate) fn config<V: VendorSpec>(
    settings: &[(&str, Value)],
    timeout_secs: u64,
    retry: RetryConfig,
    circuit: CircuitBreakerConfig,
    mock: bool,
) -> AdapterConfig {
    let now = Timestamp::now();
    let mut map: BTreeMap<String, Value> = BTreeMap::new();
    for (key, value) in settings {
        map.insert((*key).to_string(), value.clone());
    }
    AdapterConfig {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        adapter: V::NAME.to_string(),
        display_name: V::NAME.to_string(),
        enabled: true,
        settings: map,
        secret_refs: BTreeMap::new(),
        circuit_breaker: circuit,
        retry,
        timeout_secs,
        mock,
        is_default: true,
        created_at: now,
        updated_at: now,
    }
}

/// 构造已初始化的适配器（走 `init_with` 真实路径）。
pub(crate) async fn adapter<V: VendorSpec>(
    settings: &[(&str, Value)],
    secret_pairs: &[(&str, &str)],
    timeout_secs: u64,
    retry_cfg: RetryConfig,
    circuit_cfg: CircuitBreakerConfig,
    mock: bool,
) -> VendorAdapterImpl<V> {
    let cfg = config::<V>(settings, timeout_secs, retry_cfg, circuit_cfg, mock);
    let lookup = secrets(secret_pairs);
    let mut instance = VendorAdapterImpl::<V>::new();
    instance.init_with(&cfg, &lookup, false).await.expect("合法配置必须可初始化");
    instance
}

/// 取 wiremock 收到的全部请求。
pub(crate) async fn requests(server: &MockServer) -> Vec<wiremock::Request> {
    server.received_requests().await.expect("wiremock 应记录请求")
}

/// 取单个请求（并断言恰好一次）。
pub(crate) async fn single_request(server: &MockServer) -> wiremock::Request {
    let captured = requests(server).await;
    assert_eq!(captured.len(), 1, "应恰好收到 1 个请求");
    captured.into_iter().next().expect("已确认长度")
}

/// 通用告警载荷。
pub(crate) fn alerts() -> AdapterMessage {
    AdapterMessage::event(
        "ai.credential.leak",
        Severity::High,
        "发现明文 API Key",
        "在 mcp.json 中发现 sk- 开头的明文密钥",
        json!({"file": "/home/u/.cursor/mcp.json"}),
    )
    .with_asset("cursor@host1")
    .with_label("team", "soc")
}

// ---------------------------------------------------------------------------
// 飞书：自定义机器人 Webhook
// ---------------------------------------------------------------------------

#[tokio::test]
pub(crate) async fn feishu_posts_text_message_with_exact_method_path_header_and_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/open-apis/bot/v2/hook/testtoken"))
        .and(header("content-type", "application/json"))
        .and(body_partial_json(json!({"msg_type": "text"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"code": 0, "msg": "success"})))
        .expect(1)
        .mount(&server)
        .await;

    let hook = format!("{}/open-apis/bot/v2/hook/testtoken", server.uri());
    let mut feishu = adapter::<Feishu>(
        &[("allow_custom_host", json!(true))],
        &[("webhook_url", &hook)],
        5,
        retry_once(),
        circuit(3, 30),
        false,
    )
    .await;
    assert_eq!(feishu.mode(), AdapterMode::Live);

    let msg = AdapterMessage::notification("提示词注入命中", "规则 PA-INJ-001 命中 claude-code@host1")
        .with_severity(Severity::Medium);
    let receipt = feishu.send(&msg).await.expect("真实 HTTP 下发应成功");
    assert!(receipt.accepted && !receipt.mocked);
    assert_eq!(receipt.attempts, 1);
    assert_eq!(receipt.origin, hook);
    assert!(receipt.remote_id.is_none(), "飞书不回传消息 id，回执如实为 None");
    server.verify().await;

    let request = single_request(&server).await;
    assert_eq!(request.method.as_str(), "POST");
    assert_eq!(request.url.path(), "/open-apis/bot/v2/hook/testtoken");
    let body: Value = request.body_json().expect("请求体必须是 JSON");
    assert_eq!(body["msg_type"], "text");
    assert!(body["content"]["text"].as_str().unwrap_or_default().contains("提示词注入命中"), "正文必须含标题: {body}");
}

#[tokio::test]
pub(crate) async fn feishu_high_severity_posts_signed_interactive_card() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/open-apis/bot/v2/hook/signed"))
        .and(body_partial_json(json!({"msg_type": "interactive"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"StatusCode": 0, "StatusMessage": "success"})))
        .expect(1)
        .mount(&server)
        .await;

    let hook = format!("{}/open-apis/bot/v2/hook/signed", server.uri());
    let mut feishu = adapter::<Feishu>(
        &[("allow_custom_host", json!(true))],
        &[("webhook_url", &hook), ("signing_secret", "s3cr3t-signing-key")],
        5,
        retry_once(),
        circuit(3, 30),
        false,
    )
    .await;

    let msg = alerts();
    let before = agf_core::time::Timestamp::now().unix_secs();
    let receipt = feishu.send(&msg).await.expect("真实 HTTP 下发应成功");
    assert!(receipt.accepted);
    server.verify().await;

    let body: Value = single_request(&server).await.body_json().expect("JSON 体");
    assert_eq!(body["msg_type"], "interactive");
    assert_eq!(body["card"]["header"]["template"], "orange", "high 等级用橙色模板");
    let expected_timestamp: i64 = body["timestamp"].as_str().expect("timestamp").parse().expect("Unix 秒");
    assert!((before..=agf_core::time::Timestamp::now().unix_secs()).contains(&expected_timestamp));
    assert_eq!(
        body["sign"],
        json!(Feishu::sign(expected_timestamp, "s3cr3t-signing-key").expect("有密钥必须产生签名")),
        "加签字段必须与飞书算法一致"
    );
}

#[tokio::test]
pub(crate) async fn feishu_business_error_code_is_reported_without_retry() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"code": 19021, "msg": "sign match fail"})))
        .expect(1)
        .mount(&server)
        .await;

    let hook = format!("{}/open-apis/bot/v2/hook/bad", server.uri());
    let mut feishu = adapter::<Feishu>(
        &[("allow_custom_host", json!(true))],
        &[("webhook_url", &hook)],
        5,
        retry(3),
        circuit(3, 30),
        false,
    )
    .await;

    let error = feishu.send(&alerts()).await.expect_err("HTTP 200 但业务码非 0 必须报错");
    assert!(matches!(error, DomainError::Validation(_)), "{error}");
    assert!(error.to_string().contains("19021"), "{error}");
    assert_eq!(requests(&server).await.len(), 1, "业务错误码不得重试");
    assert_eq!(feishu.build_record().status, agf_adapters::HealthStatus::Degraded);
}

#[tokio::test]
pub(crate) async fn feishu_5xx_is_retried_according_to_retry_config() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(503).set_body_string("upstream down"))
        .expect(3)
        .mount(&server)
        .await;

    let hook = format!("{}/open-apis/bot/v2/hook/retry", server.uri());
    let mut feishu = adapter::<Feishu>(
        &[("allow_custom_host", json!(true))],
        &[("webhook_url", &hook)],
        5,
        retry(3),
        circuit(5, 30),
        false,
    )
    .await;

    let error = feishu.send(&alerts()).await.expect_err("5xx 必须如实报错");
    assert!(matches!(error, DomainError::DependencyUnavailable { .. }), "{error}");
    assert!(error.to_string().contains("503"), "{error}");
    server.verify().await;
    let record = feishu.build_record();
    assert_eq!(record.last_attempts, 3, "max_attempts=3 且 5xx 可重试 ⇒ 实际 3 次");
    assert_eq!(record.consecutive_failures, 1, "一次 send 只累计一次连续失败");
}

#[tokio::test]
pub(crate) async fn feishu_429_is_reported_as_rate_limited_without_retry() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(429).set_body_string("too many requests"))
        .expect(1)
        .mount(&server)
        .await;

    let hook = format!("{}/open-apis/bot/v2/hook/limited", server.uri());
    let mut feishu = adapter::<Feishu>(
        &[("allow_custom_host", json!(true))],
        &[("webhook_url", &hook)],
        5,
        retry(3),
        circuit(5, 30),
        false,
    )
    .await;

    let error = feishu.send(&alerts()).await.expect_err("429 必须如实报错");
    assert!(matches!(error, DomainError::RateLimited(_)), "{error}");
    server.verify().await;
}

#[tokio::test]
pub(crate) async fn feishu_timeout_is_reported_as_timeout() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(1500)))
        .mount(&server)
        .await;

    let hook = format!("{}/open-apis/bot/v2/hook/slow", server.uri());
    let mut feishu = adapter::<Feishu>(
        &[("allow_custom_host", json!(true))],
        &[("webhook_url", &hook)],
        1,
        retry_once(),
        circuit(5, 30),
        false,
    )
    .await;

    let error = feishu.send(&alerts()).await.expect_err("超时必须如实报错");
    assert!(matches!(error, DomainError::Timeout(_)), "{error}");
}

#[tokio::test]
pub(crate) async fn feishu_circuit_opens_after_threshold_and_fails_fast() {
    let server = MockServer::start().await;
    Mock::given(any()).respond_with(ResponseTemplate::new(500).set_body_string("boom")).expect(2).mount(&server).await;

    let hook = format!("{}/open-apis/bot/v2/hook/circuit", server.uri());
    let mut feishu = adapter::<Feishu>(
        &[("allow_custom_host", json!(true))],
        &[("webhook_url", &hook)],
        5,
        retry_once(),
        circuit(2, 30),
        false,
    )
    .await;

    for _ in 0..2 {
        assert!(feishu.send(&alerts()).await.is_err(), "上游 500 必须报错");
    }
    assert_eq!(feishu.circuit().state, CircuitState::Open, "连续 2 次失败 ⇒ 熔断开路");
    let record = feishu.build_record();
    assert_eq!(record.status, agf_adapters::HealthStatus::Unavailable);
    assert_eq!(record.health_state(), agf_core::enums::HealthState::CircuitOpen);

    let error = feishu.send(&alerts()).await.expect_err("开路后必须快速失败");
    assert!(error.to_string().contains("熔断器处于 open"), "{error}");
    server.verify().await;
    assert_eq!(requests(&server).await.len(), 2, "开路期间绝不触达外部系统");
}

// ---------------------------------------------------------------------------
// 钉钉：加签查询串 + Markdown 体
// ---------------------------------------------------------------------------

#[tokio::test]
pub(crate) async fn dingtalk_posts_markdown_with_signed_query_params() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/robot/send"))
        .and(query_param("access_token", "abcdef1234567890"))
        .and(header("content-type", "application/json"))
        .and(body_partial_json(json!({"msgtype": "markdown"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"errcode": 0, "errmsg": "ok"})))
        .expect(1)
        .mount(&server)
        .await;

    let hook = format!("{}/robot/send?access_token=abcdef1234567890", server.uri());
    let mut dingtalk = adapter::<DingTalk>(
        &[("allow_custom_host", json!(true))],
        &[("webhook_url", &hook), ("signing_secret", "SECdeadbeef")],
        5,
        retry_once(),
        circuit(3, 30),
        false,
    )
    .await;

    let msg = alerts();
    let receipt = dingtalk.send(&msg).await.expect("真实 HTTP 下发应成功");
    assert!(receipt.accepted && !receipt.mocked);
    server.verify().await;

    let request = single_request(&server).await;
    assert_eq!(request.method.as_str(), "POST");
    assert_eq!(request.url.path(), "/robot/send");
    let params: BTreeMap<String, String> =
        request.url.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let timestamp: i64 = params.get("timestamp").expect("timestamp").parse().expect("Unix 毫秒");
    assert!((agf_core::time::Timestamp::now().unix_millis() - timestamp).abs() < 5000);
    assert_eq!(params.get("access_token").map(String::as_str), Some("abcdef1234567890"));
    assert_eq!(
        params.get("sign").map(String::as_str),
        DingTalk::sign(timestamp, "SECdeadbeef").as_deref(),
        "签名必须与钉钉算法一致（查询串已 URL 解码）"
    );
    let body: Value = request.body_json().expect("JSON 体");
    assert!(body["markdown"]["text"].as_str().unwrap_or_default().contains("ai.credential.leak"));
}

#[tokio::test]
pub(crate) async fn dingtalk_business_error_code_is_reported() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"errcode": 310_000, "errmsg": "sign not match"})))
        .expect(1)
        .mount(&server)
        .await;

    let hook = format!("{}/robot/send?access_token=abcdef1234567890", server.uri());
    let mut dingtalk = adapter::<DingTalk>(
        &[("allow_custom_host", json!(true))],
        &[("webhook_url", &hook)],
        5,
        retry(3),
        circuit(3, 30),
        false,
    )
    .await;

    let error = dingtalk.send(&alerts()).await.expect_err("业务错误码必须报错");
    assert!(matches!(error, DomainError::Validation(_)), "{error}");
    assert!(error.to_string().contains("sign not match"), "{error}");
    server.verify().await;
}

#[tokio::test]
pub(crate) async fn dingtalk_rejects_custom_host_without_explicit_switch() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"errcode": 0})))
        .expect(0)
        .mount(&server)
        .await;

    let hook = format!("{}/robot/send?access_token=abcdef1234567890", server.uri());
    let cfg = config::<DingTalk>(&[], 5, retry_once(), circuit(3, 30), false);
    let lookup = secrets(&[("webhook_url", &hook)]);
    let result = VendorAdapterImpl::<DingTalk>::new().init_with(&cfg, &lookup, false).await;
    assert!(matches!(result, Err(DomainError::Config(_))), "未开 allow_custom_host 必须拒绝非厂商域名");
    server.verify().await;
}
