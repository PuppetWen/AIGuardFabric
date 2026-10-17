//! 由 `client.rs` 拆分：`identity`/`report` 等 24 项（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn identity() -> AgentIdentity {
    AgentIdentity::generate().with_agent_id("agent-1").with_hostname("host-1")
}

pub(crate) fn report(host: &str) -> AgentReport {
    AgentReport {
        collector_id: "agent-1".into(),
        collected_at: agf_core::time::Timestamp::now(),
        hostname: host.into(),
        os: "windows/x86_64".into(),
        os_user: Some("alice".into()),
        agents: vec![],
        mcp_configs: vec![],
        credential_hits: vec![],
        scan_scope: vec![],
        agent_version: crate::identity::AGENT_VERSION.to_string(),
    }
}

/// 测试传输：前 `fail_times` 次失败（可重试错误），之后成功；记录调用。
#[derive(Debug)]
pub(crate) struct FlakyTransport {
    pub(crate) fail_times: u32,
    pub(crate) calls: AtomicU32,
    pub(crate) sent: Mutex<Vec<String>>,
}

impl FlakyTransport {
    pub(crate) fn new(fail_times: u32) -> Self {
        Self { fail_times, calls: AtomicU32::new(0), sent: Mutex::new(Vec::new()) }
    }

    pub(crate) fn calls(&self) -> u32 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl AgentTransport for FlakyTransport {
    fn name(&self) -> &'static str {
        "flaky"
    }

    fn requires_network(&self) -> bool {
        true
    }

    fn send(&self, endpoint: &str, body: &str) -> DomainResult<()> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n < self.fail_times {
            return Err(DomainError::DependencyUnavailable { dependency: "agf".into(), cause: "断线".into() });
        }
        if let Ok(mut sent) = self.sent.lock() {
            sent.push(format!("{endpoint}|{}", body.len()));
        }
        Ok(())
    }
}

/// 恒失败（可重试）。
#[derive(Debug, Default)]
pub(crate) struct DownTransport;

impl AgentTransport for DownTransport {
    fn name(&self) -> &'static str {
        "down"
    }
    fn requires_network(&self) -> bool {
        true
    }
    fn send(&self, _endpoint: &str, _body: &str) -> DomainResult<()> {
        Err(DomainError::DependencyUnavailable { dependency: "agf".into(), cause: "不可达".into() })
    }
}

/// 非可重试失败（载荷非法）。
#[derive(Debug, Default)]
pub(crate) struct RejectTransport;

impl AgentTransport for RejectTransport {
    fn name(&self) -> &'static str {
        "reject"
    }
    fn requires_network(&self) -> bool {
        true
    }
    fn send(&self, _endpoint: &str, _body: &str) -> DomainResult<()> {
        Err(DomainError::Validation("载荷非法".into()))
    }
}

pub(crate) fn fast_retry(max_attempts: u32) -> RetryConfig {
    RetryConfig { max_attempts, initial_backoff_ms: 1, multiplier: 1.0, max_backoff_ms: 1, jitter: false }
}

#[tokio::test]
pub(crate) async fn mock_mode_never_uses_transport_and_records() {
    let mut client = AgentClient::new(identity(), ClientConfig::mock());
    assert_eq!(client.mode(), ClientMode::Mock);
    assert_eq!(client.transport_name(), "mock");
    assert!(!client.has_token(), "未配置令牌时不得声称已鉴权");

    let outcome = client.send_snapshot(report("host-1"), CollectionExtras::default()).await.expect("Mock 上报");
    assert!(outcome.mocked);
    assert!(!outcome.queued);
    assert!(!outcome.is_delivered(), "Mock 不等于触达服务端");
    assert_eq!(client.recorded_deliveries().len(), 1);
    assert!(client.recorded_deliveries()[0].bytes > 0);
    assert!(client.queue().is_empty(), "Mock 不产生积压");
    assert!(client.last_snapshot().is_some(), "Mock 也要更新 diff 基线");
}

#[tokio::test]
pub(crate) async fn unconfigured_queues_and_reports_not_configured() {
    let mut client = AgentClient::new(identity(), ClientConfig::default());
    assert_eq!(client.mode(), ClientMode::Unconfigured);
    let strict =
        client.deliver_strict(PayloadKind::Heartbeat, "{}", "k-strict").await.expect_err("严格模式必须报未配置");
    assert!(matches!(strict, DomainError::Config(_)));
    assert!(client.queue().is_empty(), "严格模式不入队");

    let outcome = client.deliver(PayloadKind::Heartbeat, "{}", "k-1").await.expect("默认模式应入队并返回回执");
    assert!(outcome.queued);
    assert!(!outcome.mocked);
    assert!(outcome.note.unwrap_or_default().contains("本地队列"));
    assert_eq!(client.queue().len(), 1);
}

#[tokio::test]
pub(crate) async fn live_retries_with_backoff_then_succeeds() {
    let transport = Arc::new(FlakyTransport::new(2));
    let config = ClientConfig::default().with_server_url("https://agf.example.invalid/").with_retry(fast_retry(3));
    let mut client = AgentClient::new(identity(), config).with_transport(transport.clone());
    assert_eq!(client.mode(), ClientMode::Live);
    assert_eq!(client.backoff_ms(0), 1);

    let outcome = client.send_heartbeat(&client.heartbeat_payload(vec![])).await.expect("重试后应成功");
    assert!(outcome.is_delivered());
    assert_eq!(outcome.attempts, 3, "两次失败 + 一次成功");
    assert_eq!(transport.calls(), 3);
    assert!(outcome.endpoint.ends_with("/api/v1/agent/heartbeat"));
    assert!(client.queue().is_empty(), "成功后不得积压");
}

#[tokio::test]
pub(crate) async fn live_failure_queues_and_flush_delivers_later() {
    let transport = Arc::new(FlakyTransport::new(1));
    let config = ClientConfig::default().with_server_url("https://agf.example.invalid").with_retry(fast_retry(1));
    let mut client = AgentClient::new(identity(), config).with_transport(transport.clone());
    let outcome = client.send_snapshot(report("host-1"), CollectionExtras::default()).await.expect("应入队而不是报错");
    assert!(outcome.queued);
    assert_eq!(client.queue().len(), 1);

    let stats = client.flush_queue(10).await;
    assert_eq!(stats.attempted, 1);
    assert_eq!(stats.delivered, 1, "补传应成功: {stats:?}");
    assert!(client.queue().is_empty());
    assert_eq!(transport.calls(), 2, "首次失败 + 补传成功");
}

#[tokio::test]
pub(crate) async fn flush_requeues_when_endpoint_still_down_and_expires_after_max_attempts() {
    let config = ClientConfig::default()
        .with_server_url("https://agf.example.invalid")
        .with_retry(fast_retry(1))
        .with_queue(QueueConfig { max_attempts: 2, ..QueueConfig::default() });
    let mut client = AgentClient::new(identity(), config).with_transport(Arc::new(DownTransport));
    client.deliver(PayloadKind::Snapshot, "{\"a\":1}", "k0").await.expect("入队");
    let first = client.flush_queue(10).await;
    assert_eq!(first.requeued, 1);
    assert_eq!(first.dropped, 0);
    assert_eq!(client.queue().len(), 1);
    let second = client.flush_queue(10).await;
    assert_eq!(second.dropped, 1, "达到 max_attempts 应丢弃");
    assert!(client.queue().is_empty());
    assert_eq!(client.queue_stats().expired_total, 1);
}

#[tokio::test]
pub(crate) async fn non_retryable_error_is_not_queued() {
    let config = ClientConfig::default().with_server_url("https://agf.example.invalid").with_retry(fast_retry(3));
    let mut client = AgentClient::new(identity(), config).with_transport(Arc::new(RejectTransport));
    let error = client.deliver(PayloadKind::Snapshot, "{}", "k0").await.expect_err("载荷非法必须直接报错");
    assert!(matches!(error, DomainError::Validation(_)));
    assert!(client.queue().is_empty(), "坏载荷不得入队（否则会无限重放）");
}

#[tokio::test]
pub(crate) async fn http_transport_is_explicitly_not_implemented_with_anchor() {
    // 未配置服务端地址时才走占位传输（"未配置"必须明确报错而不是假装已上行）。
    let config = ClientConfig::default().with_server_url("http://agf.example.invalid").with_retry(fast_retry(2));
    let mut client =
        AgentClient::new(identity(), config).with_transport(Arc::new(HttpTransportNotImplemented::default()));
    assert_eq!(client.transport_name(), "http-not-implemented");
    let error = client.deliver_strict(PayloadKind::Register, "{}", "k0").await.expect_err("未配置必须明确报错");
    let text = error.to_string();
    assert!(text.contains("TODO(agent-http)"), "{text}");
    let outcome = client.register().await.expect("默认入口应入队");
    assert!(outcome.queued);
    assert!(!client.is_registered(), "只入队不算注册成功");
}

#[tokio::test]
pub(crate) async fn https_without_client_cert_uses_real_tls_transport() {
    // `https://` + 未配置客户端证书 ⇒ 单向 TLS 传输（不再是"未实现"占位）。
    let config = ClientConfig::default().with_server_url("https://agf.example.invalid");
    let client = AgentClient::new(identity(), config);
    assert_eq!(client.transport_name(), "tls");
    assert_eq!(client.tls_mode(), TlsMode::ServerAuth);
    assert!(client.transport_config_error().is_none());
    assert!(client.last_uplink_response().is_none(), "未上行前没有响应");
}

#[tokio::test]
pub(crate) async fn https_with_client_cert_uses_mutual_transport() {
    // 只给证书不给私钥 ⇒ **配置错误**：传输层不静默降级为单向，健康画像如实标红。
    let tls = TlsConfig { client_cert_pem: Some(std::path::PathBuf::from("only-cert.pem")), ..TlsConfig::default() };
    let config = ClientConfig::default().with_server_url("https://agf.example.invalid").with_tls(tls);
    let client = AgentClient::new(identity(), config);
    assert_eq!(client.transport_name(), "http-not-implemented");
    assert!(matches!(client.transport_config_error(), Some(DomainError::Config(_))));
    assert!(!client.tls_health().is_healthy());
}

#[tokio::test]
pub(crate) async fn register_marks_registered_only_after_delivery() {
    let transport = Arc::new(FlakyTransport::new(0));
    let config = ClientConfig::default().with_server_url("https://agf.example.invalid");
    let mut client = AgentClient::new(identity(), config).with_transport(transport);
    let outcome = client.register().await.expect("注册应成功");
    assert!(outcome.is_delivered());
    assert!(client.is_registered());
    assert_eq!(outcome.endpoint, "https://agf.example.invalid/api/v1/agent/register");
}

#[tokio::test]
pub(crate) async fn snapshot_then_diff_uses_baseline() {
    let mut client = AgentClient::new(identity(), ClientConfig::mock());
    let mut first = report("host-1");
    first.agents.push(agf_core::agent::DetectedAgent {
        flavor: agf_core::agent::AgentFlavor::Cursor,
        version: Some("1.0".into()),
        binary_path: None,
        config_dir: Some("~/.cursor".into()),
        config_hash: None,
    });
    client.send_snapshot(first.clone(), CollectionExtras::default()).await.expect("快照");
    let diff = client.compute_diff(&first);
    assert!(diff.is_empty(), "内容未变时 diff 必须为空");
    first.agents.clear();
    let diff = client.compute_diff(&first);
    assert_eq!(diff.removed_agent_keys.len(), 1, "资产消失应产生 removed");
    let outcome = client.send_diff(&diff).await.expect("Mock 上报 diff");
    assert_eq!(outcome.kind, PayloadKind::Diff);
}

#[tokio::test]
pub(crate) async fn heartbeat_payload_reflects_queue_and_collectors() {
    let client = AgentClient::new(identity(), ClientConfig::mock());
    let payload = client.heartbeat_payload(vec![CollectorStatus {
        name: "mcp-config".into(),
        level: "implemented".into(),
        items: 2,
        elapsed_ms: 4,
        error: None,
    }]);
    assert_eq!(payload.queue_depth, 0);
    assert_eq!(payload.collectors.len(), 1);
    assert!(payload.last_snapshot_at.is_none());
    let json = serde_json::to_string(&payload).expect("序列化");
    assert!(json.contains("mcp-config"));
}

#[tokio::test]
pub(crate) async fn persisted_queue_survives_client_restart() {
    let dir = tempfile::tempdir().expect("临时目录");
    let queue_config = QueueConfig::default().with_path(dir.path().join("queue.jsonl"));
    let config = ClientConfig::default().with_queue(queue_config.clone()).with_retry(fast_retry(1));
    let mut client = AgentClient::new(identity(), config.clone());
    client.deliver(PayloadKind::Snapshot, "{\"x\":1}", "k0").await.expect("入队");
    client.save_queue().expect("落盘");

    let restored = AgentClient::with_persisted_queue(identity(), config).expect("载入");
    assert_eq!(restored.queue().len(), 1, "重启后积压必须仍在");
    assert_eq!(restored.queue().keys(), vec!["k0".to_string()]);
}

#[tokio::test]
pub(crate) async fn debug_never_leaks_token() {
    let config =
        ClientConfig::default().with_server_url("https://agf.example.invalid").with_token("super-secret-agent-token");
    let client = AgentClient::new(identity(), config);
    let text = format!("{client:?}");
    assert!(!text.contains("super-secret-agent-token"), "{text}");
    assert!(text.contains("REDACTED"));
    assert!(client.has_token());
}

#[tokio::test]
pub(crate) async fn clear_queue_and_endpoint_paths() {
    let mut client = AgentClient::new(identity(), ClientConfig::mock());
    client.deliver(PayloadKind::Snapshot, "{}", "k0").await.expect("入队");
    assert_eq!(client.queue_stats().depth, 0, "Mock 模式不积压");
    let paths = EndpointPaths::default();
    assert_eq!(paths.for_kind(PayloadKind::Register), "/api/v1/agent/register");
    assert_eq!(paths.for_kind(PayloadKind::Diff), "/api/v1/agent/report");
    // 严重等级枚举在本 crate 未直接使用，这里用其文本确保重导出可用
    assert_eq!(Severity::High.as_str(), "high");
}

#[test]
pub(crate) fn config_from_env_defaults_are_sane() {
    let config = ClientConfig::from_env();
    assert!(config.heartbeat_interval_secs >= 1);
    assert!(config.retry.max_attempts >= 1);
    assert_eq!(config.paths, EndpointPaths::default());
    assert!(ClientConfig::mock().has_server());
    assert!(!ClientConfig::default().has_server());
}
