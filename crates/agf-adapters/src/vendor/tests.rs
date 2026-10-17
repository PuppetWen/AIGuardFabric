//! 由 `vendor.rs` 拆分：`base_config`/`message` 等 29 项（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn base_config() -> AdapterConfig {
    let now = Timestamp::now();
    AdapterConfig {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        adapter: "test".into(),
        display_name: "测试".into(),
        enabled: true,
        settings: BTreeMap::new(),
        secret_refs: BTreeMap::new(),
        circuit_breaker: CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 2,
            open_secs: 30,
            half_open_probes: 1,
        },
        retry: RetryConfig {
            max_attempts: 3,
            initial_backoff_ms: 1,
            multiplier: 1.0,
            max_backoff_ms: 2,
            jitter: false,
        },
        timeout_secs: 5,
        mock: false,
        is_default: false,
        created_at: now,
        updated_at: now,
    }
}

pub(crate) fn message() -> AdapterMessage {
    AdapterMessage::event("test.ping", Severity::High, "标题", "摘要", serde_json::json!({"n": 1}))
}

// --- 测试用厂商（覆盖重试 / 熔断 / 非可重试 / Mock 路径） ---

/// 前两次失败、第三次成功（验证"重试后成功"）。
pub(crate) struct FlakyVendor;

pub(crate) static FLAKY_CALLS: AtomicU32 = AtomicU32::new(0);

#[async_trait]
impl VendorSpec for FlakyVendor {
    const NAME: &'static str = "test-flaky";
    const TODO_ANCHOR: &'static str = "adapter-test-flaky";
    const REAL_TRANSPORT: bool = true;

    fn metadata() -> AdapterMetadata {
        AdapterMetadata::new("test-flaky", "测试-重试", "test", AdapterCategory::Notification)
            .with_capabilities(vec![AdapterCapability::PushEvents])
            .with_semantics(SemanticProfile::full())
            .with_real_transport(true)
            .with_degradation("测试用：未配置时不发送")
    }

    fn encode(_msg: &AdapterMessage, _settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        Ok(VendorRequest::post("https://flaky.example.invalid/hook", "application/json", serde_json::json!({})))
    }

    async fn invoke_live(_req: &VendorRequest, _settings: &AdapterSettings) -> DomainResult<Option<String>> {
        let n = FLAKY_CALLS.fetch_add(1, Ordering::SeqCst) + 1;
        if n < 3 {
            Err(DomainError::DependencyUnavailable {
                dependency: "flaky".into(), cause: format!("第 {n} 次模拟失败")
            })
        } else {
            Ok(Some("remote-ok".to_string()))
        }
    }

    /// 声明了 `full()` 就必须覆盖语义编码（否则 Mock 校验/真实调用都会报"实现缺陷"）。
    fn encode_push(payload: &PushPayload, _settings: &AdapterSettings) -> DomainResult<Vec<VendorRequest>> {
        Ok(vec![VendorRequest::post("https://flaky.example.invalid/push", "application/json", payload.body.clone())])
    }

    fn encode_pull(_req: &PullRequest, _settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        Ok(VendorRequest::channel("GET", "https://flaky.example.invalid/pull", serde_json::Value::Null))
    }
}

/// 恒失败（可重试错误），用于熔断开路。
pub(crate) struct DownVendor;

pub(crate) static DOWN_CALLS: AtomicU32 = AtomicU32::new(0);

#[async_trait]
impl VendorSpec for DownVendor {
    const NAME: &'static str = "test-down";
    const TODO_ANCHOR: &'static str = "adapter-test-down";
    const REAL_TRANSPORT: bool = true;

    fn metadata() -> AdapterMetadata {
        AdapterMetadata::new("test-down", "测试-熔断", "test", AdapterCategory::SecurityPlatform)
            .with_real_transport(true)
            .with_degradation("测试用")
    }

    fn encode(_msg: &AdapterMessage, _settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        Ok(VendorRequest::post("https://down.example.invalid/x", "application/json", serde_json::json!({})))
    }

    async fn invoke_live(_req: &VendorRequest, _settings: &AdapterSettings) -> DomainResult<Option<String>> {
        DOWN_CALLS.fetch_add(1, Ordering::SeqCst);
        Err(DomainError::DependencyUnavailable { dependency: "down".into(), cause: "服务不可达".into() })
    }
}

/// 非可重试错误（校验失败），用于验证"业务错误一次都不重试"。
pub(crate) struct StrictVendor;

pub(crate) static STRICT_CALLS: AtomicU32 = AtomicU32::new(0);

#[async_trait]
impl VendorSpec for StrictVendor {
    const NAME: &'static str = "test-strict";
    const TODO_ANCHOR: &'static str = "adapter-test-strict";
    const REAL_TRANSPORT: bool = true;

    fn metadata() -> AdapterMetadata {
        AdapterMetadata::new("test-strict", "测试-非重试", "test", AdapterCategory::Itsm).with_real_transport(true)
    }

    fn encode(_msg: &AdapterMessage, _settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        Ok(VendorRequest::post("https://strict.example.invalid/y", "application/json", serde_json::json!({})))
    }

    async fn invoke_live(_req: &VendorRequest, _settings: &AdapterSettings) -> DomainResult<Option<String>> {
        STRICT_CALLS.fetch_add(1, Ordering::SeqCst);
        Err(DomainError::Validation("远端字段非法".into()))
    }
}

/// 阶段一常态：配置齐全但没有真实传输。
pub(crate) struct TodoVendor;

pub(crate) static TODO_CALLS: AtomicU32 = AtomicU32::new(0);

#[async_trait]
impl VendorSpec for TodoVendor {
    const NAME: &'static str = "test-todo";
    const TODO_ANCHOR: &'static str = "adapter-test-todo";

    fn metadata() -> AdapterMetadata {
        AdapterMetadata::new("test-todo", "测试-未实现", "test", AdapterCategory::Notification)
            .with_secrets(&["webhook_url"], &[])
            .with_capabilities(vec![AdapterCapability::PushEvents, AdapterCapability::SelfCheck])
            .with_degradation("未配置时不下发通知；平台主流程不受影响")
    }

    fn encode(_msg: &AdapterMessage, _settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        Ok(VendorRequest::post("https://todo.example.invalid/z", "application/json", serde_json::json!({})))
    }

    async fn invoke_live(_req: &VendorRequest, _settings: &AdapterSettings) -> DomainResult<Option<String>> {
        // 故意计数：未实现真实传输的适配器（阶段一形态）必须"不发起任何真实调用"
        TODO_CALLS.fetch_add(1, Ordering::SeqCst);
        Err(DomainError::NotImplemented("test-todo：真实调用尚未实现（TODO(adapter-test-todo)）".to_string()))
    }
}

pub(crate) fn static_secrets(value: &str) -> crate::settings::StaticSecrets {
    crate::settings::StaticSecrets::new().with("webhook_url", value)
}

/// 声明了 `full()` 却**未覆盖**语义编码：用于验证"实现缺陷"被如实报出（而不是伪装成 Unsupported）。
pub(crate) struct DeclaredOnlyVendor;

#[async_trait]
impl VendorSpec for DeclaredOnlyVendor {
    const NAME: &'static str = "test-declared-only";
    const REAL_TRANSPORT: bool = true;

    fn metadata() -> AdapterMetadata {
        AdapterMetadata::new("test-declared-only", "测试-声明未覆盖", "test", AdapterCategory::Itsm)
            .with_semantics(SemanticProfile::full())
            .with_real_transport(true)
            .with_degradation("测试用：声明了语义但未实现编码")
    }

    fn encode(_msg: &AdapterMessage, _settings: &AdapterSettings) -> DomainResult<VendorRequest> {
        Ok(VendorRequest::post("https://declared.example.invalid/x", "application/json", serde_json::json!({})))
    }
}
#[tokio::test]
pub(crate) async fn unconfigured_init_does_not_fail_and_marks_unconfigured() {
    let mut adapter = VendorAdapterImpl::<TodoVendor>::new();
    let result = adapter.init_with(&base_config(), &crate::settings::NoSecrets, false).await;
    assert!(result.is_ok(), "未配置不得导致 init 失败");
    assert_eq!(adapter.mode(), AdapterMode::Unconfigured);
    let record = adapter.build_record();
    assert!(!record.configured);
    assert_eq!(record.status, crate::health::HealthStatus::Degraded);
    assert!(record.message.unwrap_or_default().contains("webhook_url"));
}

#[tokio::test]
pub(crate) async fn invalid_config_is_rejected_and_keeps_old_config() {
    let mut adapter = VendorAdapterImpl::<TodoVendor>::new();
    let secrets = static_secrets("https://hook.example.invalid/abc");
    adapter.init_with(&base_config(), &secrets, false).await.expect("合法配置应成功");
    assert_eq!(adapter.mode(), AdapterMode::Live);
    let mut bad = base_config();
    bad.timeout_secs = 0;
    let result = adapter.init_with(&bad, &secrets, false).await;
    assert!(matches!(result, Err(DomainError::Config(_))), "非法配置必须报 Config");
    assert_eq!(adapter.mode(), AdapterMode::Live, "失败必须保持旧配置");
    assert_eq!(adapter.settings().timeout_secs, 5);
}

#[tokio::test]
pub(crate) async fn mock_mode_never_calls_real_transport_and_is_deterministic() {
    let mut adapter = VendorAdapterImpl::<TodoVendor>::mocked();
    assert_eq!(adapter.mode(), AdapterMode::Mocked);
    let before = TODO_CALLS.load(Ordering::SeqCst);
    let msg = message();
    let first = adapter.send(&msg).await.expect("Mock 发送必须成功");
    let second = adapter.send(&msg).await.expect("Mock 发送必须成功");
    assert!(first.mocked && second.mocked);
    assert_eq!(first.remote_id, second.remote_id, "Mock 回执必须确定性");
    assert_eq!(first.origin, "mock://test-todo");
    assert_eq!(TODO_CALLS.load(Ordering::SeqCst), before, "Mock 模式绝不触达真实传输");
    let record = adapter.build_record();
    assert!(record.message.unwrap_or_default().contains("AGF_MOCK_MODE"));
}

#[tokio::test]
pub(crate) async fn live_without_implementation_returns_todo_not_success() {
    let mut adapter = VendorAdapterImpl::<TodoVendor>::new();
    let secrets = static_secrets("https://hook.example.invalid/abc");
    adapter.init_with(&base_config(), &secrets, false).await.expect("合法配置应成功");
    assert_eq!(adapter.mode(), AdapterMode::Live);
    let error = adapter.send(&message()).await.expect_err("未实现必须如实返回错误");
    let text = error.to_string();
    assert!(text.contains("TODO(adapter-test-todo)"), "错误必须带 TODO 锚点: {text}");
    assert!(matches!(error, DomainError::NotImplemented(_)));
    let record = adapter.build_record();
    assert_eq!(record.status, crate::health::HealthStatus::Unavailable);
    assert!(record.message.unwrap_or_default().contains("TODO(adapter-test-todo)"));
}

#[tokio::test]
pub(crate) async fn retries_then_succeeds_and_reports_attempts() {
    FLAKY_CALLS.store(0, Ordering::SeqCst);
    let mut adapter = VendorAdapterImpl::<FlakyVendor>::new();
    adapter.init_with(&base_config(), &crate::settings::NoSecrets, false).await.expect("无必需凭据应可 init");
    assert_eq!(adapter.mode(), AdapterMode::Live);
    let receipt = adapter.send(&message()).await.expect("第三次尝试应成功");
    assert_eq!(receipt.attempts, 3, "max_attempts=3 且前两次失败 ⇒ 尝试 3 次");
    assert!(!receipt.mocked);
    assert_eq!(receipt.remote_id.as_deref(), Some("remote-ok"));
    assert_eq!(adapter.build_record().status, crate::health::HealthStatus::Available);
    assert_eq!(adapter.circuit().consecutive_failures, 0, "成功后连续失败数清零");
}

#[tokio::test]
pub(crate) async fn circuit_opens_after_threshold_and_recovers_status() {
    DOWN_CALLS.store(0, Ordering::SeqCst);
    let mut adapter = VendorAdapterImpl::<DownVendor>::new();
    let mut config = base_config();
    config.retry =
        RetryConfig { max_attempts: 1, initial_backoff_ms: 1, multiplier: 1.0, max_backoff_ms: 1, jitter: false };
    adapter.init_with(&config, &crate::settings::NoSecrets, false).await.expect("init 应成功");
    for _ in 0..2 {
        assert!(adapter.send(&message()).await.is_err());
    }
    let record = adapter.build_record();
    assert_eq!(record.consecutive_failures, 2);
    assert_eq!(record.status, crate::health::HealthStatus::Unavailable);
    assert_eq!(record.health_state(), agf_core::enums::HealthState::CircuitOpen);
    let calls_before = DOWN_CALLS.load(Ordering::SeqCst);
    let error = adapter.send(&message()).await.expect_err("开路后必须快速失败");
    assert!(error.to_string().contains("熔断器处于 open"), "{error}");
    assert_eq!(DOWN_CALLS.load(Ordering::SeqCst), calls_before, "开路期间绝不触达外部系统");
}

#[tokio::test]
pub(crate) async fn non_retryable_error_is_attempted_once() {
    STRICT_CALLS.store(0, Ordering::SeqCst);
    let mut adapter = VendorAdapterImpl::<StrictVendor>::new();
    adapter.init_with(&base_config(), &crate::settings::NoSecrets, false).await.expect("init 应成功");
    assert!(adapter.send(&message()).await.is_err());
    assert_eq!(STRICT_CALLS.load(Ordering::SeqCst), 1, "校验类错误不得重试");
    let record = adapter.build_record();
    assert_eq!(record.last_attempts, 1);
    assert_eq!(record.status, crate::health::HealthStatus::Degraded);
}

#[tokio::test]
pub(crate) async fn unconfigured_send_reports_missing_keys_without_calling_out() {
    TODO_CALLS.store(0, Ordering::SeqCst);
    let mut adapter = VendorAdapterImpl::<TodoVendor>::new();
    adapter.init_with(&base_config(), &crate::settings::NoSecrets, false).await.expect("init 应成功");
    let error = adapter.send(&message()).await.expect_err("未配置必须明确失败");
    assert!(matches!(error, DomainError::Config(_)));
    assert!(error.to_string().contains("webhook_url"));
    assert_eq!(TODO_CALLS.load(Ordering::SeqCst), 0);
}

#[tokio::test]
pub(crate) async fn close_is_idempotent_and_blocks_send() {
    let mut adapter = VendorAdapterImpl::<TodoVendor>::mocked();
    adapter.close().await.expect("首次关闭成功");
    adapter.close().await.expect("重复关闭必须幂等成功");
    assert!(adapter.is_closed());
    let error = adapter.send(&message()).await.expect_err("关闭后不得再发送");
    assert!(matches!(error, DomainError::PreconditionFailed(_)));
}

#[tokio::test]
pub(crate) async fn shutdown_via_core_contract_is_idempotent() {
    let mut adapter = VendorAdapterImpl::<TodoVendor>::mocked();
    CoreAdapter::shutdown(&mut adapter).await.expect("首次 shutdown");
    CoreAdapter::shutdown(&mut adapter).await.expect("重复 shutdown");
    assert_eq!(CoreAdapter::name(&adapter), "test-todo");
    assert_eq!(CoreAdapter::descriptor(&adapter).category, "message");
}

#[tokio::test]
pub(crate) async fn core_contract_mock_semantics_are_deterministic_for_declared_capability() {
    // FlakyVendor 声明 full()：Mock 下三条语义都返回确定性降级结果（零网络）
    let adapter = VendorAdapterImpl::<FlakyVendor>::mocked();
    let request = PullRequest { resource: "alarms".into(), ..PullRequest::default() };
    let outcome = CoreAdapter::sync(&adapter, SyncDirection::Both, &request).await.expect("Mock 下 sync 应成功");
    assert!(outcome.mocked && outcome.degraded);
    assert!(outcome.warnings.iter().any(|w| w.contains("AGF_MOCK_MODE")));
    let response = CoreAdapter::pull(&adapter, &request).await.expect("Mock 下 pull 应成功");
    assert!(response.mocked);
    assert!(response.origin.contains("mock://test-flaky"));
    CoreAdapter::push(
        &adapter,
        &PushPayload {
            entity: "event".into(),
            entity_id: "1".into(),
            body: serde_json::json!({}),
            idempotency_key: None,
        },
    )
    .await
    .expect("Mock 下 push 应成功");

    // VendorAdapter 面：Mock 回写回执必须确定性且零请求
    let payload = PushPayload {
        entity: "event".into(),
        entity_id: "1".into(),
        body: serde_json::json!({}),
        idempotency_key: None,
    };
    let first = VendorAdapter::push(&adapter, &payload).await.expect("Mock 回写");
    let second = VendorAdapter::push(&adapter, &payload).await.expect("Mock 回写");
    assert!(first.mocked && second.mocked);
    assert_eq!(first.requests, 0, "Mock 不发请求");
    assert_eq!(first.remote_id, second.remote_id, "Mock 回执必须确定性");
    assert!(first.remote_id.unwrap_or_default().starts_with("mock-push-"));
}

#[tokio::test]
pub(crate) async fn undeclared_semantics_are_honestly_unavailable_in_every_mode() {
    // TodoVendor 既未登记语义、也没有真实传输 ⇒ Mock 与 Live 都如实返回 NotImplemented + TODO 锚点
    let adapter = VendorAdapterImpl::<TodoVendor>::mocked();
    let request = PullRequest { resource: "alarms".into(), ..PullRequest::default() };
    let error = CoreAdapter::sync(&adapter, SyncDirection::Both, &request).await.expect_err("未登记语义不得假装成功");
    assert!(matches!(error, DomainError::NotImplemented(_)), "{error}");
    assert!(error.to_string().contains("TODO(adapter-test-todo)"), "{error}");
    assert!(CoreAdapter::pull(&adapter, &request).await.is_err());
    let payload = PushPayload {
        entity: "event".into(),
        entity_id: "1".into(),
        body: serde_json::json!({}),
        idempotency_key: None,
    };
    assert!(CoreAdapter::push(&adapter, &payload).await.is_err());

    let mut live = VendorAdapterImpl::<TodoVendor>::new();
    live.init_with(&base_config(), &crate::settings::NoSecrets, false).await.expect("init");
    assert!(CoreAdapter::sync(&live, SyncDirection::Pull, &request).await.is_err());
    assert!(CoreAdapter::pull(&live, &request).await.is_err());
}

#[tokio::test]
pub(crate) async fn declared_but_uncovered_semantic_reports_implementation_defect() {
    // DeclaredOnlyVendor 声明了 full() 但未覆写 encode_pull ⇒ Live 必须报"实现缺陷"，而不是伪装成 Unsupported
    let mut live = VendorAdapterImpl::<DeclaredOnlyVendor>::new();
    live.init_with(&base_config(), &crate::settings::NoSecrets, false).await.expect("init");
    assert_eq!(live.mode(), AdapterMode::Live);
    let error = CoreAdapter::pull(&live, &PullRequest { resource: "alarms".into(), ..PullRequest::default() })
        .await
        .expect_err("声明 Implemented 却未覆盖编码 ⇒ 缺陷");
    assert!(matches!(error, DomainError::Internal(_)), "{error}");
    assert!(error.to_string().contains("实现缺陷"), "{error}");
}

#[tokio::test]
pub(crate) async fn health_bridges_to_core_adapter_health() {
    let mut adapter = VendorAdapterImpl::<TodoVendor>::mocked();
    let health = CoreAdapter::health(&adapter).await.expect("健康检查不应失败");
    assert_eq!(health.adapter, "test-todo");
    assert!(health.mocked);
    assert_eq!(health.capabilities.len(), 2);
    // VendorAdapter::health 默认实现走 health_check 转换
    adapter.init_with(&base_config(), &crate::settings::NoSecrets, false).await.expect("init");
    let record = adapter.health_check().await.expect("健康检查");
    assert_eq!(record.status, crate::health::HealthStatus::Degraded);
}

#[tokio::test]
pub(crate) async fn subscribe_filter_and_event_prefixes() {
    let adapter = VendorAdapterImpl::<TodoVendor>::mocked();
    let notification = AdapterMessage::notification("标题", "摘要");
    assert!(adapter.subscribes(&notification));
    assert_eq!(notification.kind, MessageKind::Notification);
    assert!(adapter.encode(&notification).is_ok());
}

#[tokio::test]
pub(crate) async fn debug_output_does_not_leak_credentials() {
    let mut adapter = VendorAdapterImpl::<TodoVendor>::new();
    let secrets = static_secrets("https://hook.example.invalid/plaintext-secret-1234");
    adapter.init_with(&base_config(), &secrets, false).await.expect("init");
    let text = format!("{adapter:?}");
    assert!(!text.contains("plaintext-secret-1234"), "Debug 不得泄露凭据: {text}");
    assert!(text.contains("test-todo"));
    assert_eq!(
        adapter.settings().secret_raw("webhook_url"),
        Some("https://hook.example.invalid/plaintext-secret-1234")
    );
}
