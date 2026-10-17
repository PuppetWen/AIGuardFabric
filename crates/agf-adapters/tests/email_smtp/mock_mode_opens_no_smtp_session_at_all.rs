//! 由 `email_smtp.rs` 拆分：`mock_mode_opens_no_smtp_session_at_all` 等 4 个函数（纯搬移，逻辑不变）。
use super::*;

#[tokio::test]
pub(crate) async fn mock_mode_opens_no_smtp_session_at_all() {
    let (port, sessions) = fake_smtp(SmtpBehavior::default()).await;
    let mut email = email_adapter(port, &[], &[], retry_once(), true).await;

    assert_eq!(email.mode(), AdapterMode::Mocked);
    let receipt = email.send(&alerts()).await.expect("Mock 发送必须成功");
    assert!(receipt.mocked);
    assert_eq!(receipt.origin, "mock://email");
    assert_eq!(count_after_grace(&sessions).await, 0, "Mock 模式必须零 SMTP 连接");
}

#[tokio::test]
pub(crate) async fn unconfigured_smtp_reports_config_error_without_connecting() {
    let (port, sessions) = fake_smtp(SmtpBehavior::default()).await;
    // 只给 smtp_host/port（缺 from 与收件人）⇒ Unconfigured
    let now = Timestamp::now();
    let mut settings = BTreeMap::new();
    settings.insert("smtp_host".to_string(), json!("127.0.0.1"));
    settings.insert("smtp_port".to_string(), json!(port));
    let config = AdapterConfig {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        adapter: Email::NAME.to_string(),
        display_name: "email-unconfigured".to_string(),
        enabled: true,
        settings,
        secret_refs: BTreeMap::new(),
        circuit_breaker: circuit(3, 30),
        retry: retry_once(),
        timeout_secs: 5,
        mock: false,
        is_default: true,
        created_at: now,
        updated_at: now,
    };
    let mut email = VendorAdapterImpl::<Email>::new();
    email.init_with(&config, &StaticSecrets::new(), false).await.expect("未配置不得导致 init 失败");

    assert_eq!(email.mode(), AdapterMode::Unconfigured);
    let record = email.health_check().await.expect("健康检查不得失败");
    assert_eq!(record.status, agf_adapters::HealthStatus::Degraded, "未配置是降级而非失败");
    assert!(!record.configured);
    let error = email.send(&alerts()).await.expect_err("未配置必须明确报错");
    assert!(matches!(error, DomainError::Config(_)), "{error}");
    assert!(error.to_string().contains("from"), "错误必须列出缺项: {error}");
    assert_eq!(count_after_grace(&sessions).await, 0, "未配置必须不建连");
}

#[tokio::test]
pub(crate) async fn unreachable_smtp_host_is_reported_as_retryable_dependency_failure() {
    // 127.0.0.1:1 上无监听者：真实建连被拒 ⇒ 可重试的依赖不可用（而非 NotImplemented/假装成功）
    let mut email = email_adapter(1, &[], &[], retry_once(), false).await;
    assert_eq!(email.mode(), AdapterMode::Live);
    let error = email.send(&alerts()).await.expect_err("不可达目标必须如实报错");
    let retryable = error.is_degradable() || matches!(error, DomainError::Timeout(_));
    assert!(retryable, "网络类失败必须可重试: {error}");
    assert!(!matches!(error, DomainError::NotImplemented(_)), "email 已实现真实投递: {error}");
    assert!(!error.to_string().contains("TODO("), "{error}");
}

#[tokio::test]
pub(crate) async fn starttls_is_mandatory_and_refuses_silent_plaintext_downgrade() {
    // 明文路径的完整往返已由首个用例覆盖；这里断言 `smtp_security` 与建连形态的对应关系，
    // 以及"服务端不声明 STARTTLS 时绝不降级为明文发信"。
    let (port, sessions) = fake_smtp(SmtpBehavior::default()).await;
    let mut plain = email_adapter(port, &[("smtp_security", json!("none"))], &[], retry_once(), false).await;
    assert!(!plain.send(&alerts()).await.expect("明文投递").mocked);
    assert_eq!(wait_sessions(&sessions, 1).await.len(), 1);
    assert_eq!(
        Email::profile(plain.settings()).expect("画像").security_mode(),
        SmtpSecurity::None,
        "smtp_security=none ⇒ 明文"
    );

    let (tls_port, tls_sessions) = fake_smtp(SmtpBehavior::default()).await;
    let mut starttls = email_adapter(tls_port, &[("smtp_security", json!("starttls"))], &[], retry_once(), false).await;
    let error = starttls.send(&alerts()).await.expect_err("服务端不支持 STARTTLS 时必须失败，而不是明文发送");
    assert!(
        matches!(error, DomainError::DependencyUnavailable { .. } | DomainError::Timeout(_)),
        "STARTTLS 不可用属可重试的依赖问题: {error}"
    );
    let observed = wait_sessions(&tls_sessions, 1).await;
    assert!(observed[0].data.is_empty(), "未完成 STARTTLS 升级前不得发送任何报文正文");
    println!("=== STARTTLS 强制升级证据：错误 = {error}；服务端未收到 DATA ===");
}
