//! 由 `registry.rs` 拆分：`SLACK_HOOK`/`local_feishu` 等 22 项（纯搬移，逻辑不变）。
use super::*;

// Intentionally invalid Slack credential; configuration validation only needs the /services/ prefix.
pub(crate) const SLACK_HOOK: &str = "https://hooks.slack.com/services/test-only";

/// 挂一个"飞书业务成功"的本地假服务器，返回指向它的 webhook 地址。
pub(crate) async fn local_feishu(server: &MockServer) -> String {
    Mock::given(path("/open-apis/bot/v2/hook/local"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"code": 0, "msg": "success"})))
        .expect(1)
        .mount(server)
        .await;
    format!("{}/open-apis/bot/v2/hook/local", server.uri())
}

pub(crate) fn registry_mock() -> AdapterRegistry {
    AdapterRegistry::mock_only(TenantId::default_tenant()).expect("内置注册不得失败")
}

pub(crate) fn message(severity: Severity) -> AdapterMessage {
    AdapterMessage::event("ai.asset.discovered", severity, "发现资产", "cursor@host1", json!({}))
}

#[test]
pub(crate) fn mock_only_registers_every_builtin() {
    let registry = registry_mock();
    assert_eq!(registry.len(), crate::vendors::BUILTIN_NAMES.len());
    assert!(registry.mock_mode());
    assert!(registry.contains("feishu"));
    assert!(registry.contains("edr-isolation"));
    assert!(registry.names().windows(2).all(|w| w[0] <= w[1]), "names 必须有序");
    assert_eq!(registry.descriptors().len(), crate::vendors::BUILTIN_NAMES.len());
}

#[test]
pub(crate) fn duplicate_registration_is_conflict() {
    let mut registry = registry_mock();
    let again = registry.register::<crate::vendors::feishu::Feishu>();
    assert!(matches!(again, Err(DomainError::Conflict(_))));
    assert_eq!(registry.len(), crate::vendors::BUILTIN_NAMES.len());
}

#[test]
pub(crate) fn register_unknown_and_lookup_failures_are_reported() {
    let registry = AdapterRegistry::new(TenantId::default_tenant(), true);
    assert!(registry.is_empty());
    assert!(registry.handle("nope").is_none());
    assert!(registry.is_enabled("nope").is_none());
    assert!(registry.rule("nope").is_none());
}

#[test]
pub(crate) fn debug_lists_adapter_names_without_credentials() {
    let registry = registry_mock();
    let text = format!("{registry:?}");
    assert!(text.contains("feishu"));
    assert!(!text.contains("hook/abcdef"), "注册表 Debug 不得含凭据");
}

#[tokio::test]
pub(crate) async fn route_respects_prefix_and_severity() {
    let mut registry = registry_mock();
    registry
        .subscribe(SubscriptionRule::all("feishu").with_prefixes(&["ai."]).with_min_severity(Severity::High))
        .expect("规则设置应成功");
    assert!(registry.route(&message(Severity::High)).await.contains(&"feishu".to_string()));
    assert!(!registry.route(&message(Severity::Low)).await.contains(&"feishu".to_string()));
    let notify = AdapterMessage::notification("普通通知", "摘要").with_severity(Severity::High);
    assert!(!registry.route(&notify).await.contains(&"feishu".to_string()), "前缀不匹配不得路由");
    assert!(registry.route(&notify).await.contains(&"slack".to_string()), "全订阅适配器仍应命中");
}

#[tokio::test]
pub(crate) async fn route_respects_vendor_level_filter() {
    let registry = registry_mock();
    let plain = AdapterMessage::notification("普通告警", "摘要").with_severity(Severity::Critical);
    let routed = registry.route(&plain).await;
    assert!(!routed.contains(&"edr-isolation".to_string()), "EDR 只订隔离类载荷");
    let isolate = AdapterMessage::event("enforce.isolate", Severity::Critical, "隔离", "检出 C2", json!({}))
        .with_label("host_id", "host-1");
    assert!(registry.route(&isolate).await.contains(&"edr-isolation".to_string()));
}

#[tokio::test]
pub(crate) async fn disabled_adapter_is_not_routed_and_send_is_rejected() {
    let mut registry = registry_mock();
    assert!(registry.set_enabled("feishu", false).expect("启停应成功"));
    assert_eq!(registry.is_enabled("feishu"), Some(false));
    assert!(!registry.route(&message(Severity::Critical)).await.contains(&"feishu".to_string()));
    let error = registry.send_to("feishu", &message(Severity::Critical)).await.expect_err("禁用后不得下发");
    assert!(matches!(error, DomainError::PreconditionFailed(_)));
    assert!(!registry.set_enabled("feishu", false).expect("重复禁用"), "状态未变化时返回 false");
    assert!(matches!(registry.set_enabled("nope", true), Err(DomainError::NotFound { .. })));
}

#[tokio::test]
pub(crate) async fn apply_config_rejects_invalid_and_keeps_old() {
    let server = MockServer::start().await;
    let hook = local_feishu(&server).await;

    let mut registry = AdapterRegistry::new(TenantId::default_tenant(), false);
    registry.register::<crate::vendors::feishu::Feishu>().expect("注册应成功");
    registry = registry.with_secrets(Arc::new(secrets(&[("webhook_url", &hook)])));
    let good = config_for("feishu", &[("allow_custom_host", json!(true))], false);
    registry.apply_config(&good).await.expect("合法配置应成功");
    let handle = registry.handle("feishu").expect("句柄存在");
    let mode_before = { handle.lock().await.mode() };
    assert_eq!(mode_before, AdapterMode::Live);

    let mut bad = good.clone();
    bad.timeout_secs = 0;
    let error = registry.apply_config(&bad).await.expect_err("非法配置必须报错");
    assert!(matches!(error, DomainError::Config(_)));
    // 旧配置仍然生效：模式不变，且真实下发仍走原 endpoint（本地假服务器收到请求）
    let mode_after = { handle.lock().await.mode() };
    assert_eq!(mode_after, AdapterMode::Live, "失败必须保持旧配置");
    assert_eq!(registry.metadata("feishu").map(|m| m.name), Some("feishu".to_string()));
    let receipt = registry.send_to("feishu", &message(Severity::High)).await.expect("旧配置必须仍可真实下发");
    assert!(receipt.accepted && !receipt.mocked);
    assert_eq!(receipt.origin, hook);
    server.verify().await;
}

#[tokio::test]
pub(crate) async fn apply_config_unknown_adapter_is_not_found() {
    let mut registry = registry_mock();
    let error = registry.apply_config(&config_for("not-registered", &[], true)).await.expect_err("未登记必须报错");
    assert!(matches!(error, DomainError::NotFound { .. }));
}

#[tokio::test]
pub(crate) async fn apply_config_switches_to_mock_and_live() {
    let server = MockServer::start().await;
    let hook = local_feishu(&server).await;

    let mut registry = AdapterRegistry::new(TenantId::default_tenant(), false);
    registry.register::<crate::vendors::feishu::Feishu>().expect("注册");
    registry = registry.with_secrets(Arc::new(secrets(&[("webhook_url", &hook)])));

    let mut mock_config = config_for("feishu", &[("allow_custom_host", json!(true))], true);
    registry.apply_config(&mock_config).await.expect("Mock 配置");
    let receipt = registry.send_to("feishu", &message(Severity::Critical)).await.expect("Mock 下发");
    assert!(receipt.mocked, "Mock 配置下不得触达外部系统");

    mock_config.mock = false;
    registry.apply_config(&mock_config).await.expect("Live 配置");
    let receipt = registry.send_to("feishu", &message(Severity::Critical)).await.expect("Live 真实下发");
    assert!(receipt.accepted && !receipt.mocked, "切回 Live 后必须真实发包");
    server.verify().await;

    // 缺凭据 → 降级为 Unconfigured（不报错，但下发明确失败）
    let mut empty = AdapterRegistry::new(TenantId::default_tenant(), false);
    empty.register::<crate::vendors::feishu::Feishu>().expect("注册");
    empty.apply_config(&config_for("feishu", &[], false)).await.expect("未配置不得导致失败");
    let health = empty.health_map().await;
    assert_eq!(health.get("feishu").map(|h| h.status), Some(HealthStatus::Degraded));
    assert!(empty.send_to("feishu", &message(Severity::Critical)).await.is_err());
}

#[tokio::test]
pub(crate) async fn apply_config_updates_rule_from_settings() {
    let mut registry = registry_mock();
    let config = config_for(
        "slack",
        &[("event_prefixes", json!(["ai.credential.", "enforce."])), ("min_severity", json!("high"))],
        true,
    );
    registry.apply_config(&config).await.expect("配置应成功");
    let rule = registry.rule("slack").cloned().expect("规则存在");
    assert_eq!(rule.event_prefixes, vec!["ai.credential.", "enforce."]);
    assert_eq!(rule.min_severity, Some(Severity::High));
    assert!(rule.matches(&AdapterMessage::event("ai.credential.leak", Severity::High, "t", "s", json!({}))));
    assert!(!rule.matches(&AdapterMessage::event("ai.credential.leak", Severity::Low, "t", "s", json!({}))));
}

#[tokio::test]
pub(crate) async fn invalid_rule_settings_reject_whole_config() {
    let mut registry = registry_mock();
    for settings in [
        vec![("event_prefixes", json!("not-an-array"))],
        vec![("event_prefixes", json!([]))],
        vec![("event_prefixes", json!([""]))],
        vec![("min_severity", json!("urgent"))],
    ] {
        let config = config_for("slack", &settings, true);
        assert!(registry.apply_config(&config).await.is_err(), "{settings:?} 应被拒绝");
    }
    assert_eq!(
        registry.rule("slack").map(|r| r.event_prefixes.clone()),
        Some(vec!["*".to_string()]),
        "失败不得改动规则"
    );
}

#[tokio::test]
pub(crate) async fn broadcast_isolates_failures() {
    // 刻意不用 mock_only：需要"一个适配器失败、另一个成功"的真实隔离验证
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(503).set_body_string("feishu down"))
        .expect(3)
        .mount(&server)
        .await;
    let hook = format!("{}/open-apis/bot/v2/hook/local", server.uri());

    let mut registry = AdapterRegistry::new(TenantId::default_tenant(), false);
    registry.register::<crate::vendors::feishu::Feishu>().expect("注册 feishu");
    registry.register::<crate::vendors::slack::Slack>().expect("注册 slack");
    registry =
        registry.with_secrets(Arc::new(secrets(&[("feishu:webhook_url", &hook), ("slack:webhook_url", SLACK_HOOK)])));
    // feishu：配置齐全 → Live（真实发包，上游 503 ⇒ 按 retry 重试 3 次后如实失败）
    registry
        .apply_config(&config_for("feishu", &[("allow_custom_host", json!(true))], false))
        .await
        .expect("feishu 配置");
    // slack：显式 Mock → 下发成功
    registry.apply_config(&config_for("slack", &[], true)).await.expect("slack 配置");

    let outcomes = registry.broadcast(&message(Severity::Critical)).await;
    assert_eq!(outcomes.len(), 2, "feishu 与 slack 都应命中");
    let feishu = outcomes.iter().find(|o| o.adapter == "feishu").expect("feishu 必须命中");
    assert!(!feishu.is_ok());
    assert!(feishu.error_text().unwrap_or_default().contains("503"));
    let slack = outcomes.iter().find(|o| o.adapter == "slack").expect("slack 必须命中");
    assert!(slack.is_ok(), "单个适配器失败不得影响其它适配器");
    assert!(slack.result.as_ref().is_ok_and(|r| r.mocked));
    server.verify().await;
}

#[tokio::test]
pub(crate) async fn health_all_covers_every_registered_adapter() {
    let registry = registry_mock();
    let records = registry.health_all().await;
    assert_eq!(records.len(), crate::vendors::BUILTIN_NAMES.len());
    for record in &records {
        assert!(record.mocked);
        assert_eq!(record.mode, AdapterMode::Mocked);
        assert!(record.message.clone().unwrap_or_default().contains("AGF_MOCK_MODE"));
    }
    assert_eq!(registry.health_map().await.len(), crate::vendors::BUILTIN_NAMES.len());
}

#[tokio::test]
pub(crate) async fn close_all_is_idempotent_and_blocks_send() {
    let registry = registry_mock();
    assert_eq!(registry.close_all().await, crate::vendors::BUILTIN_NAMES.len());
    assert_eq!(registry.close_all().await, crate::vendors::BUILTIN_NAMES.len(), "重复关闭必须幂等");
    let error = registry.send_to("feishu", &message(Severity::High)).await.expect_err("关闭后不得下发");
    assert!(matches!(error, DomainError::PreconditionFailed(_)));
}

#[tokio::test]
pub(crate) async fn init_all_reports_skipped_and_failed() {
    let mut registry = registry_mock();
    let configs = vec![config_for("feishu", &[], true), config_for("not-registered", &[], true), {
        let mut bad = config_for("slack", &[], true);
        bad.circuit_breaker.failure_threshold = 0;
        bad
    }];
    let report = registry.init_all(&configs).await.expect("批量初始化不应整体失败");
    assert_eq!(report.applied, 1);
    assert_eq!(report.skipped, 1);
    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.failed[0].adapter, "slack");
}

#[tokio::test]
pub(crate) async fn subscribe_validation() {
    let mut registry = registry_mock();
    assert!(matches!(
        registry.subscribe(SubscriptionRule { adapter: "feishu".into(), event_prefixes: vec![], min_severity: None }),
        Err(DomainError::Validation(_))
    ));
    assert!(matches!(registry.subscribe(SubscriptionRule::all("nope")), Err(DomainError::NotFound { .. })));
    registry.subscribe(SubscriptionRule::all("feishu").with_prefixes(&["notify."])).expect("规则应成功");
    assert_eq!(registry.rule("feishu").map(|r| r.event_prefixes.clone()), Some(vec!["notify.".to_string()]));
}

#[tokio::test]
pub(crate) async fn metadata_and_descriptor_are_available_for_console() {
    let registry = registry_mock();
    let handle = registry.handle("syslog-forwarder").expect("句柄存在");
    let guard = handle.lock().await;
    let metadata: AdapterMetadata = guard.metadata();
    assert_eq!(metadata.category, crate::contract::AdapterCategory::SecurityPlatform);
    assert!(metadata.requires_network);
    assert_eq!(guard.descriptor().name, "syslog-forwarder");
    assert_eq!(guard.mode(), AdapterMode::Mocked);
}
