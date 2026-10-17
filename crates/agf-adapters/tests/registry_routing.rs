#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! 集成测试：适配器注册表的端到端行为。
//!
//! 覆盖 acceptance 中的"注册表路由 / Mock 确定性 / 配置校验失败 / 健康状态流转 / 关闭幂等"，
//! 全部通过 crate 的**公开 API**（`AdapterRegistry` + `agf_core::adapter::Adapter`）驱动，
//! 不使用 crate 内部的 `test_support`。
//!
//! `Live` 路径不联外网：用 `wiremock` 起本地假服务器，凭据指向 `127.0.0.1` 随机端口
//! （飞书/Slack 需显式 `allow_custom_host=true`，见各厂商模块的"未配置时的降级行为"表）。

use std::collections::BTreeMap;
use std::sync::Arc;

use agf_adapters::{
    AdapterMessage, AdapterMode, AdapterRegistry, HealthStatus, MessageKind, StaticSecrets, SubscriptionRule,
};
use agf_core::adapter::{CircuitBreakerConfig, RetryConfig};
use agf_core::enums::Severity;
use agf_core::ids::{Id, TenantId};
use agf_core::time::Timestamp;
use serde_json::json;
use wiremock::matchers::{any, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const FEISHU_HOOK: &str = "https://open.feishu.cn/open-apis/bot/v2/hook/abcdef1234567890";
// Intentionally invalid Slack credential; configuration validation only needs the /services/ prefix.
const SLACK_HOOK: &str = "https://hooks.slack.com/services/test-only";
const GENERIC_HOOK: &str = "https://soar.example.invalid/hooks/agf?token=abcdef1234567890";

/// 本地假服务器上的三条 Webhook 路径（与各厂商的路径形态校验一致）。
const FEISHU_PATH: &str = "/open-apis/bot/v2/hook/token";
const SLACK_PATH: &str = "/services/T00000000/B00000000/token";
const GENERIC_PATH: &str = "/hooks/agf";

fn config(adapter: &str, mock: bool, extra: &[(&str, serde_json::Value)]) -> agf_core::adapter::AdapterConfig {
    let now = Timestamp::now();
    let mut settings: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for (k, v) in extra {
        settings.insert((*k).to_string(), v.clone());
    }
    agf_core::adapter::AdapterConfig {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        adapter: adapter.to_string(),
        display_name: adapter.to_string(),
        enabled: true,
        settings,
        secret_refs: BTreeMap::new(),
        circuit_breaker: CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 2,
            open_secs: 30,
            half_open_probes: 1,
        },
        retry: RetryConfig {
            max_attempts: 2,
            initial_backoff_ms: 1,
            multiplier: 1.0,
            max_backoff_ms: 1,
            jitter: false,
        },
        timeout_secs: 5,
        mock,
        is_default: true,
        created_at: now,
        updated_at: now,
    }
}

fn secrets() -> Arc<dyn agf_adapters::SecretLookup> {
    Arc::new(
        StaticSecrets::new()
            .with("feishu:webhook_url", FEISHU_HOOK)
            .with("slack:webhook_url", SLACK_HOOK)
            .with("webhook:webhook_url", GENERIC_HOOK),
    )
}

/// 指向本地假服务器的凭据（`Live` 路径用；不联外网）。
fn live_secrets(server: &MockServer) -> Arc<dyn agf_adapters::SecretLookup> {
    Arc::new(
        StaticSecrets::new()
            .with("feishu:webhook_url", &format!("{}{FEISHU_PATH}", server.uri()))
            .with("slack:webhook_url", &format!("{}{SLACK_PATH}", server.uri()))
            .with("webhook:webhook_url", &format!("{}{GENERIC_PATH}", server.uri())),
    )
}

fn alerts() -> AdapterMessage {
    AdapterMessage::event(
        "ai.credential.leak",
        Severity::Critical,
        "发现明文 API Key",
        "在 mcp.json 中发现 sk- 开头的明文密钥",
        serde_json::json!({"file": "/home/u/.cursor/mcp.json"}),
    )
    .with_asset("cursor@host1")
    .with_label("team", "soc")
}

#[tokio::test]
async fn mock_registry_routes_and_returns_deterministic_receipts() {
    let registry = AdapterRegistry::mock_only(TenantId::default_tenant()).expect("内置注册");
    assert_eq!(registry.len(), 12);

    let routed = registry.route(&alerts()).await;
    for expected in ["feishu", "dingtalk", "wecom", "email", "webhook", "slack", "jira", "servicenow", "zentao"] {
        assert!(routed.contains(&expected.to_string()), "{expected} 应在路由结果中");
    }
    assert!(!routed.contains(&"edr-isolation".to_string()), "EDR 只订阅隔离类载荷");
    assert!(!routed.contains(&"iam-scim".to_string()), "IAM 只订阅身份停用载荷");

    let first = registry.broadcast(&alerts()).await;
    let second = registry.broadcast(&alerts()).await;
    assert_eq!(first.len(), second.len());
    for (a, b) in first.iter().zip(second.iter()) {
        assert!(a.is_ok(), "{} Mock 下发应成功", a.adapter);
        assert_eq!(a.adapter, b.adapter);
        assert_eq!(
            a.result.as_ref().ok().and_then(|r| r.remote_id.clone()),
            b.result.as_ref().ok().and_then(|r| r.remote_id.clone()),
            "{} Mock 回执必须确定性",
            a.adapter
        );
    }
}

#[tokio::test]
async fn subscription_rules_gate_routing() {
    let mut registry = AdapterRegistry::mock_only(TenantId::default_tenant()).expect("内置注册");
    registry
        .subscribe(SubscriptionRule::all("feishu").with_prefixes(&["ai.credential."]).with_min_severity(Severity::High))
        .expect("规则设置");
    let high = alerts();
    assert!(registry.route(&high).await.contains(&"feishu".to_string()));
    let low = AdapterMessage::event("ai.credential.leak", Severity::Low, "低危", "s", serde_json::Value::Null);
    assert!(!registry.route(&low).await.contains(&"feishu".to_string()), "未达最低等级不得路由");
    let other = AdapterMessage::event("ai.model.changed", Severity::Critical, "模型变更", "s", serde_json::Value::Null);
    assert!(!registry.route(&other).await.contains(&"feishu".to_string()), "前缀不匹配不得路由");
}

#[tokio::test]
async fn live_mode_performs_real_http_for_every_adapter() {
    let server = MockServer::start().await;
    // 三个厂商各自挂"业务成功"响应：飞书业务码、通用 Webhook 的 id、Slack 的纯文本 ok
    Mock::given(path(FEISHU_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"code": 0, "msg": "success"})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path(GENERIC_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "srv-1"})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path(SLACK_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;

    let mut registry = AdapterRegistry::new(TenantId::default_tenant(), false).with_secrets(live_secrets(&server));
    registry.register::<agf_adapters::vendors::feishu::Feishu>().expect("注册 feishu");
    registry.register::<agf_adapters::vendors::webhook::Webhook>().expect("注册 webhook");
    registry.register::<agf_adapters::vendors::slack::Slack>().expect("注册 slack");
    let report = registry
        .init_all(&[
            config("feishu", false, &[("allow_custom_host", json!(true))]),
            config("webhook", false, &[]),
            config("slack", false, &[("allow_custom_host", json!(true))]),
            config("not-registered", false, &[]),
        ])
        .await
        .expect("批量初始化不应整体失败");
    assert_eq!(report.applied, 3);
    assert_eq!(report.skipped, 1);
    assert!(report.failed.is_empty(), "{:?}", report.failed);

    for (adapter, expected_path) in [("feishu", FEISHU_PATH), ("webhook", GENERIC_PATH), ("slack", SLACK_PATH)] {
        assert!(
            registry.core_descriptor(adapter).expect("描述符").real_implementation,
            "{adapter} 已实现真实传输，必须如实登记"
        );
        let receipt = registry.send_to(adapter, &alerts()).await.expect("真实 HTTP 下发应成功");
        assert!(receipt.accepted, "{adapter} 回执必须为已接受");
        assert!(!receipt.mocked, "{adapter} 不得返回 Mock 回执");
        let handle = registry.handle(adapter).expect("句柄");
        let mode = { handle.lock().await.mode() };
        assert_eq!(mode, AdapterMode::Live);
        let received = server.received_requests().await.expect("请求记录");
        assert!(
            received.iter().any(|r| r.url.path() == expected_path),
            "{adapter} 未按预期路径 {expected_path} 发出请求"
        );
    }
    server.verify().await;
}

#[tokio::test]
async fn live_encoding_targets_configured_vendor_endpoints() {
    // 纯编码断言（`encode` 不触网）：真实厂商 URL 下的编码产物必须指向配置的 endpoint
    let mut registry = AdapterRegistry::new(TenantId::default_tenant(), false).with_secrets(secrets());
    registry.register::<agf_adapters::vendors::feishu::Feishu>().expect("注册 feishu");
    registry.register::<agf_adapters::vendors::webhook::Webhook>().expect("注册 webhook");
    let report = registry
        .init_all(&[config("feishu", false, &[]), config("webhook", false, &[])])
        .await
        .expect("初始化不应整体失败");
    assert_eq!(report.applied, 2);
    assert!(report.failed.is_empty(), "{:?}", report.failed);

    for (adapter, expected_endpoint) in [("feishu", FEISHU_HOOK), ("webhook", GENERIC_HOOK)] {
        let handle = registry.handle(adapter).expect("句柄");
        let guard = handle.lock().await;
        assert_eq!(guard.mode(), AdapterMode::Live);
        let request = guard.encode(&alerts()).expect("编码应成功");
        assert_eq!(request.method, "POST");
        assert_eq!(request.endpoint, expected_endpoint, "{adapter} 编码必须指向配置的 endpoint");
        assert!(!request.body.is_null(), "{adapter} 请求体不得为空");
    }
}

#[tokio::test]
async fn invalid_config_keeps_previous_and_health_flow_is_reported() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream down"))
        .expect(2)
        .mount(&server)
        .await;

    let mut registry = AdapterRegistry::new(TenantId::default_tenant(), false).with_secrets(live_secrets(&server));
    registry.register::<agf_adapters::vendors::feishu::Feishu>().expect("注册 feishu");
    let live = config("feishu", false, &[("allow_custom_host", json!(true))]);
    registry.apply_config(&live).await.expect("合法配置");
    let mut broken = live.clone();
    broken.retry.max_attempts = 0;
    assert!(registry.apply_config(&broken).await.is_err(), "非法重试参数必须被拒绝");

    // 旧配置仍生效：仍处于 Live 且真实发出请求（上游 500 ⇒ 如实报错、按旧重试参数重试 2 次）
    let error = registry.send_to("feishu", &alerts()).await.expect_err("上游 500 必须如实报错");
    assert!(error.to_string().contains("500"), "{error}");

    let health = registry.health_map().await;
    let feishu = health.get("feishu").expect("健康记录");
    assert_eq!(feishu.status, HealthStatus::Degraded, "Live + 已实现真实传输 + 有失败 ⇒ 降级");
    assert_eq!(feishu.circuit.consecutive_failures, 1, "一次下发失败累计一次连续失败");
    assert_eq!(feishu.last_attempts, 2, "旧配置 retry.max_attempts=2 ⇒ 实际尝试 2 次（含重试）");
    assert!(feishu.last_error.clone().unwrap_or_default().contains("500"));
    assert_eq!(feishu.mode, AdapterMode::Live);
    server.verify().await;
}

#[tokio::test]
async fn mock_health_is_degraded_and_close_is_idempotent() {
    let registry = AdapterRegistry::mock_only(TenantId::default_tenant()).expect("内置注册");
    let records = registry.health_all().await;
    assert_eq!(records.len(), 12);
    for record in &records {
        assert_eq!(record.mode, AdapterMode::Mocked);
        assert_eq!(record.status, HealthStatus::Degraded);
        assert!(record.mocked);
        assert!(record.message.clone().unwrap_or_default().contains("AGF_MOCK_MODE"));
    }
    assert_eq!(registry.close_all().await, 12);
    assert_eq!(registry.close_all().await, 12, "重复关闭必须幂等");
    assert!(registry.send_to("feishu", &alerts()).await.is_err());
}

#[tokio::test]
async fn descriptors_and_core_contract_are_consumable_by_console() {
    let registry = AdapterRegistry::mock_only(TenantId::default_tenant()).expect("内置注册");
    let descriptors = registry.descriptors();
    assert_eq!(descriptors.len(), 12);
    for descriptor in &descriptors {
        assert!(!descriptor.degradation.is_empty());
        assert!(!descriptor.mock_location.is_empty());
        // 真实实现必须如实登记：12 个适配器均已落地真实传输（email 走真实 SMTP 投递）
        assert!(descriptor.real_implementation, "{} 的真实实现标记与实际不符（必须为 true）", descriptor.name);
        assert!(descriptor.doc_anchor.starts_with("docs/adapter-spec.md#"));
    }
    // `agf_core::adapter::Adapter` 契约面同样可用（控制台/运行时按统一契约消费）
    let health = registry.core_health("jira").await.expect("健康检查");
    assert_eq!(health.adapter, "jira");
    assert!(health.mocked);
    let descriptor = registry.core_descriptor("jira").expect("描述符");
    assert_eq!(descriptor.category, "itsm");
    let metadata = registry.metadata("jira").expect("元信息");
    assert_eq!(metadata.name, "jira");
    assert_eq!(metadata.version, env!("CARGO_PKG_VERSION"));
    assert!(metadata.requires_network);
    assert!(metadata.capabilities.contains(&agf_core::adapter::AdapterCapability::QueryLogs));
    assert!(registry.metadata("nope").is_none());
    assert!(registry.core_health("nope").await.is_err());
}

#[tokio::test]
async fn message_kind_and_labels_survive_routing() {
    let msg = AdapterMessage::notification("每日盘点", "3 台主机未上报心跳");
    assert_eq!(msg.kind, MessageKind::Notification);
    assert_eq!(msg.event_type, "notify.alert");
    let registry = AdapterRegistry::mock_only(TenantId::default_tenant()).expect("注册");
    let outcome = registry.send_to("wecom", &msg).await.expect("Mock 下发");
    assert!(outcome.mocked);
    assert!(outcome.remote_id.unwrap_or_default().starts_with("mock-"));
}
