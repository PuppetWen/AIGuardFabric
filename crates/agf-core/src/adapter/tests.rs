//! 由 `adapter.rs` 拆分：`circuit_opens_after_threshold_and_recovers` 等 11 个函数（纯搬移，逻辑不变）。

use crate::enums::HealthState;
use crate::error::DomainResult;
use crate::ids::{Id, TenantId};
use crate::time::Timestamp;
use std::collections::BTreeMap;

use super::*;

use crate::error::DomainError;

#[test]
pub(crate) fn circuit_opens_after_threshold_and_recovers() {
    let cfg = CircuitBreakerConfig { enabled: true, failure_threshold: 3, open_secs: 30, half_open_probes: 1 };
    let mut snap = CircuitSnapshot::default();
    let now = Timestamp::now();
    assert!(snap.allows_call(&cfg, now));
    snap.on_failure(&cfg, "e1", now);
    snap.on_failure(&cfg, "e2", now);
    assert_eq!(snap.state, CircuitState::Closed, "未达阈值仍闭合");
    snap.on_failure(&cfg, "e3", now);
    assert_eq!(snap.state, CircuitState::Open);
    assert!(!snap.allows_call(&cfg, now), "开路期间快速失败");
    assert_eq!(snap.health(), HealthState::CircuitOpen);

    let later = now.offset_secs(31);
    assert!(snap.allows_call(&cfg, later), "开路到期进入半开");
    assert_eq!(snap.state, CircuitState::HalfOpen);
    assert_eq!(snap.health(), HealthState::Degraded);
    assert!(!snap.allows_call(&cfg, later), "半开探测次数用尽");
    snap.on_success();
    assert_eq!(snap.state, CircuitState::Closed);
    assert_eq!(snap.consecutive_failures, 0);
}

#[test]
pub(crate) fn disabled_circuit_always_allows() {
    let cfg = CircuitBreakerConfig { enabled: false, ..CircuitBreakerConfig::default() };
    let mut snap = CircuitSnapshot::default();
    let now = Timestamp::now();
    for _ in 0..100 {
        snap.on_failure(&cfg, "e", now);
    }
    assert!(snap.allows_call(&cfg, now));
}

#[test]
pub(crate) fn retry_backoff_is_capped() {
    let r =
        RetryConfig { max_attempts: 6, initial_backoff_ms: 100, multiplier: 3.0, max_backoff_ms: 1_000, jitter: false };
    assert_eq!(r.backoff_ms(0), 100);
    assert_eq!(r.backoff_ms(1), 300);
    assert_eq!(r.backoff_ms(2), 900);
    assert_eq!(r.backoff_ms(3), 1_000, "必须被 max_backoff 截断");
    assert_eq!(r.backoff_ms(50), 1_000);
}

#[test]
pub(crate) fn health_reports_degrade_not_failure() {
    let u = AdapterHealth::unconfigured("alicloud-cms", "未配置 AK/SK");
    assert_eq!(u.state, HealthState::Unconfigured);
    assert!(!u.configured);
    assert!(!u.mocked);
    let m = AdapterHealth::mocked("alicloud-cms");
    assert!(m.mocked);
    assert_eq!(m.state, HealthState::Degraded);
    assert!(m.message.unwrap_or_default().contains("AGF_MOCK_MODE"));
}

#[test]
pub(crate) fn sync_direction_helpers() {
    assert!(SyncDirection::Both.includes_pull());
    assert!(SyncDirection::Both.includes_push());
    assert!(!SyncDirection::Pull.includes_push());
    assert_eq!(SyncDirection::Push.as_str(), "push");
}

#[test]
pub(crate) fn adapter_config_setting_helpers() {
    let now = Timestamp::now();
    let mut settings = BTreeMap::new();
    settings.insert("region".to_string(), serde_json::Value::from("cn-hangzhou"));
    settings.insert("tls".to_string(), serde_json::Value::from(true));
    let mut secret_refs = BTreeMap::new();
    secret_refs.insert("access_key_id".to_string(), Id::new());
    let cfg = AdapterConfig {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        adapter: "alicloud-cms".into(),
        display_name: "阿里云云监控".into(),
        enabled: true,
        settings,
        secret_refs,
        circuit_breaker: CircuitBreakerConfig::default(),
        retry: RetryConfig::default(),
        timeout_secs: 30,
        mock: false,
        is_default: true,
        created_at: now,
        updated_at: now,
    };
    assert_eq!(cfg.get_str("region"), Some("cn-hangzhou"));
    assert!(cfg.get_bool("tls", false));
    assert!(!cfg.get_bool("missing", false));
    assert!(cfg.has_secrets(&["access_key_id"]));
    assert!(!cfg.has_secrets(&["access_key_id", "access_key_secret"]));
}

#[test]
pub(crate) fn adapter_capability_and_descriptor() {
    let d = AdapterDescriptor {
        name: "alicloud-cms".into(),
        display_name: "阿里云云监控".into(),
        category: "alicloud".into(),
        required_secrets: vec!["access_key_id".into(), "access_key_secret".into()],
        optional_secrets: vec!["sts_token".into()],
        capabilities: vec![AdapterCapability::PushMetrics, AdapterCapability::SelfCheck],
        degradation: "未配置时不上报指标，事件订阅回退到本地轮询；平台主流程不受影响".into(),
        mock_location: "crates/agf-alicloud/src/cms.rs#MockCmsAdapter".into(),
        real_implementation: true,
        doc_anchor: "docs/adapter-spec.md#alicloud-cms".into(),
    };
    assert_eq!(d.capabilities.len(), 2);
    assert!(!d.degradation.is_empty(), "必须写明降级行为");
    assert!(!d.mock_location.is_empty(), "必须写明 Mock 实现位置");
    assert_eq!(AdapterCapability::ProbePrivateLink.as_str(), "probe-private-link");
}

#[test]
pub(crate) fn sync_outcome_helpers() {
    let m = SyncOutcome::mock(12, 0);
    assert!(m.mocked);
    assert!(!m.has_failures());
    assert!(m.finished_at.is_some());
    let f = SyncOutcome { failed: 1, ..SyncOutcome::default() };
    assert!(f.has_failures());
}

#[tokio::test]
pub(crate) async fn invoke_with_policy_retries_then_succeeds() {
    let cfg = CircuitBreakerConfig::default();
    let retry =
        RetryConfig { max_attempts: 3, initial_backoff_ms: 1, multiplier: 1.0, max_backoff_ms: 2, jitter: false };
    let mut snap = CircuitSnapshot::default();
    let mut calls = 0_u32;
    let res = invoke_with_policy("test", &mut snap, &cfg, &retry, Timestamp::now(), |_attempt| {
        calls += 1;
        let current = calls;
        async move { if current < 3 { Err(DomainError::Timeout("模拟超时".into())) } else { Ok(current) } }
    })
    .await;
    assert_eq!(res.ok(), Some(3));
    assert_eq!(snap.consecutive_failures, 0);
    assert_eq!(snap.total_success, 1);
}

#[tokio::test]
pub(crate) async fn invoke_with_policy_fails_and_opens_circuit() {
    let cfg = CircuitBreakerConfig { enabled: true, failure_threshold: 1, open_secs: 30, half_open_probes: 1 };
    let retry =
        RetryConfig { max_attempts: 2, initial_backoff_ms: 1, multiplier: 1.0, max_backoff_ms: 1, jitter: false };
    let mut snap = CircuitSnapshot::default();
    let now = Timestamp::now();
    let res: DomainResult<()> = invoke_with_policy("test", &mut snap, &cfg, &retry, now, |_a| async {
        Err(DomainError::DependencyUnavailable { dependency: "test".into(), cause: "down".into() })
    })
    .await;
    assert!(res.is_err());
    assert_eq!(snap.state, CircuitState::Open);
    // 开路后立刻再调，应快速失败且不再执行 op
    let mut executed = false;
    let res2: DomainResult<()> = invoke_with_policy("test", &mut snap, &cfg, &retry, now, |_a| {
        executed = true;
        async { Ok(()) }
    })
    .await;
    assert!(res2.is_err());
    assert!(!executed, "开路期间不应真正调用外部系统");
}

#[tokio::test]
pub(crate) async fn invoke_with_policy_does_not_retry_non_retryable() {
    let cfg = CircuitBreakerConfig::default();
    let retry =
        RetryConfig { max_attempts: 5, initial_backoff_ms: 1, multiplier: 1.0, max_backoff_ms: 1, jitter: false };
    let mut snap = CircuitSnapshot::default();
    let mut calls = 0_u32;
    let res: DomainResult<()> = invoke_with_policy("test", &mut snap, &cfg, &retry, Timestamp::now(), |_a| {
        calls += 1;
        async { Err(DomainError::Validation("参数错".into())) }
    })
    .await;
    assert!(res.is_err());
    assert_eq!(calls, 1, "校验错误不应重试");
}
