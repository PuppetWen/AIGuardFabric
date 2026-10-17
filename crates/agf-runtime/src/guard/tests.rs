//! 由 `guard.rs` 拆分：`audit` 等 22 个函数（纯搬移，逻辑不变）。
use super::*;
use crate::policy::structured_policy;
use agf_core::ids::TenantId;
use agf_core::policy::StructuredCondition;
use agf_core::time::Timestamp;

pub(crate) fn audit() -> InterceptionAuditLog {
    InterceptionAuditLog::new()
}

pub(crate) fn config_all_points() -> EngineConfig {
    EngineConfig::default()
}

/// 生产形态的引擎：签名 **Enforce** + 已轮换（非 dev）密钥 + 策略已签名。
///
/// 自检的"健康报告"用例必须基于生产形态的引擎——否则 `policy.signature-mode`
/// 与 `policy.signature` 两项必然 FAIL（那正是自检要抓的问题，而不是测试的基线）。
pub(crate) fn full_engine() -> PolicyEngine {
    use crate::signature::PolicySigner;
    let signer = PolicySigner::new(b"agf-test-signer-key-0123456789abcd".to_vec(), "k1")
        .unwrap_or_else(|_| PolicySigner::dev_default());
    let mut p = structured_policy(
        TenantId::default_tenant(),
        "block-all",
        StructuredCondition { tool_denylist: vec!["shell".into()], ..Default::default() },
        PolicyAction::Deny,
        1,
    );
    p.intercept_points = vec![InterceptPoint::McpProxy, InterceptPoint::AiGateway, InterceptPoint::ProcessHook];
    p.signature = signer.sign(&p);
    let mut default_allow_audit = structured_policy(
        TenantId::default_tenant(),
        "audit-log",
        StructuredCondition { command_deny: vec!["whoami".into()], ..Default::default() },
        PolicyAction::Audit,
        5,
    );
    default_allow_audit.intercept_points = p.intercept_points.clone();
    default_allow_audit.signature = signer.sign(&default_allow_audit);
    let engine = PolicyEngine::new()
        .with_signer(signer)
        .with_signature_mode(SignatureMode::Enforce)
        .from_policies(vec![p, default_allow_audit]);
    assert!(engine.is_ok());
    engine.unwrap_or_default()
}

// ---------- 心跳 ----------

#[test]
pub(crate) fn heartbeat_alert_after_three_misses() {
    let monitor = HeartbeatMonitor::new();
    monitor.register(ManagedEndpoint::new("agent:fs-01", "agent", 30));
    assert!(monitor.is_alive("agent:fs-01"));
    assert!(monitor.alerts().is_empty());
    let base = Timestamp::now();
    // 第 1、2 次丢失：不告警
    for i in 1..=2 {
        let now = base.offset_secs(30 * i);
        assert_eq!(monitor.tick(now).len(), 0, "第 {i} 次丢失不应告警");
        assert!(monitor.is_alive("agent:fs-01"));
    }
    assert_eq!(monitor.state("agent:fs-01").map(|s| s.missed), Some(2));
    // 第 3 次丢失：告警
    let alerts = monitor.tick(base.offset_secs(90));
    assert_eq!(alerts.len(), 1, "N=3 时应告警");
    let alert = &alerts[0];
    assert_eq!(alert.endpoint_id, "agent:fs-01");
    assert_eq!(alert.missed, 3);
    assert!(alert.silence_secs >= 90);
    assert!(alert.suggestion.contains("心跳丢失"));
    assert!(!monitor.is_alive("agent:fs-01"));
    assert_eq!(monitor.alerts().len(), 1);
    // 不重复告警
    assert_eq!(monitor.tick(base.offset_secs(120)).len(), 0);
    assert_eq!(monitor.alerts().len(), 1);
}

#[test]
pub(crate) fn heartbeat_recovers_after_beat() {
    let monitor = HeartbeatMonitor::new();
    monitor.register(ManagedEndpoint::new("proxy:mcp-1", "proxy", 10));
    let base = Timestamp::now();
    for i in 1..=3 {
        let _ = monitor.tick(base.offset_secs(10 * i));
    }
    assert!(!monitor.is_alive("proxy:mcp-1"));
    assert!(monitor.record_beat_at("proxy:mcp-1", base.offset_secs(31)));
    assert!(monitor.is_alive("proxy:mcp-1"));
    assert!(monitor.alerts().is_empty(), "恢复后告警应清除");
    assert_eq!(monitor.state("proxy:mcp-1").map(|s| s.missed), Some(0));
}

#[test]
pub(crate) fn heartbeat_ignores_unknown_endpoint() {
    let monitor = HeartbeatMonitor::new();
    assert!(!monitor.record_beat("nobody"));
    assert!(!monitor.is_alive("nobody"));
    assert_eq!(monitor.state("nobody"), None);
    assert!(monitor.is_empty());
}

#[test]
pub(crate) fn heartbeat_custom_threshold_and_interval() {
    let monitor = HeartbeatMonitor::new();
    monitor.register(ManagedEndpoint::new("agent:a", "agent", 60).with_alert_after(1));
    let base = Timestamp::now();
    // 未到间隔：不计数
    assert_eq!(monitor.tick(base.offset_secs(59)).len(), 0);
    // 到间隔：阈值 1 ⇒ 立即告警
    assert_eq!(monitor.tick(base.offset_secs(60)).len(), 1);
}

#[test]
pub(crate) fn heartbeat_multiple_endpoints_sorted_and_counted() {
    let monitor = HeartbeatMonitor::new();
    monitor.register(ManagedEndpoint::new("agent:b", "agent", 10));
    monitor.register(ManagedEndpoint::new("agent:a", "agent", 10));
    monitor.register(ManagedEndpoint::new("proxy:c", "proxy", 10));
    assert_eq!(monitor.len(), 3);
    assert_eq!(monitor.alive_count(), 3);
    let base = Timestamp::now();
    for i in 1..=3 {
        let _ = monitor.tick(base.offset_secs(10 * i));
    }
    let alerts = monitor.alerts();
    assert_eq!(alerts.len(), 3);
    assert_eq!(alerts[0].endpoint_id, "agent:a", "告警应按 id 稳定排序");
    assert_eq!(monitor.alive_count(), 0);
    assert_eq!(monitor.states().len(), 3);
}

#[test]
pub(crate) fn heartbeat_endpoint_helpers() {
    let ep = ManagedEndpoint::new("agent:x", "agent", 30);
    assert_eq!(ep.alert_after, 3);
    assert_eq!(endpoint_id("agent", "fs"), "agent:fs");
    assert!(endpoint_id_of("agent", Id::nil()).starts_with("agent:"));
    assert!(intercept_point_label(InterceptPoint::McpProxy).contains("MCP"));
    assert!(intercept_point_label(InterceptPoint::ProcessHook).contains("Hook"));
}

// ---------- 自检 ----------

#[test]
pub(crate) fn healthy_report_passes_all_items() {
    let engine = full_engine();
    let bl = Blocklist::with_defaults();
    let log = audit();
    let cfg = config_all_points();
    let monitor = HeartbeatMonitor::new();
    monitor.register(ManagedEndpoint::new("proxy:mcp-1", "proxy", 30));
    let report = SelfCheck::new(&engine, &bl, &log, &cfg, TenantId::default_tenant()).with_heartbeats(&monitor).run();
    assert!(report.healthy, "未通过项: {:?}", report.failures());
    assert_eq!(report.failed, 0);
    assert_eq!(report.critical_failures, 0);
    assert_eq!(report.policy_count, 2);
    assert_eq!(report.blocklist_rule_count, bl.len());
    assert_eq!(report.audit_entries, 0);
    assert!(report.summary().contains("运行时防护自检"));
    assert!(report.item(keys::BLOCKLIST_NON_EMPTY).is_some());
}

#[test]
pub(crate) fn empty_blocklist_fails_the_check() {
    let engine = full_engine();
    let bl = Blocklist::empty();
    let log = audit();
    let cfg = config_all_points();
    let report = SelfCheck::new(&engine, &bl, &log, &cfg, TenantId::default_tenant()).run();
    assert!(!report.healthy, "空黑名单必须判 FAIL");
    let item = report.item(keys::BLOCKLIST_NON_EMPTY);
    assert!(item.is_some_and(|i| !i.passed && i.critical));
    assert!(item.is_some_and(|i| i.reason.contains("最低防线")));
    assert_eq!(report.blocklist_rule_count, 0);
}

#[test]
pub(crate) fn unsigned_policy_fails_the_check() {
    // Warn 模式下装载未签名策略 ⇒ 自检必须 FAIL
    let mut p = structured_policy(
        TenantId::default_tenant(),
        "unsigned",
        StructuredCondition { tool_denylist: vec!["shell".into()], ..Default::default() },
        PolicyAction::Deny,
        1,
    );
    p.intercept_points = vec![InterceptPoint::McpProxy, InterceptPoint::AiGateway, InterceptPoint::ProcessHook];
    let engine = PolicyEngine::new()
        .with_signer(crate::signature::PolicySigner::dev_default())
        .with_signature_mode(SignatureMode::Warn)
        .from_policies(vec![p]);
    assert!(engine.is_ok());
    let Some(engine) = engine.ok() else { return };
    let bl = Blocklist::with_defaults();
    let log = audit();
    let cfg = config_all_points();
    let report = SelfCheck::new(&engine, &bl, &log, &cfg, TenantId::default_tenant()).run();
    assert!(!report.healthy);
    assert!(report.item(keys::POLICY_UNSIGNED).is_some_and(|i| !i.passed));
    assert!(report.item(keys::POLICY_SIGNATURE_MODE).is_some_and(|i| !i.passed));
    // 开发默认密钥也应 FAIL
    assert!(report.item(keys::POLICY_DEV_KEY).is_some_and(|i| !i.passed));
}

#[test]
pub(crate) fn signature_disabled_is_reported_as_failure() {
    // 本用例的主体就是"关掉签名校验会被自检抓到"，因此刻意构造 Disabled 引擎
    // （`full_engine()` 是生产形态的 Enforce 引擎，不能用来测这一项）
    let engine = PolicyEngine::new().with_signature_mode(SignatureMode::Disabled).from_policies(vec![]);
    assert!(engine.is_ok());
    let Some(engine) = engine.ok() else { return };
    let bl = Blocklist::with_defaults();
    let log = audit();
    let cfg = config_all_points();
    let report = SelfCheck::new(&engine, &bl, &log, &cfg, TenantId::default_tenant()).run();
    assert!(report.item(keys::POLICY_SIGNATURE_MODE).is_some_and(|i| !i.passed && i.critical));
    assert!(report.item(keys::POLICY_SIGNATURE).is_some_and(|i| !i.passed), "未配置签名密钥应 FAIL");
}

#[test]
pub(crate) fn missing_intercept_point_fails_the_check() {
    let mut p = structured_policy(
        TenantId::default_tenant(),
        "only-mcp",
        StructuredCondition { tool_denylist: vec!["shell".into()], ..Default::default() },
        PolicyAction::Deny,
        1,
    );
    p.intercept_points = vec![InterceptPoint::McpProxy];
    let engine = PolicyEngine::new().with_signature_mode(SignatureMode::Disabled).from_policies(vec![p]);
    assert!(engine.is_ok());
    let Some(engine) = engine.ok() else { return };
    let bl = Blocklist::with_defaults();
    let log = audit();
    let cfg = config_all_points();
    let report = SelfCheck::new(&engine, &bl, &log, &cfg, TenantId::default_tenant()).run();
    let item = report.item(keys::INTERCEPT_POINTS);
    assert!(item.is_some_and(|i| !i.passed && i.critical));
    assert!(item.is_some_and(|i| i.reason.contains("ai-gateway")), "{item:?}");
}

#[test]
pub(crate) fn all_dry_run_fails_the_check() {
    let mut p = structured_policy(
        TenantId::default_tenant(),
        "dry",
        StructuredCondition { tool_denylist: vec!["shell".into()], ..Default::default() },
        PolicyAction::Deny,
        1,
    );
    p.dry_run = true;
    p.intercept_points = vec![InterceptPoint::McpProxy, InterceptPoint::AiGateway, InterceptPoint::ProcessHook];
    let engine = PolicyEngine::new().with_signature_mode(SignatureMode::Disabled).from_policies(vec![p]);
    assert!(engine.is_ok());
    let Some(engine) = engine.ok() else { return };
    let bl = Blocklist::with_defaults();
    let log = audit();
    let cfg = config_all_points();
    let report = SelfCheck::new(&engine, &bl, &log, &cfg, TenantId::default_tenant()).run();
    assert!(report.item(keys::POLICY_ALL_DRY_RUN).is_some_and(|i| !i.passed && i.critical));
    assert!(report.item(keys::POLICY_HAS_BLOCKING).is_some_and(|i| !i.passed));
    assert!(!report.healthy);
}

#[test]
pub(crate) fn empty_policy_table_warns_but_does_not_fail() {
    let engine = PolicyEngine::new().with_signature_mode(SignatureMode::Disabled);
    let bl = Blocklist::with_defaults();
    let log = audit();
    let cfg = config_all_points();
    let report = SelfCheck::new(&engine, &bl, &log, &cfg, TenantId::default_tenant()).run();
    let item = report.item(keys::POLICY_ALL_DRY_RUN);
    assert!(item.is_some_and(|i| !i.passed && !i.critical), "空策略表是告警而非关键失败");
    assert!(report.item(keys::POLICY_HAS_BLOCKING).is_some_and(|i| !i.passed));
    // 拦截点未配置 ⇒ 关键失败
    assert!(report.item(keys::INTERCEPT_POINTS).is_some_and(|i| !i.passed && i.critical));
}

#[test]
pub(crate) fn tampered_audit_chain_fails_the_check() {
    let engine = full_engine();
    let bl = Blocklist::with_defaults();
    let log = audit();
    let r = crate::audit::InterceptionRecord::new(
        TenantId::default_tenant(),
        "s",
        InterceptPoint::McpProxy,
        crate::audit::InterceptionVerdict::Blocked,
        "原始原因",
    );
    assert!(log.append(r).is_ok());
    assert!(log.tamper_reason_for_test(0, "被篡改"));
    let cfg = config_all_points();
    let report = SelfCheck::new(&engine, &bl, &log, &cfg, TenantId::default_tenant()).run();
    let item = report.item(keys::AUDIT_CHAIN);
    assert!(item.is_some_and(|i| !i.passed && i.critical), "{item:?}");
    assert!(item.is_some_and(|i| i.reason.contains("疑似被篡改")));
    assert!(!report.healthy);
    assert_eq!(report.audit_entries, 1);
}

#[test]
pub(crate) fn truncated_audit_buffer_warns() {
    let engine = full_engine();
    let bl = Blocklist::with_defaults();
    let log = InterceptionAuditLog::with_capacity(1);
    for i in 0..3 {
        let r = crate::audit::InterceptionRecord::new(
            TenantId::default_tenant(),
            "s",
            InterceptPoint::McpProxy,
            crate::audit::InterceptionVerdict::Forwarded,
            &format!("r{i}"),
        );
        assert!(log.append(r).is_ok());
    }
    let cfg = config_all_points();
    let report = SelfCheck::new(&engine, &bl, &log, &cfg, TenantId::default_tenant()).run();
    let item = report.item(keys::AUDIT_COMPLETE);
    assert!(item.is_some_and(|i| !i.passed && !i.critical), "滚出是告警而非关键失败");
    assert!(report.item(keys::AUDIT_CHAIN).is_some_and(|i| i.passed), "窗口内链仍自洽");
}

#[test]
pub(crate) fn heartbeat_alert_shows_up_in_report() {
    let engine = full_engine();
    let bl = Blocklist::with_defaults();
    let log = audit();
    let cfg = config_all_points();
    let monitor = HeartbeatMonitor::new();
    monitor.register(ManagedEndpoint::new("proxy:mcp-1", "proxy", 10));
    let base = Timestamp::now();
    for i in 1..=3 {
        let _ = monitor.tick(base.offset_secs(10 * i));
    }
    let report = SelfCheck::new(&engine, &bl, &log, &cfg, TenantId::default_tenant()).with_heartbeats(&monitor).run();
    assert!(report.item(keys::HEARTBEAT).is_some_and(|i| !i.passed && i.critical));
    assert_eq!(report.heartbeat_alerts.len(), 1);
    assert!(report.summary().contains("心跳告警 1 个"));
    assert!(!report.healthy);
}

#[test]
pub(crate) fn no_enrolled_endpoint_warns() {
    let engine = full_engine();
    let bl = Blocklist::with_defaults();
    let log = audit();
    let cfg = config_all_points();
    let monitor = HeartbeatMonitor::new();
    let report = SelfCheck::new(&engine, &bl, &log, &cfg, TenantId::default_tenant()).with_heartbeats(&monitor).run();
    assert!(report.item(keys::HEARTBEAT_ENROLLED).is_some_and(|i| !i.passed && !i.critical));
    assert!(report.item(keys::HEARTBEAT).is_some_and(|i| i.passed));
}

#[test]
pub(crate) fn quota_and_approval_checks() {
    let engine = full_engine();
    let bl = Blocklist::with_defaults();
    let log = audit();
    let cfg = config_all_points();
    let quotas = QuotaService::in_memory(vec![agf_core::quota::Quota::tenant_default(
        TenantId::default_tenant(),
        agf_core::enums::QuotaDimension::Requests,
        100,
    )]);
    let approvals = crate::approval::InMemoryApprovalStore::new();
    let report = SelfCheck::new(&engine, &bl, &log, &cfg, TenantId::default_tenant())
        .with_quotas(&quotas)
        .with_approvals(&approvals)
        .run();
    assert!(report.item(keys::QUOTA_DEGRADED).is_some_and(|i| i.passed));
    assert!(report.item(keys::APPROVAL_AVAILABLE).is_some_and(|i| i.passed));
    assert!(report.healthy, "未通过: {:?}", report.failures());
}

#[test]
pub(crate) fn eval_error_mode_is_reported() {
    let mut p = structured_policy(
        TenantId::default_tenant(),
        "x",
        StructuredCondition { tool_denylist: vec!["shell".into()], ..Default::default() },
        PolicyAction::Deny,
        1,
    );
    p.intercept_points = vec![InterceptPoint::McpProxy, InterceptPoint::AiGateway, InterceptPoint::ProcessHook];
    let engine = PolicyEngine::new()
        .with_signature_mode(SignatureMode::Disabled)
        .with_eval_error_mode(crate::policy::EvalErrorMode::FailOpen)
        .from_policies(vec![p]);
    assert!(engine.is_ok());
    let Some(engine) = engine.ok() else { return };
    let bl = Blocklist::with_defaults();
    let log = audit();
    let cfg = config_all_points();
    let report = SelfCheck::new(&engine, &bl, &log, &cfg, TenantId::default_tenant()).run();
    let item = report.item(keys::EVAL_ERROR_MODE);
    assert!(item.is_some_and(|i| !i.passed && !i.critical));
    assert!(item.is_some_and(|i| i.reason.contains("fail-open")));
}
