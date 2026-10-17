//! 由 `guard.rs` 拆分：`quick_report_helper_works` 等 5 个函数（纯搬移，逻辑不变）。
use super::*;
use crate::policy::structured_policy;
use agf_core::ids::TenantId;
use agf_core::policy::PolicyLanguage;
use agf_core::policy::StructuredCondition;

#[test]
pub(crate) fn quick_report_helper_works() {
    let engine = full_engine();
    let bl = Blocklist::with_defaults();
    let log = audit();
    let cfg = config_all_points();
    let report = quick_report(&engine, &bl, &log, &cfg);
    assert!(report.policy_count > 0);
    assert!(report.item(keys::POLICY_SIGNATURE_MODE).is_some());
    assert!(serde_json::to_string(&report).is_ok(), "报告必须可序列化给前端");
}

#[test]
pub(crate) fn guard_item_constructors() {
    let p = GuardItem::pass("k", "标签", "ok");
    assert!(p.passed && !p.critical);
    let f = GuardItem::fail("k", "标签", "bad");
    assert!(!f.passed && f.critical);
    let w = GuardItem::warn("k", "标签", "meh");
    assert!(!w.passed && !w.critical);
    assert_eq!(f.key, "k");
    assert_eq!(f.label, "标签");
}

#[test]
pub(crate) fn report_helpers() {
    let items = vec![GuardItem::pass("a", "A", "x"), GuardItem::fail("b", "B", "y"), GuardItem::warn("c", "C", "z")];
    let report = GuardReport::build(items, Vec::new(), 3, 40, 10);
    assert!(!report.healthy);
    assert_eq!(report.passed, 1);
    assert_eq!(report.failed, 2);
    assert_eq!(report.critical_failures, 1);
    assert_eq!(report.failures().len(), 2);
    assert_eq!(report.item("a").map(|i| i.passed), Some(true));
    assert_eq!(report.item("zzz"), None);
    assert!(report.summary().contains("1/3 通过"));
}

#[test]
pub(crate) fn language_coverage_for_policy_languages() {
    // 自检不区分策略语言：Rego/CEL 策略与结构化策略同等对待
    let mut p =
        structured_policy(TenantId::default_tenant(), "rego", StructuredCondition::default(), PolicyAction::Deny, 1);
    p.language = PolicyLanguage::Rego;
    p.source = "package agf\naction := \"deny\" if { true }".into();
    p.intercept_points = vec![InterceptPoint::McpProxy, InterceptPoint::AiGateway, InterceptPoint::ProcessHook];
    let engine = PolicyEngine::new().with_signature_mode(SignatureMode::Disabled).from_policies(vec![p]);
    assert!(engine.is_ok(), "{engine:?}");
    let Some(engine) = engine.ok() else { return };
    let bl = Blocklist::with_defaults();
    let log = audit();
    let cfg = config_all_points();
    let report = SelfCheck::new(&engine, &bl, &log, &cfg, TenantId::default_tenant()).run();
    assert!(report.item(keys::POLICY_ALL_DRY_RUN).is_some_and(|i| i.passed));
    assert!(report.item(keys::POLICY_HAS_BLOCKING).is_some_and(|i| i.passed));
}

#[test]
pub(crate) fn keys_are_stable_contract_strings() {
    assert_eq!(keys::POLICY_SIGNATURE, "policy.signature");
    assert_eq!(keys::POLICY_UNSIGNED, "policy.unsigned");
    assert_eq!(keys::INTERCEPT_POINTS, "intercept.points");
    assert_eq!(keys::BLOCKLIST_NON_EMPTY, "blocklist.non-empty");
    assert_eq!(keys::AUDIT_CHAIN, "audit.chain");
    assert_eq!(keys::HEARTBEAT, "guard.heartbeat");
}
