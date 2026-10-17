//! 由 `policy.rs` 拆分：`dry_run_policy_does_not_trigger_blocklist_veto` 等 18 个函数（纯搬移，逻辑不变）。
use super::*;
use agf_core::enums::{RiskDomain, Severity};
use pretty_assertions::assert_eq;

#[test]
pub(crate) fn dry_run_policy_does_not_trigger_blocklist_veto() {
    // dry-run 策略的"不拦截"是显式运营意图，黑名单不升级（但审计仍记录命中）
    let mut list = crate::blocklist::Blocklist::with_defaults();
    let hit = list.evaluate_command("rm -rf /").ok().flatten();
    let mut allow_all = sp("dry-allow", StructuredCondition::default(), PolicyAction::Allow, 1);
    allow_all.dry_run = true;
    let e = engine_with(vec![allow_all]);
    let d = e.evaluate(&ctx(), hit.as_ref());
    assert!(d.is_ok());
    assert_eq!(d.ok().map(|d| d.action), Some(PolicyAction::Allow));
}

#[test]
pub(crate) fn hit_source_fallback_deny_blocks_even_without_policies() {
    let mut list = crate::blocklist::Blocklist::with_defaults();
    let hit = list.evaluate_command("rm -rf /").ok().flatten();
    assert!(hit.is_some());
    let e = PolicyEngine::new().with_signature_mode(SignatureMode::Disabled).with_hit_source(HitSource::FallbackDeny);
    let d = e.evaluate(&ctx(), hit.as_ref());
    assert!(d.is_ok());
    let d = d.ok().unwrap_or_else(|| PolicyDecision::allow("x"));
    assert_eq!(d.action, PolicyAction::Deny);
    assert!(d.is_blocking());
    assert!(d.reason.contains("cmd.rm-rf-root"), "原因应含规则 id: {}", d.reason);
    assert!(d.policy_id.is_none());
}

#[test]
pub(crate) fn hit_source_annotate_appends_blocklist_reason() {
    let mut list = crate::blocklist::Blocklist::with_defaults();
    let hit = list.evaluate_command("rm -rf /").ok().flatten();
    let e = PolicyEngine::new()
        .with_signature_mode(SignatureMode::Disabled)
        .with_hit_source(HitSource::Annotate)
        .from_policies(vec![sp(
            "shell",
            StructuredCondition { tool_denylist: vec!["execute_shell".into()], ..Default::default() },
            PolicyAction::Audit,
            1,
        )]);
    assert!(e.is_ok());
    let Some(e) = e.ok() else { return };
    let d = e.evaluate(&ctx(), hit.as_ref());
    assert!(d.is_ok());
    let d = d.ok().unwrap_or_else(|| PolicyDecision::allow("x"));
    assert!(d.reason.contains("黑名单"), "原因应含黑名单注记: {}", d.reason);
    assert_eq!(d.action, PolicyAction::Deny, "Annotate 也保留否决权");
}

#[test]
pub(crate) fn hit_source_annotate_without_policy_hit_does_not_block() {
    let mut list = crate::blocklist::Blocklist::with_defaults();
    let hit = list.evaluate_command("rm -rf /").ok().flatten();
    let e = PolicyEngine::new().with_signature_mode(SignatureMode::Disabled).with_hit_source(HitSource::Annotate);
    let d = e.evaluate(&ctx(), hit.as_ref());
    assert!(d.is_ok());
    let d = d.ok().unwrap_or_else(|| PolicyDecision::allow("x"));
    assert_eq!(d.action, PolicyAction::Allow, "Annotate 不兜底拦截");
    assert!(d.reason.contains("cmd.rm-rf-root"), "{}", d.reason);
    assert!(d.dry_run);
}

#[test]
pub(crate) fn audit_hit_is_not_a_fallback_deny() {
    let mut list = crate::blocklist::Blocklist::with_defaults();
    let list_ok = list.add_rule(crate::blocklist::RuleRule {
        id: "audit.wioami".into(),
        kind: crate::blocklist::RuleKind::Command,
        pattern: "wioami".into(),
        action: crate::blocklist::RuleAction::Audit,
        reason: "记录".into(),
        domain: RiskDomain::ToolAbuse,
        severity: Severity::Info,
    });
    assert!(list_ok.is_ok());
    let hit = list.evaluate_command("wioami").ok().flatten();
    assert!(hit.is_some());
    let e = PolicyEngine::new().with_signature_mode(SignatureMode::Disabled).with_hit_source(HitSource::PolicyFirst);
    assert_eq!(e.evaluate(&ctx(), hit.as_ref()).map(|d| d.action), Ok(PolicyAction::Allow));
}

#[test]
pub(crate) fn blocklist_hit_json_is_injected_into_rego() {
    let mut list = crate::blocklist::Blocklist::with_defaults();
    let hit = list.evaluate_command("rm -rf /").ok().flatten();
    let e = engine_with(vec![rego(
        "rego-uses-hit",
        r#"package agf
action := "deny" if { input.hit != null }
reason := sprintf("黑名单 %v", [input.hit.rule_id]) if { input.hit != null }
"#,
        PolicyAction::Audit,
        10,
    )]);
    let d = e.evaluate(&ctx(), hit.as_ref());
    assert!(d.is_ok());
    let d = d.ok().unwrap_or_else(|| PolicyDecision::allow("x"));
    assert_eq!(d.action, PolicyAction::Deny);
    assert_eq!(d.reason, "黑名单 cmd.rm-rf-root");
}

// ---------- 签名模式 ----------

#[test]
pub(crate) fn signature_enforce_rejects_unsigned_policy() {
    let signer = PolicySigner::dev_default();
    let engine = PolicyEngine::new()
        .with_signer(signer)
        .with_signature_mode(SignatureMode::Enforce)
        .from_policies(vec![sp("unsigned", StructuredCondition::default(), PolicyAction::Deny, 1)]);
    assert!(engine.is_ok());
    let Some(engine) = engine.ok() else { return };
    assert!(engine.is_empty(), "Enforce 模式下未签名策略不得生效");
    assert_eq!(engine.rejected().len(), 1);
    assert!(engine.rejected()[0].1.contains("签名缺失"));
}

#[test]
pub(crate) fn signature_enforce_accepts_validly_signed_policy() {
    let signer = PolicySigner::dev_default();
    let mut p = sp(
        "signed",
        StructuredCondition { tool_denylist: vec!["execute_shell".into()], ..Default::default() },
        PolicyAction::Deny,
        1,
    );
    p.signature = signer.sign(&p);
    let engine =
        PolicyEngine::new().with_signer(signer).with_signature_mode(SignatureMode::Enforce).from_policies(vec![p]);
    assert!(engine.is_ok());
    let Some(engine) = engine.ok() else { return };
    assert_eq!(engine.len(), 1);
    assert!(engine.rejected().is_empty());
    assert_eq!(engine.evaluate(&ctx(), None).map(|d| d.action), Ok(PolicyAction::Deny));
}

#[test]
pub(crate) fn signature_warn_accepts_unsigned_but_records_warning() {
    let mut p = sp(
        "unsigned-warn",
        StructuredCondition { tool_denylist: vec!["execute_shell".into()], ..Default::default() },
        PolicyAction::Deny,
        1,
    );
    p.signature = String::new();
    let engine = PolicyEngine::new()
        .with_signer(PolicySigner::dev_default())
        .with_signature_mode(SignatureMode::Warn)
        .from_policies(vec![p]);
    assert!(engine.is_ok());
    let Some(engine) = engine.ok() else { return };
    assert_eq!(engine.len(), 1, "Warn 模式应装载");
    assert_eq!(engine.signature_warnings().len(), 1);
    assert!(engine.signature_warnings()[0].contains("签名缺失"));
    assert_eq!(engine.evaluate(&ctx(), None).map(|d| d.action), Ok(PolicyAction::Deny));
}

#[test]
pub(crate) fn signature_warn_reports_invalid_signature() {
    let signer = PolicySigner::dev_default();
    let mut p = sp("tampered", StructuredCondition::default(), PolicyAction::Deny, 1);
    p.signature = signer.sign(&p);
    p.priority = 999; // 篡改
    let engine =
        PolicyEngine::new().with_signer(signer).with_signature_mode(SignatureMode::Warn).from_policies(vec![p]);
    assert!(engine.is_ok());
    let Some(engine) = engine.ok() else { return };
    assert_eq!(engine.len(), 1);
    assert!(engine.signature_warnings()[0].contains("签名非法"));
}

#[test]
pub(crate) fn signature_enforce_without_signer_rejects_everything() {
    let engine = PolicyEngine::new().with_signature_mode(SignatureMode::Enforce).from_policies(vec![sp(
        "x",
        StructuredCondition::default(),
        PolicyAction::Deny,
        1,
    )]);
    assert!(engine.is_ok());
    let Some(engine) = engine.ok() else { return };
    assert!(engine.is_empty());
    assert!(engine.rejected()[0].1.contains("未配置策略签名密钥"));
}

#[test]
pub(crate) fn signature_disabled_skips_verification() {
    let engine = engine_with(vec![sp("x", StructuredCondition::default(), PolicyAction::Deny, 1)]);
    assert_eq!(engine.len(), 1);
    assert_eq!(engine.signature_mode(), SignatureMode::Disabled);
    assert!(engine.signature_state(&engine.policies()[0]).is_none());
}

#[test]
pub(crate) fn signature_modes_have_stable_labels() {
    assert_eq!(SignatureMode::Enforce.as_str(), "enforce");
    assert!(SignatureMode::Enforce.is_enforcing());
    assert!(!SignatureMode::Warn.is_enforcing());
    assert_eq!(SignatureMode::default(), SignatureMode::Enforce, "生产默认必须是 Enforce");
    assert_eq!(EvalErrorMode::default(), EvalErrorMode::FailClosed);
    assert_eq!(EvalErrorMode::FailClosed.as_str(), "fail-closed");
    assert_eq!(HitSource::default(), HitSource::PolicyFirst);
    assert_eq!(HitSource::Off.as_str(), "off");
    assert!(HitSource::Off.is_unsafe());
    assert!(!HitSource::PolicyFirst.is_unsafe());
}

// ---------- 热重载 ----------

#[test]
pub(crate) fn replace_swaps_policy_set_atomically() {
    let mut e = engine_with(vec![sp(
        "old",
        StructuredCondition { tool_denylist: vec!["execute_shell".into()], ..Default::default() },
        PolicyAction::Deny,
        1,
    )]);
    assert_eq!(e.evaluate(&ctx(), None).map(|d| d.action), Ok(PolicyAction::Deny));
    let ok = e.replace(vec![sp(
        "new",
        StructuredCondition { tool_denylist: vec!["read_file".into()], ..Default::default() },
        PolicyAction::Deny,
        1,
    )]);
    assert!(ok.is_ok());
    assert_eq!(e.len(), 1);
    assert_eq!(e.policies()[0].name, "new");
    assert_eq!(e.evaluate(&ctx(), None).map(|d| d.action), Ok(PolicyAction::Allow));
}

#[test]
pub(crate) fn failed_replace_keeps_previous_policy_set() {
    let mut e = engine_with(vec![sp(
        "keep",
        StructuredCondition { tool_denylist: vec!["execute_shell".into()], ..Default::default() },
        PolicyAction::Deny,
        1,
    )]);
    let mut broken = sp("broken", StructuredCondition::default(), PolicyAction::Deny, 1);
    broken.language = PolicyLanguage::Rego;
    broken.source = "package agf\naction := }".into();
    let bad = e.replace(vec![broken]);
    assert!(bad.is_err());
    assert_eq!(e.len(), 1, "热重载失败必须保留原策略集");
    assert_eq!(e.policies()[0].name, "keep");
    assert_eq!(e.evaluate(&ctx(), None).map(|d| d.action), Ok(PolicyAction::Deny));
}

#[test]
pub(crate) fn load_appends_to_existing() {
    let mut e = engine_with(vec![sp("a", StructuredCondition::default(), PolicyAction::Audit, 1)]);
    let ok = e.load(vec![sp("b", StructuredCondition::default(), PolicyAction::Audit, 2)]);
    assert!(ok.is_ok());
    assert_eq!(e.len(), 2);
}

#[test]
pub(crate) fn evaluate_detailed_reports_match_metadata() {
    let mut list = crate::blocklist::Blocklist::with_defaults();
    let hit = list.evaluate_command("rm -rf /").ok().flatten();
    let e = engine_with(vec![sp(
        "p",
        StructuredCondition { tool_denylist: vec!["execute_shell".into()], ..Default::default() },
        PolicyAction::Deny,
        1,
    )]);
    let out = e.evaluate_detailed(&ctx(), hit.as_ref());
    assert!(out.is_ok());
    let Some((decision, detail)) = out.ok() else { return };
    assert_eq!(decision.action, PolicyAction::Deny);
    assert_eq!(detail.policy_name.as_deref(), Some("p"));
    assert!(detail.blocklist_hit);
    assert_eq!(detail.evaluated, 1);
    assert_eq!(detail.backend_redact, decision.redact);
}

#[test]
pub(crate) fn structured_policy_helper_matches_engine_expectations() {
    let p =
        structured_policy(TenantId::default_tenant(), "helper", StructuredCondition::default(), PolicyAction::Audit, 7);
    assert_eq!(p.priority, 7);
    assert!(p.enabled);
    assert!(!p.dry_run);
    assert_eq!(p.language, PolicyLanguage::Structured);
    assert_eq!(p.action, PolicyAction::Audit);
}
