//! 由 `blocklist.rs` 拆分：`kind_and_action_roundtrip` 等 4 个函数（纯搬移，逻辑不变）。
use super::*;

#[test]
pub(crate) fn kind_and_action_roundtrip() {
    for k in RuleKind::all() {
        assert_eq!(RuleKind::parse(k.as_str()), Ok(k));
        assert!(!k.display_zh().is_empty());
    }
    assert!(RuleKind::parse("nope").is_err());
    assert_eq!(RuleAction::parse("block"), Ok(RuleAction::Deny));
    assert!(RuleAction::parse("isolate").is_err());
    assert!(RuleAction::Deny.is_blocking());
    assert!(!RuleAction::Audit.is_blocking());
    assert_eq!(RuleAction::Allow.as_str(), "allow");
}

#[test]
pub(crate) fn audit_action_rules_do_not_block() {
    let mut list = Blocklist::empty();
    assert!(
        list.add_rule(RuleRule {
            id: "audit.shell".into(),
            kind: RuleKind::Command,
            pattern: "whoami".into(),
            action: RuleAction::Audit,
            reason: "记录一次身份查询".into(),
            domain: RiskDomain::ToolAbuse,
            severity: Severity::Info,
        })
        .is_ok()
    );
    let hit = list.evaluate_command("whoami");
    assert!(hit.is_ok());
    let hit = hit.ok().flatten();
    assert!(hit.is_some());
    assert!(!hit.as_ref().is_some_and(RuleHit::is_blocking), "audit 规则不应拦截");
    assert_eq!(list.stats().hits.get("audit.shell"), Some(&1));
}

#[test]
pub(crate) fn empty_blocklist_has_no_hits() {
    let mut list = Blocklist::empty();
    assert!(list.is_empty());
    assert_eq!(list.len(), 0);
    assert!(list.evaluate_command("rm -rf /").ok().flatten().is_none());
    assert!(list.stats().is_empty());
}

#[test]
pub(crate) fn serde_roundtrip_of_rules_and_stats() {
    let rules = default_rules();
    let json = serde_json::to_string(&rules);
    assert!(json.is_ok());
    let Some(json) = json.ok() else { return };
    let back: Result<Vec<RuleRule>, _> = serde_json::from_str(&json);
    assert!(back.is_ok());
    assert_eq!(back.ok().map(|r| r.len()), Some(rules.len()));
    let stats = Blocklist::with_defaults().stats().clone();
    assert!(serde_json::to_string(&stats).is_ok());
}
