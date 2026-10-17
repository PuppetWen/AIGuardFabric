//! 由 `rego.rs` 拆分：`ctx` 等 14 个函数（纯搬移，逻辑不变）。
use super::*;
use crate::testkit::sample_policy;
use agf_core::enums::{DataClass, InterceptPoint};
use agf_core::ids::{Id, TenantId};
use agf_core::policy::PolicyContext;
use agf_core::time::Timestamp;

pub(crate) fn ctx() -> PolicyContext {
    PolicyContext {
        tenant_id: TenantId::default_tenant(),
        session_id: "s-1".into(),
        agent_id: Some(Id::new()),
        department: Some("研发".into()),
        intercept_point: InterceptPoint::McpProxy,
        tool_name: Some("shell".into()),
        path: Some("/etc/shadow".into()),
        domain: Some("evil.example.com".into()),
        command: Some("rm -rf /".into()),
        payload: serde_json::json!({"name": "shell"}),
        payload_bytes: 12,
        risk_domains: vec![agf_core::enums::RiskDomain::ToolAbuse],
        max_severity: Some(agf_core::enums::Severity::High),
        data_class: DataClass::Confidential,
        now: Timestamp::now(),
    }
}

pub(crate) fn rego_policy(name: &str, source: &str) -> Policy {
    let mut p = sample_policy(name);
    p.language = agf_core::policy::PolicyLanguage::Rego;
    p.source = source.to_string();
    p
}

#[test]
pub(crate) fn action_reason_redact_contract() {
    let p = rego_policy(
        "rego-deny-rm",
        r#"
package agf

action := "deny" if { contains(input.command, "rm -rf") }
reason := sprintf("危险命令：%v", [input.command]) if { contains(input.command, "rm -rf") }
redact := true if { input.data_class == "confidential" }
"#,
    );
    let backend = RegoBackend::compile(&p);
    assert!(backend.is_ok(), "{backend:?}");
    let Some(backend) = backend.ok() else { return };
    assert!(backend.has_action_rule());
    assert!(backend.has_reason_rule());
    assert!(backend.has_redact_rule());
    let out = backend.evaluate(&ctx(), None);
    assert!(out.is_ok(), "{out:?}");
    let Some(out) = out.ok() else { return };
    assert!(out.hit);
    assert_eq!(out.action, Some(PolicyAction::Deny));
    assert_eq!(out.reason.as_deref(), Some("危险命令：rm -rf /"));
    assert!(out.redact);
}

#[test]
pub(crate) fn undefined_rules_mean_miss() {
    let p = rego_policy(
        "rego-noop",
        r#"
package agf

action := "deny" if { input.command == "something-else" }
"#,
    );
    let backend = RegoBackend::compile(&p);
    assert!(backend.is_ok());
    let Some(backend) = backend.ok() else { return };
    let out = backend.evaluate(&ctx(), None);
    assert!(out.is_ok(), "规则体为假应视为未命中而非报错: {out:?}");
    let Some(out) = out.ok() else { return };
    assert!(!out.hit, "规则体为假应视为未命中，而非错误");
    assert_eq!(out.action, None);
    assert!(!out.redact);
}

#[test]
pub(crate) fn reason_only_policy_counts_as_hit() {
    let p = rego_policy(
        "rego-audit-only",
        r#"
package agf

reason := "命中审计规则" if { input.tool_name == "shell" }
"#,
    );
    let backend = RegoBackend::compile(&p);
    assert!(backend.is_ok());
    let Some(backend) = backend.ok() else { return };
    assert!(!backend.has_action_rule());
    let out = backend.evaluate(&ctx(), None);
    assert!(out.is_ok());
    let Some(out) = out.ok() else { return };
    assert!(out.hit, "仅 reason 的策略也应视为命中");
    assert_eq!(out.action, None, "未定义 action 规则时动作由策略行配置决定");
    assert_eq!(out.reason.as_deref(), Some("命中审计规则"));
}

#[test]
pub(crate) fn hit_object_is_injected_into_input() {
    let p = rego_policy(
        "rego-uses-hit",
        r#"
package agf

action := "deny" if { input.hit != null }
reason := sprintf("黑名单 %v", [input.hit.rule_id]) if { input.hit != null }
"#,
    );
    let backend = RegoBackend::compile(&p);
    assert!(backend.is_ok());
    let Some(backend) = backend.ok() else { return };
    // 无命中：input.hit == null ⇒ 不命中
    let out = backend.evaluate(&ctx(), None);
    assert!(out.is_ok());
    assert!(!out.ok().map(|o| o.hit).unwrap_or(true));
    // 有命中
    let hit = serde_json::json!({"rule_id": "cmd.rm-rf", "reason": "危险命令"});
    let out = backend.evaluate(&ctx(), Some(&hit));
    assert!(out.is_ok());
    let Some(out) = out.ok() else { return };
    assert!(out.hit);
    assert_eq!(out.action, Some(PolicyAction::Deny));
    assert_eq!(out.reason.as_deref(), Some("黑名单 cmd.rm-rf"));
}

#[test]
pub(crate) fn compile_error_is_parse_error_with_policy_name() {
    let p = rego_policy("broken-rego", "package agf\n\naction := \"deny\" if { this is not rego }");
    let err = RegoBackend::compile(&p);
    assert!(err.is_err());
    let Some(e) = err.err() else { return };
    assert_eq!(e.code(), "parse_error");
    assert!(e.to_string().contains("broken-rego"), "错误信息应含策略名: {e}");
}

#[test]
pub(crate) fn wrong_package_is_rejected() {
    let p = rego_policy("wrong-pkg", "package other\n\naction := \"deny\"");
    let err = RegoBackend::compile(&p);
    assert!(err.is_err());
    let Some(e) = err.err() else { return };
    assert_eq!(e.code(), "parse_error");
    assert!(e.to_string().contains("包名非法"), "{e}");
}

#[test]
pub(crate) fn non_string_action_is_rejected_at_eval() {
    let p = rego_policy("bad-action-type", "package agf\n\naction := 42 if { true }");
    let backend = RegoBackend::compile(&p);
    assert!(backend.is_ok(), "编译期只探测定义，类型错误在求值期报出");
    let Some(backend) = backend.ok() else { return };
    let out = backend.evaluate(&ctx(), None);
    assert!(out.is_err());
    assert_eq!(out.err().map(|e| e.code()), Some("parse_error"));
}

#[test]
pub(crate) fn unknown_action_string_is_rejected() {
    let p = rego_policy("bad-action-name", "package agf\n\naction := \"explode\" if { true }");
    let backend = RegoBackend::compile(&p);
    assert!(backend.is_ok());
    let Some(backend) = backend.ok() else { return };
    let err = backend.evaluate(&ctx(), None);
    assert!(err.is_err());
    assert!(err.err().map(|e| e.to_string().contains("未知策略动作")).unwrap_or(false));
}

#[test]
pub(crate) fn default_rule_and_multiple_bodies() {
    let p = rego_policy(
        "rego-default",
        r#"
package agf

default action := "allow"

action := "isolate" if { input.max_severity == "critical" }
action := "deny" if { input.domain == "evil.example.com" }
"#,
    );
    let backend = RegoBackend::compile(&p);
    assert!(backend.is_ok());
    let Some(backend) = backend.ok() else { return };
    // default 存在 ⇒ action 始终有定义 ⇒ 任何输入都"命中"
    let out = backend.evaluate(&ctx(), None);
    assert!(out.is_ok());
    let Some(out) = out.ok() else { return };
    assert!(out.hit);
    assert_eq!(out.action, Some(PolicyAction::Deny), "domain 规则应先于 default 命中");
}

#[test]
pub(crate) fn input_schema_carries_all_context_fields() {
    let json = build_input(&ctx(), None);
    assert!(json.is_ok());
    let Some(json) = json.ok() else { return };
    for key in [
        "tenant_id",
        "session_id",
        "agent_id",
        "department",
        "intercept_point",
        "tool_name",
        "path",
        "domain",
        "command",
        "payload",
        "payload_bytes",
        "risk_domains",
        "max_severity",
        "data_class",
        "now",
        "hit",
    ] {
        assert!(json.get(key).is_some(), "input 缺少字段 {key}");
    }
    assert_eq!(json["intercept_point"], serde_json::json!("mcp-proxy"));
    assert_eq!(json["hit"], serde_json::Value::Null);
}

#[test]
pub(crate) fn rule_paths_are_the_documented_contract() {
    assert_eq!(RULE_ACTION, "data.agf.action");
    assert_eq!(RULE_REASON, "data.agf.reason");
    assert_eq!(RULE_REDACT, "data.agf.redact");
    assert_eq!(PACKAGE, "agf");
}

#[test]
pub(crate) fn sanitize_name_keeps_rego_friendly_chars() {
    assert_eq!(sanitize_name("阻断 危险/命令"), "阻断_危险_命令");
    assert_eq!(sanitize_name(""), "policy");
    assert_eq!(sanitize_name("a-b_c1"), "a-b_c1");
}
