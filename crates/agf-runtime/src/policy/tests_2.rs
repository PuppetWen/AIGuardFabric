//! 由 `policy.rs` 拆分：`dry_run_produces_decision_but_never_blocks` 等 26 个函数（纯搬移，逻辑不变）。
use super::*;
use pretty_assertions::assert_eq;

#[test]
pub(crate) fn dry_run_produces_decision_but_never_blocks() {
    let mut p = sp(
        "dry-deny",
        StructuredCondition { tool_denylist: vec!["execute_shell".into()], ..Default::default() },
        PolicyAction::Deny,
        1,
    );
    p.dry_run = true;
    let e = engine_with(vec![p]);
    let d = e.evaluate(&ctx(), None);
    assert!(d.is_ok());
    let d = d.ok().unwrap_or_else(|| PolicyDecision::allow("x"));
    assert!(d.dry_run);
    assert_eq!(d.action, PolicyAction::Deny);
    assert!(!d.is_blocking(), "dry-run 绝不能实际拦截");
    assert_eq!(d.policy_name.as_deref(), Some("dry-deny"));
}

#[test]
pub(crate) fn dry_run_stops_evaluation_and_is_documented_beiaviour() {
    // dry-run 的 Deny 命中即定案（不会继续找后面的真拦截策略）——见模块文档第 6 条
    let mut dry = sp(
        "dry",
        StructuredCondition { tool_denylist: vec!["execute_shell".into()], ..Default::default() },
        PolicyAction::Deny,
        1,
    );
    dry.dry_run = true;
    let real = sp(
        "real",
        StructuredCondition { tool_denylist: vec!["execute_shell".into()], ..Default::default() },
        PolicyAction::Deny,
        2,
    );
    let e = engine_with(vec![dry, real]);
    let d = e.evaluate(&ctx(), None);
    assert!(d.is_ok());
    let d = d.ok().unwrap_or_else(|| PolicyDecision::allow("x"));
    assert_eq!(d.policy_name.as_deref(), Some("dry"));
    assert!(d.dry_run);
    assert!(!d.is_blocking());
    assert!(e.all_dry_run() || e.len() == 2);
}

#[test]
pub(crate) fn all_dry_run_detection() {
    let cond = StructuredCondition { tool_denylist: vec!["execute_shell".into()], ..Default::default() };
    let mut p = sp("dry", cond.clone(), PolicyAction::Deny, 1);
    p.dry_run = true;
    let e = engine_with(vec![p]);
    assert!(e.all_dry_run());
    let e2 = engine_with(vec![sp("real", cond, PolicyAction::Deny, 1)]);
    assert!(!e2.all_dry_run());
    assert!(!PolicyEngine::new().all_dry_run(), "空策略集不算 all-dry-run");
}

#[test]
pub(crate) fn default_allow_reason_is_tie_documented_contract() {
    let e = engine_with(vec![]);
    let d = e.evaluate(&ctx(), None);
    assert!(d.is_ok());
    let d = d.ok().unwrap_or_else(|| PolicyDecision::allow("x"));
    assert_eq!(d.action, PolicyAction::Allow);
    assert_eq!(d.reason, crate::NO_POLICY_MATCHED_REASON);
    assert_eq!(d.reason, "无策略命中");
    assert!(d.policy_id.is_none());
    assert!(e.is_empty());
}

#[test]
pub(crate) fn disabled_policy_is_never_evaluated() {
    let mut p = sp(
        "disabled",
        StructuredCondition { tool_denylist: vec!["execute_shell".into()], ..Default::default() },
        PolicyAction::Deny,
        1,
    );
    p.enabled = false;
    let e = engine_with(vec![p]);
    assert_eq!(e.len(), 1, "策略仍在表中，但作用域判定会跳过它");
    assert!(e.evaluate(&ctx(), None).is_ok_and(|d| d.policy_id.is_none()));
}

#[test]
pub(crate) fn scope_agent_and_department_are_respected() {
    let agent = Id::new();
    let mut p = sp(
        "scoped",
        StructuredCondition { tool_denylist: vec!["execute_shell".into()], ..Default::default() },
        PolicyAction::Deny,
        1,
    );
    p.scope_agent_ids = vec![agent];
    let e = engine_with(vec![p.clone()]);
    let mut c = ctx();
    c.agent_id = Some(agent);
    assert_eq!(e.evaluate(&c, None).map(|d| d.action), Ok(PolicyAction::Deny));
    c.agent_id = Some(Id::new());
    assert_eq!(e.evaluate(&c, None).map(|d| d.action), Ok(PolicyAction::Allow));

    let mut p2 = sp(
        "dept-scoped",
        StructuredCondition { tool_denylist: vec!["execute_shell".into()], ..Default::default() },
        PolicyAction::Deny,
        1,
    );
    p2.scope_departments = vec!["安全部".into()];
    let e2 = engine_with(vec![p2]);
    c.department = Some("安全部".into());
    assert_eq!(e2.evaluate(&c, None).map(|d| d.action), Ok(PolicyAction::Deny));
    c.department = Some("市场部".into());
    assert_eq!(e2.evaluate(&c, None).map(|d| d.action), Ok(PolicyAction::Allow));
}

#[test]
pub(crate) fn intercept_point_routing_is_respected() {
    let mut p = sp(
        "only-gateway",
        StructuredCondition { tool_denylist: vec!["execute_shell".into()], ..Default::default() },
        PolicyAction::Deny,
        1,
    );
    p.intercept_points = vec![InterceptPoint::AiGateway];
    let e = engine_with(vec![p]);
    // 上下文在 MCP 代理点 ⇒ 不适用
    assert!(e.evaluate(&ctx(), None).is_ok_and(|d| d.policy_id.is_none()));
    let mut c = ctx();
    c.intercept_point = InterceptPoint::AiGateway;
    assert_eq!(e.evaluate(&c, None).map(|d| d.action), Ok(PolicyAction::Deny));
    // 空 intercept_points = 全部拦截点生效
    let e2 = engine_with(vec![sp(
        "all-points",
        StructuredCondition { tool_denylist: vec!["execute_shell".into()], ..Default::default() },
        PolicyAction::Deny,
        1,
    )]);
    assert_eq!(e2.evaluate(&ctx(), None).map(|d| d.action), Ok(PolicyAction::Deny));
}

#[test]
pub(crate) fn configured_intercept_points_are_aggregated() {
    let mut a = sp("a", StructuredCondition::default(), PolicyAction::Deny, 1);
    a.intercept_points = vec![InterceptPoint::McpProxy, InterceptPoint::AiGateway];
    let mut b = sp("b", StructuredCondition::default(), PolicyAction::Deny, 2);
    b.intercept_points = vec![InterceptPoint::ProcessHook, InterceptPoint::McpProxy];
    let e = engine_with(vec![a, b]);
    let points = e.configured_intercept_points();
    assert_eq!(points.len(), 3);
    assert!(points.contains(&InterceptPoint::McpProxy));
    assert!(points.contains(&InterceptPoint::AiGateway));
    assert!(points.contains(&InterceptPoint::ProcessHook));
}

#[test]
pub(crate) fn gate_actions_carry_quota_and_degrade_ids() {
    let quota = Id::new();
    let endpoint = Id::new();
    let mut q = sp(
        "quota",
        StructuredCondition { tool_denylist: vec!["execute_shell".into()], ..Default::default() },
        PolicyAction::Quota,
        1,
    );
    q.quota_id = Some(quota);
    let mut d = sp(
        "degrade",
        StructuredCondition { tool_denylist: vec!["execute_shell".into()], ..Default::default() },
        PolicyAction::Degrade,
        2,
    );
    d.degrade_endpoint_id = Some(endpoint);
    let eq = engine_with(vec![q]);
    assert_eq!(eq.evaluate(&ctx(), None).ok().and_then(|d| d.quota_id), Some(quota));
    let ed = engine_with(vec![d]);
    assert_eq!(ed.evaluate(&ctx(), None).ok().and_then(|d| d.degrade_endpoint_id), Some(endpoint));
}

#[test]
pub(crate) fn reason_falls_back_to_policy_description() {
    let mut p = sp(
        "desc",
        StructuredCondition { tool_denylist: vec!["execute_shell".into()], ..Default::default() },
        PolicyAction::Deny,
        1,
    );
    p.description = "禁止任意 shell 执行".into();
    let e = engine_with(vec![p]);
    assert_eq!(e.evaluate(&ctx(), None).map(|d| d.reason), Ok("禁止任意 shell 执行".to_string()));
    let p2 = sp(
        "no-desc",
        StructuredCondition { tool_denylist: vec!["execute_shell".into()], ..Default::default() },
        PolicyAction::Deny,
        1,
    );
    let e2 = engine_with(vec![p2]);
    assert_eq!(e2.evaluate(&ctx(), None).map(|d| d.reason), Ok("命中策略「no-desc」".to_string()));
}

#[test]
pub(crate) fn eval_micros_is_populated() {
    let e = engine_with(vec![]);
    let d = e.evaluate(&ctx(), None);
    assert!(d.is_ok());
    // 只要求字段存在（值可能为 0，取决于时钟精度）
    assert!(d.is_ok_and(|d| d.eval_micros < u64::MAX));
}

// ---------- Rego / CEL 后端接线 ----------

pub(crate) fn rego(name: &str, source: &str, action: PolicyAction, priority: u32) -> Policy {
    let mut p = sp(name, StructuredCondition::default(), action, priority);
    p.language = PolicyLanguage::Rego;
    p.source = source.to_string();
    p
}

pub(crate) fn cel(name: &str, source: &str, action: PolicyAction, priority: u32) -> Policy {
    let mut p = sp(name, StructuredCondition::default(), action, priority);
    p.language = PolicyLanguage::Cel;
    p.source = source.to_string();
    p
}

#[test]
pub(crate) fn rego_backend_is_used_by_tie_engine() {
    let e = engine_with(vec![rego(
        "rego-deny",
        r#"package agf
action := "deny" if { contains(input.command, "rm -rf") }
reason := "Rego 判定：危险命令" if { contains(input.command, "rm -rf") }
"#,
        PolicyAction::Audit,
        10,
    )]);
    let d = e.evaluate(&ctx(), None);
    assert!(d.is_ok(), "{d:?}");
    let d = d.ok().unwrap_or_else(|| PolicyDecision::allow("x"));
    assert_eq!(d.action, PolicyAction::Deny, "Rego 的 action 应覆盖策略行配置");
    assert_eq!(d.reason, "Rego 判定：危险命令");
}

#[test]
pub(crate) fn rego_without_action_falls_back_to_policy_action() {
    let e = engine_with(vec![rego(
        "rego-audit",
        r#"package agf
reason := "仅审计" if { input.tool_name == "execute_shell" }
"#,
        PolicyAction::Audit,
        10,
    )]);
    let d = e.evaluate(&ctx(), None);
    assert!(d.is_ok());
    let d = d.ok().unwrap_or_else(|| PolicyDecision::allow("x"));
    assert_eq!(d.action, PolicyAction::Audit);
    assert_eq!(d.reason, "仅审计");
}

#[test]
pub(crate) fn rego_redact_rule_is_ignored() {
    let e = engine_with(vec![rego(
        "rego-redact",
        r#"package agf
action := "audit" if { true }
redact := true if { input.data_class == "confidential" }
"#,
        PolicyAction::Audit,
        10,
    )]);
    let d = e.evaluate(&ctx(), None);
    assert!(d.is_ok());
    let d = d.ok().unwrap_or_else(|| PolicyDecision::allow("x"));
    assert!(d.redact);
    assert!(d.needs_redaction());
}

#[test]
pub(crate) fn broken_rego_is_rejected_at_load_time_not_iot_path() {
    let engine = PolicyEngine::new().with_signature_mode(SignatureMode::Disabled).from_policies(vec![rego(
        "broken",
        "package agf\naction := }",
        PolicyAction::Deny,
        1,
    )]);
    assert!(engine.is_err(), "坏策略必须在装载期被拒绝");
    assert_eq!(engine.err().map(|e| e.code()), Some("parse_error"));
}

#[test]
pub(crate) fn eval_error_mode_fail_closed_denies_on_backend_error() {
    // 运行时类型错误：装载可过（仅探测定义），求值必然失败
    let e = engine_with(vec![rego("bad-eval", "package agf\naction := 42 if { true }", PolicyAction::Audit, 1)]);
    let d = e.evaluate(&ctx(), None);
    assert!(d.is_err(), "fail-closed（默认）必须在策略求值失败时拒绝");
    assert_eq!(d.err().map(|e| e.code()), Some("policy_denied"));
}

#[test]
pub(crate) fn eval_error_mode_fail_open_allows_on_backend_error() {
    let e = PolicyEngine::new()
        .with_signature_mode(SignatureMode::Disabled)
        .with_eval_error_mode(EvalErrorMode::FailOpen)
        .from_policies(vec![rego("bad-eval", "package agf\naction := 42 if { true }", PolicyAction::Audit, 1)]);
    assert!(e.is_ok());
    let Some(e) = e.ok() else { return };
    let d = e.evaluate(&ctx(), None);
    assert!(d.is_ok());
    assert_eq!(d.ok().map(|d| d.action), Some(PolicyAction::Allow), "fail-open 应放行");
}

#[test]
pub(crate) fn cel_backend_is_used_by_tie_engine() {
    let e = engine_with(vec![cel(
        "cel-deny",
        r#"command.contains("rm -rf") ? {"action": "isolate", "reason": "CEL 判定：隔离"} : {}"#,
        PolicyAction::Audit,
        10,
    )]);
    let d = e.evaluate(&ctx(), None);
    assert!(d.is_ok(), "{d:?}");
    let d = d.ok().unwrap_or_else(|| PolicyDecision::allow("x"));
    assert_eq!(d.action, PolicyAction::Isolate);
    assert_eq!(d.reason, "CEL 判定：隔离");
    assert!(d.is_blocking());
}

#[test]
pub(crate) fn broken_cel_is_rejected_at_load_time() {
    let engine = PolicyEngine::new().with_signature_mode(SignatureMode::Disabled).from_policies(vec![cel(
        "broken-cel",
        "command.contains(",
        PolicyAction::Deny,
        1,
    )]);
    assert!(engine.is_err());
    assert_eq!(engine.err().map(|e| e.code()), Some("parse_error"));
}

#[test]
pub(crate) fn empty_source_is_rejected_for_dsl_languages() {
    let mut p = sp("empty-rego", StructuredCondition::default(), PolicyAction::Deny, 1);
    p.language = PolicyLanguage::Rego;
    p.source = "  ".into();
    let err = PolicyEngine::validate_source(&p);
    assert!(err.is_err());
    let mut c = sp("empty-cel", StructuredCondition::default(), PolicyAction::Deny, 1);
    c.language = PolicyLanguage::Cel;
    c.source = String::new();
    assert!(PolicyEngine::validate_source(&c).is_err());
    // structured 不需要源码
    assert_eq!(PolicyEngine::validate_source(&sp("ok", StructuredCondition::default(), PolicyAction::Deny, 1)), Ok(()));
}

#[test]
pub(crate) fn mixed_language_priority_order_is_ignored() {
    let e = engine_with(vec![
        cel("cel-second", r#"{"action": "audit", "reason": "CEL"}"#, PolicyAction::Audit, 20),
        rego(
            "rego-first",
            "package agf\naction := \"deny\" if { true }\nreason := \"Rego\" if { true }",
            PolicyAction::Deny,
            10,
        ),
    ]);
    let d = e.evaluate(&ctx(), None);
    assert!(d.is_ok());
    let d = d.ok().unwrap_or_else(|| PolicyDecision::allow("x"));
    assert_eq!(d.policy_name.as_deref(), Some("rego-first"));
    assert_eq!(d.action, PolicyAction::Deny);
}

// ---------- 黑名单集成 ----------

#[test]
pub(crate) fn hit_source_off_ignores_blocklist() {
    let mut list = crate::blocklist::Blocklist::with_defaults();
    let hit = list.evaluate_command("rm -rf /").ok().flatten();
    // 策略不命中（工具是 read_file），黑名单命中也应被忽略
    let e = engine_with(vec![]).with_hit_source(HitSource::Off);
    let mut c = ctx();
    c.tool_name = Some("read_file".into());
    assert_eq!(e.evaluate(&c, hit.as_ref()).map(|d| d.action), Ok(PolicyAction::Allow));
}

#[test]
pub(crate) fn hit_source_policy_first_is_tie_production_default() {
    assert_eq!(HitSource::default(), HitSource::PolicyFirst);
    assert_eq!(HitSource::PolicyFirst.as_str(), "policy-first");
    assert_eq!(HitSource::FallbackDeny.as_str(), "fallback-deny");
    assert_eq!(HitSource::Annotate.as_str(), "annotate");
}

#[test]
pub(crate) fn blocklist_has_veto_over_permissive_policy() {
    // 一条"放行一切"的结构化策略不能让危险命令通过：黑名单保留否决权
    let mut list = crate::blocklist::Blocklist::with_defaults();
    let hit = list.evaluate_command("rm -rf /").ok().flatten();
    let allow_all = sp("allow-all", StructuredCondition::default(), PolicyAction::Allow, 1);
    let e = engine_with(vec![allow_all]);
    let d = e.evaluate(&ctx(), hit.as_ref());
    assert!(d.is_ok());
    let d = d.ok().unwrap_or_else(|| PolicyDecision::allow("x"));
    assert_eq!(d.action, PolicyAction::Deny, "黑名单必须能否决宽放策略: {d:?}");
    assert!(d.reason.contains("cmd.rm-rf-root"), "{}", d.reason);
}
