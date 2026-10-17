//! 由 `engine.rs` 拆分：`hot_reload_policies_takes_effect_immediately` 等 15 个函数（纯搬移，逻辑不变）。
use super::*;
use crate::blocklist::Blocklist;
use crate::guard::keys as guard_keys;
use crate::mcp_proxy::JsonRpcFrame;
use crate::policy::{SignatureMode, structured_policy};
use agf_core::enums::PolicyAction;
use agf_core::policy::StructuredCondition;
use pretty_assertions::assert_eq;

#[tokio::test]
pub(crate) async fn hot_reload_policies_takes_effect_immediately() {
    let e = engine(vec![deny_policy("deny-rm", "rm -rf")], vec![]);
    let c = {
        let mut c = ctx("s-1");
        c.command = Some("sudo rm -rf /var".to_string());
        c
    };
    assert_eq!(e.evaluate(c.clone()).await.ok().map(|d| d.action), Some(PolicyAction::Deny));
    // 热重载为空策略表 ⇒ 策略不再命中；注意此时**黑名单兜底**仍在（最低防线不随策略表清空），
    // 因此断言的是"策略身份已消失"而不是"动作变成 Allow"。
    assert!(e.reload_policies(vec![]).await.is_ok());
    assert_eq!(e.policy_count().await, 0);
    let cleared = e.evaluate(c.clone()).await.ok();
    assert_eq!(cleared.as_ref().map(|d| d.policy_id), Some(None), "策略应已全部卸载");
    assert_eq!(cleared.as_ref().and_then(|d| d.policy_name.as_deref()), None);
    assert!(cleared.as_ref().is_some_and(|d| d.reason.contains("黑名单")), "空策略表下应由黑名单兜底: {cleared:?}");
    // 再下发一条新策略 ⇒ 立即生效
    assert!(e.reload_policies(vec![deny_policy("deny-sudo", "sudo")]).await.is_ok());
    let reloaded = e.evaluate(c).await.ok();
    assert_eq!(reloaded.as_ref().map(|d| d.action), Some(PolicyAction::Deny));
    assert_eq!(reloaded.as_ref().and_then(|d| d.policy_name.as_deref()), Some("deny-sudo"));
}

#[tokio::test]
pub(crate) async fn failed_policy_reload_keeps_old_set() {
    let e = engine(vec![deny_policy("deny-rm", "rm -rf")], vec![]);
    let mut broken =
        structured_policy(TenantId::default_tenant(), "broken", StructuredCondition::default(), PolicyAction::Deny, 1);
    broken.language = agf_core::policy::PolicyLanguage::Rego;
    broken.source = "package agf\naction := }".into();
    let bad = e.reload_policies(vec![broken]).await;
    assert!(bad.is_err());
    assert_eq!(e.policy_count().await, 1, "失败的热重载必须保留旧策略");
}

#[tokio::test]
pub(crate) async fn blocklist_hot_reload_and_restore() {
    let e = engine(vec![], vec![]);
    let before = e.blocklist_len().await;
    assert!(before >= 35);
    assert!(
        e.reload_blocklist(vec![crate::blocklist::RuleRule::deny(
            "only",
            crate::blocklist::RuleKind::Command,
            "danger",
            "唯一规则",
            agf_core::enums::RiskDomain::ToolAbuse,
            agf_core::enums::Severity::High,
        )])
        .await
        .is_ok()
    );
    assert_eq!(e.blocklist_len().await, 1);
    // 旧规则失效
    let out = e.intercept_mcp_request(ctx("s"), r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run","arguments":{"command":"rm -rf /"}}}"#).await;
    assert!(matches!(out.ok(), Some(InterceptOutcome::Forward)));
    // 恢复内置
    e.reload_default_blocklist().await;
    assert_eq!(e.blocklist_len().await, before);
}

#[tokio::test]
pub(crate) async fn evaluate_never_fails_open_by_default() {
    // Rego 运行时类型错误 ⇒ fail-closed ⇒ PolicyDenied
    let mut p = structured_policy(
        TenantId::default_tenant(),
        "bad-eval",
        StructuredCondition::default(),
        PolicyAction::Audit,
        1,
    );
    p.language = agf_core::policy::PolicyLanguage::Rego;
    p.source = "package agf\naction := 42 if { true }".into();
    p.intercept_points = all_points();
    let e = engine(vec![p], vec![]);
    let err = e.evaluate(ctx("s")).await;
    assert!(err.is_err(), "默认必须 fail-closed");
    assert_eq!(err.err().map(|e| e.code()), Some("policy_denied"));
}

#[tokio::test]
pub(crate) async fn install_signer_reenrols_policies() {
    let e = engine(vec![deny_policy("p", "rm -rf")], vec![]);
    assert_eq!(e.policy_count().await, 1);
    // 安装签名器 + Enforce：已有策略未签名 ⇒ 被拒绝装载
    let ok = e.install_signer(PolicySigner::dev_default(), SignatureMode::Enforce).await;
    assert!(ok.is_ok());
    assert_eq!(e.policy_count().await, 0, "未签名策略在 Enforce 下不得生效");
    let report = e.guard_report().await;
    assert!(report.item(guard_keys::POLICY_UNSIGNED).is_some_and(|i| !i.passed));
}

#[tokio::test]
pub(crate) async fn frame_size_limit_is_enforced() {
    let mut e = engine(vec![], vec![]);
    e.set_max_frame_bytes(32);
    let out = e
        .intercept_mcp_request(
            ctx("s"),
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{}}}"#,
        )
        .await;
    assert!(out.is_err());
    assert_eq!(out.err().map(|e| e.code()), Some("parse_error"));
}

#[tokio::test]
pub(crate) async fn malformed_frame_is_reported() {
    let e = engine(vec![], vec![]);
    let out = e.intercept_mcp_request(ctx("s"), "{oops").await;
    assert!(out.is_err());
    assert_eq!(out.err().map(|e| e.code()), Some("parse_error"));
    // 方向错误：请求帧送去响应拦截
    let wrong =
        e.intercept_mcp_response(&ctx("s"), r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#).await;
    assert!(wrong.is_err());
    assert_eq!(wrong.err().map(|e| e.code()), Some("validation_failed"));
}

#[tokio::test]
pub(crate) async fn intercept_frame_accepts_parsed_frames() {
    let e = engine(vec![], vec![]);
    let frame = JsonRpcFrame::tool_call(1, "execute_shell", serde_json::json!({"command": "mkfs /dev/sda"}));
    let out = e.intercept_frame(&ctx("s"), &frame).await;
    assert!(out.is_ok());
    assert!(matches!(out.ok(), Some(InterceptOutcome::Blocked { .. })));
}

#[tokio::test]
pub(crate) async fn redaction_helpers_on_engine() {
    let e = engine(vec![], vec![]);
    let (text, n) = e.redact_text("token=sk-proj-abcdefghijklmnopqrstuvwx");
    assert!(n >= 1);
    assert!(!text.contains("sk-proj-abcdefghijklmnopqrstuvwx"));
    let (json, m) = e.redact_json(&serde_json::json!({"api_key": "sk-proj-abcdefghijklmnopqrstuvwx"}));
    assert!(m >= 1);
    assert!(!json.to_string().contains("sk-proj-abcdefghijklmnopqrstuvwx"));
}

#[tokio::test]
pub(crate) async fn quota_snapshot_without_quota_service_is_degraded() {
    let engine = PolicyEngine::new().with_signature_mode(SignatureMode::Disabled);
    let e = RuntimeEngine::assemble(
        engine,
        Blocklist::with_defaults(),
        QuotaService::in_memory(vec![]),
        Arc::new(InMemoryApprovalStore::new()),
        EngineConfig::default(),
    );
    let snap = e.quota_snapshot(TenantId::default_tenant(), None, "s").await;
    assert!(snap.is_ok());
    assert!(snap.is_ok_and(|s| s.entries.is_empty()));
}

#[tokio::test]
pub(crate) async fn config_helpers() {
    let cfg = EngineConfig::default();
    assert_eq!(cfg.required_intercept_points().len(), 3);
    assert!(cfg.enroll_self_proxy);
    let cfg2 = EngineConfig::default()
        .with_required_points(vec![InterceptPoint::McpProxy])
        .with_tenant(TenantId::new())
        .with_redaction_mode(RedactionMode::Aggressive)
        .with_audit_capacity(16)
        .with_self_proxy_enrollment(false)
        .with_heartbeat_interval(5);
    assert_eq!(cfg2.required_intercept_points(), vec![InterceptPoint::McpProxy]);
    assert_eq!(cfg2.audit_capacity, 16);
    assert!(!cfg2.enroll_self_proxy);
    assert_eq!(cfg2.heartbeat_interval_secs, 5);
    assert_eq!(cfg2.redaction_mode, RedactionMode::Aggressive);
}

#[tokio::test]
pub(crate) async fn audit_capacity_is_respected() {
    let e = RuntimeEngine::in_memory(vec![], vec![], EngineConfig::default().with_audit_capacity(2));
    assert!(e.is_ok());
    let Some(e) = e.ok() else { return };
    let raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather","arguments":{}}}"#;
    for _ in 0..4 {
        assert!(e.intercept_mcp_request(ctx("s"), raw).await.is_ok());
    }
    assert_eq!(e.audit().len(), 2);
    assert_eq!(e.audit().total(), 4);
    assert!(e.audit().is_truncated());
    let report = e.guard_report().await;
    assert!(report.item(guard_keys::AUDIT_COMPLETE).is_some_and(|i| !i.passed));
}

#[tokio::test]
pub(crate) async fn heartbeat_via_engine() {
    let e = engine(vec![], vec![]);
    let monitor = e.heartbeats();
    assert_eq!(monitor.len(), 1, "离线引擎默认注册一个代理端点");
    assert_eq!(monitor.alive_count(), 1);
    // 记录心跳：未注册端点返回 false
    assert!(!monitor.record_beat("nobody"));
    let ids: Vec<String> = monitor.states().iter().map(|s| s.endpoint_id.clone()).collect();
    assert!(ids[0].starts_with("proxy:runtime-"));
    assert!(monitor.record_beat(&ids[0]));
    let base = Timestamp::now();
    for i in 1..=3 {
        let _ = monitor.tick(base.offset_secs(30 * i));
    }
    assert_eq!(monitor.alerts().len(), 1);
    let report = e.guard_report().await;
    assert!(report.item(guard_keys::HEARTBEAT).is_some_and(|i| !i.passed));
    assert_eq!(report.heartbeat_alerts.len(), 1);
}

#[test]
pub(crate) fn status_mapping_and_blocking_helper() {
    assert_eq!(RuntimeEngine::status_for(PolicyAction::Deny), 403);
    assert_eq!(RuntimeEngine::status_for(PolicyAction::Isolate), 403);
    assert_eq!(RuntimeEngine::status_for(PolicyAction::Throttle), 429);
    assert_eq!(RuntimeEngine::status_for(PolicyAction::Quota), 429);
    assert_eq!(RuntimeEngine::status_for(PolicyAction::Approval), 202);
    assert_eq!(RuntimeEngine::status_for(PolicyAction::Allow), 200);
    assert!(!RuntimeEngine::is_blocking(&PolicyDecision::allow("x")));
}

#[tokio::test]
pub(crate) async fn concurrent_interceptions_keep_audit_chain_valid() {
    let e = Arc::new(engine(vec![deny_policy("deny-rm", "rm -rf")], vec![]));
    let mut handles = Vec::new();
    for t in 0..6 {
        let e = Arc::clone(&e);
        handles.push(tokio::spawn(async move {
                for i in 0..8 {
                    let raw = format!(
                        r#"{{"jsonrpc":"2.0","id":{i},"method":"tools/call","params":{{"name":"run","arguments":{{"command":"ls -la"}}}}}}"#
                    );
                    let out = e.intercept_mcp_request(ctx(&format!("s-{t}")), &raw).await;
                    assert!(out.is_ok());
                }
            }));
    }
    for h in handles {
        assert!(h.await.is_ok());
    }
    assert_eq!(e.audit().total(), 48);
    assert!(e.audit().verify().passed);
}
