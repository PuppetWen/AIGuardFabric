//! 由 `mcp_proxy.rs` 拆分：`tenant` 等 24 个函数（纯搬移，逻辑不变）。
use super::*;
use crate::approval::{ApprovalStore, InMemoryApprovalStore};
use crate::blocklist::Blocklist;
use crate::policy::{SignatureMode, structured_policy};
use agf_core::enums::{PolicyAction, QuotaDimension};
use agf_core::policy::{Policy, StructuredCondition};
use agf_core::quota::{Quota, QuotaWindow};

pub(crate) fn tenant() -> TenantId {
    TenantId::default_tenant()
}

pub(crate) fn session() -> McpProxySession {
    McpProxySession::new(tenant(), Id::new(), McpTransport::Stdio).with_session_id("sess-1").with_agent(Id::new())
}

pub(crate) fn proxy_with(policies: Vec<Policy>, blocklist: Blocklist) -> McpProxy {
    let engine = PolicyEngine::new().with_signature_mode(SignatureMode::Disabled).from_policies(policies);
    assert!(engine.is_ok(), "{engine:?}");
    offline_proxy(engine.unwrap_or_default(), blocklist)
}

pub(crate) fn deny_tool_policy(tool: &str) -> Policy {
    structured_policy(
        tenant(),
        format!("deny-{tool}"),
        StructuredCondition { tool_denylist: vec![tool.into()], ..Default::default() },
        PolicyAction::Deny,
        10,
    )
}

// ---------- 耗时埋点 ----------

#[tokio::test]
pub(crate) async fn every_intercept_path_records_a_real_latency() {
    let proxy = proxy_with(vec![deny_tool_policy("execute_shell")], Blocklist::with_defaults());
    // 入站 · 策略拒绝
    let denied = JsonRpcFrame::parse(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_shell","arguments":{"command":"ls"}}}"#,
    );
    assert!(denied.is_ok(), "{denied:?}");
    if let Ok(frame) = denied {
        let out = proxy.intercept_request(&session(), &frame).await;
        assert!(out.is_ok(), "{out:?}");
    }
    // 入站 · 非工具调用（直接放行，但同样要带耗时）
    let handshake = JsonRpcFrame::parse(r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}"#);
    assert!(handshake.is_ok(), "{handshake:?}");
    if let Ok(frame) = handshake {
        let out = proxy.intercept_request(&session(), &frame).await;
        assert!(out.is_ok(), "{out:?}");
    }
    // 出站 · 错误响应（直接放行）
    let failure = JsonRpcFrame::parse(r#"{"jsonrpc":"2.0","id":3,"error":{"code":-32000,"message":"工具执行失败"}}"#);
    assert!(failure.is_ok(), "{failure:?}");
    if let Ok(frame) = failure {
        let out = proxy.intercept_response(&session(), &frame).await;
        assert!(out.is_ok(), "{out:?}");
    }

    let records = proxy.audit().records();
    assert_eq!(records.len(), 3, "三条路径都要写审计: {records:?}");
    assert_eq!(records[0].tool_name.as_deref(), Some("execute_shell"));
    assert!(records[1].tool_name.is_none(), "握手请求不能归到上一次工具调用");
    assert!(records[2].tool_name.is_none(), "没有请求关联的响应不能猜测工具名");
    for record in &records {
        assert!(record.latency_micros > 0, "每条拦截记录都必须带真实耗时: {}", record.summary_line());
    }
    assert!(proxy.audit().verify().passed, "带耗时的链必须自洽");
}

// ---------- JSON-RPC 帧 ----------

#[test]
pub(crate) fn parses_realistic_tools_call_frame() {
    let raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_shell","arguments":{"command":"ls -la","timeout":30}}}"#;
    let frame = JsonRpcFrame::parse(raw);
    assert!(frame.is_ok());
    let Some(f) = frame.ok() else { return };
    assert!(f.is_request());
    assert!(!f.is_response());
    assert!(f.is_tool_call());
    assert_eq!(f.method_name(), "tools/call");
    assert_eq!(f.tool_name(), Some("execute_shell"));
    assert_eq!(f.arguments()["timeout"], serde_json::json!(30));
    assert_eq!(f.id, Some(serde_json::json!(1)));
}

#[test]
pub(crate) fn parses_response_frames() {
    let ok = JsonRpcFrame::parse(r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#);
    assert!(ok.is_ok());
    assert!(ok.is_ok_and(|f| f.is_response()));
    let err = JsonRpcFrame::parse(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"nope"}}"#);
    assert!(err.is_ok());
    assert!(err.is_ok_and(|f| f.is_response() && f.error.is_some()));
}

#[test]
pub(crate) fn malformed_frames_are_rejected_with_precise_reasons() {
    assert!(matches!(JsonRpcFrame::parse("not json"), Err(JsonRpcParseError::InvalidJson(_))));
    assert_eq!(JsonRpcFrame::parse("[1,2,3]"), Err(JsonRpcParseError::NotAnObject));
    assert_eq!(JsonRpcFrame::parse(r#"{"id":1}"#), Err(JsonRpcParseError::BadVersion(String::new())));
    assert_eq!(
        JsonRpcFrame::parse(r#"{"jsonrpc":"1.0","id":1,"method":"x"}"#),
        Err(JsonRpcParseError::BadVersion("1.0".to_string()))
    );
    assert_eq!(JsonRpcFrame::parse(r#"{"jsonrpc":"2.0","id":1}"#), Err(JsonRpcParseError::UnknownShape));
    let too_large = JsonRpcFrame::parse_with_limit(r#"{"jsonrpc":"2.0","id":1,"method":"x"}"#, 8);
    assert!(matches!(too_large, Err(JsonRpcParseError::TooLarge { .. })));
    assert!(JsonRpcParseError::NotAnObject.to_string().contains("JSON 对象"));
}

#[test]
pub(crate) fn serialize_roundtrip_and_modification() {
    let frame = JsonRpcFrame::tool_call(7, "read_file", serde_json::json!({"path": "/tmp/a"}));
    let line = frame.to_line();
    assert!(line.is_ok());
    let Some(line) = line.ok() else { return };
    let back = JsonRpcFrame::parse(&line);
    assert_eq!(back.ok(), Some(frame.clone()));
    let modified =
        frame.clone().with_params(serde_json::json!({"name": "read_file", "arguments": {"path": "[[AGF_REDACTED]]"}}));
    let text = modified.to_line().unwrap_or_default();
    assert!(text.contains("AGF_REDACTED"));
    assert!(!text.contains("/tmp/a"));
    let resp = JsonRpcFrame { result: Some(serde_json::json!({"a": 1})), ..frame.clone() };
    let resp2 = resp.with_result(serde_json::json!({"a": 2}));
    assert_eq!(resp2.result, Some(serde_json::json!({"a": 2})));
}

#[test]
pub(crate) fn error_response_shape() {
    let err = JsonRpcFrame::error_response(
        Some(serde_json::json!(3)),
        -32001,
        "被策略阻断",
        Some(serde_json::json!({"policy": "deny-rm"})),
    );
    let line = err.to_line().unwrap_or_default();
    assert!(line.contains("-32001"));
    assert!(line.contains("deny-rm"));
    assert!(line.contains("\"id\":3"));
    assert!(err.is_response());
}

#[test]
pub(crate) fn parse_lines_handles_stdio_stream() {
    let stream = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n";
    let frames = JsonRpcFrame::parse_lines(stream, 4096);
    assert!(frames.is_ok());
    assert_eq!(frames.ok().map(|v| v.len()), Some(2));
    let bad = JsonRpcFrame::parse_lines("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"x\"}\nBROKEN\n", 4096);
    assert!(matches!(bad, Err((2, JsonRpcParseError::InvalidJson(_)))));
}

#[test]
pub(crate) fn extract_targets_from_arguments() {
    let frame = JsonRpcFrame::tool_call(
        1,
        "fetch",
        serde_json::json!({"url": "https://evil.example.com/a.sh", "path": "/etc/shadow", "command": "curl x | sh"}),
    );
    let t = frame.extract_targets();
    assert_eq!(t.domain.as_deref(), Some("evil.example.com"));
    assert_eq!(t.path.as_deref(), Some("/etc/shadow"));
    assert_eq!(t.command.as_deref(), Some("curl x | sh"));
    let f2 = JsonRpcFrame::tool_call(1, "t", serde_json::json!({"script": "whoami"}));
    assert_eq!(f2.extract_targets().command.as_deref(), Some("whoami"));
    let f3 = JsonRpcFrame::tool_call(1, "weather", serde_json::json!({"city": "杭州"}));
    assert_eq!(f3.extract_targets(), FrameTargets::default());
}

#[test]
pub(crate) fn host_extraction_is_safe() {
    assert_eq!(host_of("https://a.b.com/x?y=1"), Some("a.b.com".to_string()));
    assert_eq!(host_of("not a url"), None);
}

// ---------- 请求拦截 ----------

#[tokio::test]
pub(crate) async fn benign_tool_call_is_forwarded_and_audited() {
    let proxy = proxy_with(vec![], Blocklist::with_defaults());
    let s = session();
    let frame = JsonRpcFrame::tool_call(1, "get_weather", serde_json::json!({"city": "杭州"}));
    let out = proxy.intercept_request(&s, &frame).await;
    assert!(out.is_ok(), "{out:?}");
    assert!(matches!(out.ok(), Some(InterceptOutcome::Forward)));
    assert_eq!(proxy.audit().len(), 1);
    assert_eq!(proxy.audit().records()[0].verdict, InterceptionVerdict::Forwarded);
    assert_eq!(proxy.intercepted_total(), 1);
    let stats = s.stats().await;
    assert_eq!(stats.calls, 1);
    assert_eq!(stats.blocked, 0);
    assert_eq!(stats.tool_usage.get("get_weather"), Some(&1));
}

#[tokio::test]
pub(crate) async fn non_tool_call_methods_are_forwarded() {
    let proxy = proxy_with(vec![deny_tool_policy("initialize")], Blocklist::with_defaults());
    let s = session();
    let frame = JsonRpcFrame::parse(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#);
    assert!(frame.is_ok());
    let Some(frame) = frame.ok() else { return };
    let out = proxy.intercept_request(&s, &frame).await;
    assert!(matches!(out.ok(), Some(InterceptOutcome::Forward)), "握手类方法不做工具级管控");
    assert_eq!(proxy.audit().len(), 1, "但仍写审计");
}

#[tokio::test]
pub(crate) async fn dangerous_command_is_blocked_by_blocklist() {
    let proxy = proxy_with(vec![], Blocklist::with_defaults());
    let s = session();
    let frame = JsonRpcFrame::tool_call(1, "execute_shell", serde_json::json!({"command": "rm -rf /"}));
    let out = proxy.intercept_request(&s, &frame).await;
    assert!(out.is_ok());
    let Some(InterceptOutcome::Blocked { decision }) = out.ok() else {
        panic!("危险命令必须被阻断");
    };
    assert_eq!(decision.action, PolicyAction::Deny);
    assert!(decision.reason.contains("cmd.rm-rf-root"), "{}", decision.reason);
    assert_eq!(proxy.audit().len(), 1);
    let rec = &proxy.audit().records()[0];
    assert_eq!(rec.verdict, InterceptionVerdict::Blocked);
    assert_eq!(rec.blocklist_rules, vec!["cmd.rm-rf-root".to_string()]);
    assert!(rec.enforced);
    assert_eq!(s.stats().await.blocked, 1);
}

#[tokio::test]
pub(crate) async fn blocked_by_policy_returns_decision() {
    let proxy = proxy_with(vec![deny_tool_policy("execute_shell")], Blocklist::empty());
    let s = session();
    let frame = JsonRpcFrame::tool_call(1, "execute_shell", serde_json::json!({"command": "ls"}));
    let out = proxy.intercept_request(&s, &frame).await;
    assert!(out.is_ok());
    let Some(InterceptOutcome::Blocked { decision }) = out.ok() else { panic!("策略应阻断") };
    assert_eq!(decision.policy_name.as_deref(), Some("deny-execute_shell"));
    assert!(decision.is_blocking());
}

#[tokio::test]
pub(crate) async fn redaction_rewrites_arguments() {
    let policy = structured_policy(
        tenant(),
        "redact-secrets",
        StructuredCondition { tool_denylist: vec!["read_file".into()], ..Default::default() },
        PolicyAction::Redact,
        10,
    );
    let proxy = proxy_with(vec![policy], Blocklist::empty());
    let s = session();
    let frame = JsonRpcFrame::tool_call(
        1,
        "read_file",
        serde_json::json!({"path": "/tmp/a", "api_key": "sk-proj-abcdefghijklmnopqrstuvwx"}),
    );
    let out = proxy.intercept_request(&s, &frame).await;
    assert!(out.is_ok(), "{out:?}");
    let Some(InterceptOutcome::ForwardRedacted { payload, redactions }) = out.ok() else {
        panic!("应脱敏转发");
    };
    assert!(redactions >= 1);
    assert!(!payload.contains("sk-proj-abcdefghijklmnopqrstuvwx"), "载荷中不得残留凭据: {payload}");
    assert!(payload.contains("AGF_"), "应替换为占位符: {payload}");
    assert!(JsonRpcFrame::parse(&payload).is_ok());
    assert_eq!(s.stats().await.redacted, 1);
    assert_eq!(proxy.audit().records()[0].verdict, InterceptionVerdict::ForwardedRedacted);
}

#[tokio::test]
pub(crate) async fn approval_request_denies_and_creates_record() {
    let policy = structured_policy(
        tenant(),
        "approve-shell",
        StructuredCondition {
            tool_denylist: vec!["execute_shell".into()],
            require_approval: true,
            ..Default::default()
        },
        PolicyAction::Approval,
        10,
    );
    let store = std::sync::Arc::new(InMemoryApprovalStore::new());
    let engine = PolicyEngine::new().with_signature_mode(SignatureMode::Disabled).from_policies(vec![policy]);
    assert!(engine.is_ok());
    let proxy = offline_proxy(engine.unwrap_or_default(), Blocklist::empty()).with_approvals(store.clone());
    let s = session();
    let frame = JsonRpcFrame::tool_call(1, "execute_shell", serde_json::json!({"command": "ls"}));
    let out = proxy.intercept_request(&s, &frame).await;
    assert!(out.is_ok(), "{out:?}");
    let Some(needs) = out.ok() else { return };
    let (id, link) = match &needs {
        InterceptOutcome::NeedsApproval { id, link } => (*id, link.clone()),
        other => panic!("应进入审批，实际 {other:?}"),
    };
    assert!(link.contains(&id.to_string()));
    assert!(needs.is_blocked(), "待审批期间必须拒绝");
    assert_eq!(store.count().await, Ok(Some(1)), "必须创建审批单");
    assert_eq!(s.stats().await.pending_approvals, 1);
    assert_eq!(proxy.audit().records()[0].verdict, InterceptionVerdict::PendingApproval);
    // 审批单可被批准，且只能消费一次
    assert!(store.approve(tenant(), id, Id::new(), "同意").await.is_ok());
    assert!(store.consume(tenant(), id, "mcp-proxy").await.is_ok());
    assert!(store.consume(tenant(), id, "mcp-proxy").await.is_err(), "单次语义");
}

#[tokio::test]
pub(crate) async fn approval_without_store_fails_closed() {
    let policy = structured_policy(
        tenant(),
        "approve-shell",
        StructuredCondition {
            tool_denylist: vec!["execute_shell".into()],
            require_approval: true,
            ..Default::default()
        },
        PolicyAction::Approval,
        10,
    );
    let proxy = proxy_with(vec![policy], Blocklist::empty());
    let s = session();
    let frame = JsonRpcFrame::tool_call(1, "execute_shell", serde_json::json!({"command": "ls"}));
    let out = proxy.intercept_request(&s, &frame).await;
    assert!(out.is_err(), "无审批存储时必须报错而不是放行");
    assert_eq!(out.err().map(|e| e.code()), Some("dependency_unavailable"));
}

#[tokio::test]
pub(crate) async fn oversized_payload_is_blocked_by_policy() {
    let policy = structured_policy(
        tenant(),
        "payload-cap",
        StructuredCondition { max_payload_bytes: Some(64), ..Default::default() },
        PolicyAction::Deny,
        10,
    );
    let proxy = proxy_with(vec![policy], Blocklist::empty());
    let s = session();
    let big = "x".repeat(256);
    let frame = JsonRpcFrame::tool_call(1, "echo", serde_json::json!({"data": big}));
    let out = proxy.intercept_request(&s, &frame).await;
    assert!(out.is_ok());
    let Some(InterceptOutcome::Blocked { decision }) = out.ok() else { panic!("超上限载荷应阻断") };
    assert_eq!(decision.policy_name.as_deref(), Some("payload-cap"));
}

#[tokio::test]
pub(crate) async fn quota_exceeded_throttles_request() {
    let mut q = Quota::tenant_default(tenant(), QuotaDimension::Requests, 1);
    q.on_exceed = PolicyAction::Throttle;
    q.window = QuotaWindow::Minute;
    let quotas = QuotaService::in_memory(vec![q]);
    let proxy = proxy_with(vec![], Blocklist::empty()).with_quotas(quotas);
    let s = session();
    let frame = JsonRpcFrame::tool_call(1, "get_weather", serde_json::json!({}));
    let first = proxy.intercept_request(&s, &frame).await;
    assert!(matches!(first.ok(), Some(InterceptOutcome::Forward)));
    let second = proxy.intercept_request(&s, &frame).await;
    assert!(second.is_ok());
    let Some(InterceptOutcome::Throttled { retry_after }) = second.ok() else {
        panic!("第二次调用应被限流");
    };
    assert!(retry_after > 0);
    assert_eq!(s.stats().await.blocked, 1);
    assert_eq!(proxy.audit().records().last().map(|r| r.verdict), Some(InterceptionVerdict::Throttled));
}

#[tokio::test]
pub(crate) async fn quota_degrade_yields_degraded_outcome() {
    let mut q = Quota::tenant_default(tenant(), QuotaDimension::Requests, 1);
    q.on_exceed = PolicyAction::Degrade;
    let quotas = QuotaService::in_memory(vec![q]);
    let proxy = proxy_with(vec![], Blocklist::empty()).with_quotas(quotas);
    let s = session();
    let frame = JsonRpcFrame::tool_call(1, "chat", serde_json::json!({}));
    assert!(matches!(proxy.intercept_request(&s, &frame).await.ok(), Some(InterceptOutcome::Forward)));
    let second = proxy.intercept_request(&s, &frame).await;
    assert!(second.is_ok());
    assert!(matches!(second.ok(), Some(InterceptOutcome::Degraded { .. })));
}

#[tokio::test]
pub(crate) async fn session_finish_releases_concurrency_once() {
    let q = Quota::tenant_default(tenant(), QuotaDimension::Concurrency, 1);
    let quotas = QuotaService::in_memory(vec![q]);
    let proxy = proxy_with(vec![], Blocklist::empty()).with_quotas(quotas.clone());
    let s = session();
    let frame = JsonRpcFrame::tool_call(1, "chat", serde_json::json!({}));
    assert!(matches!(proxy.intercept_request(&s, &frame).await.ok(), Some(InterceptOutcome::Forward)));
    assert!(s.stats().await.concurrency_held);
    assert!(s.finish(&quotas, &QuotaConsumption::one_request()).await.is_ok_and(|v| v));
    assert!(!s.stats().await.concurrency_held);
    assert!(s.finish(&quotas, &QuotaConsumption::one_request()).await.is_ok_and(|v| !v));
    assert!(matches!(proxy.intercept_request(&s, &frame).await.ok(), Some(InterceptOutcome::Forward)));
}
