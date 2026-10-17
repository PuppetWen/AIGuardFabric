//! 由 `audit.rs` 拆分：`InterceptionLogHelper`/`impl_InterceptionLogHelper` 等 6 项（纯搬移，逻辑不变）。
use super::*;
use agf_core::enums::InterceptPoint;

/// 构造一条进程 Hook 点的记录（验证拦截点字段参与哈希）。
pub(crate) struct InterceptionLogHelper {
    pub(crate) record: InterceptionRecord,
}

impl InterceptionLogHelper {
    pub(crate) fn new() -> Self {
        Self {
            record: InterceptionRecord::new(
                TenantId::default_tenant(),
                "s",
                InterceptPoint::ProcessHook,
                InterceptionVerdict::Blocked,
                "eBPF 拦截",
            ),
        }
    }
}

#[test]
pub(crate) fn decision_is_applied_to_record() {
    use agf_core::enums::PolicyAction;
    use agf_core::ids::Id;
    use agf_core::policy::PolicyDecision;

    let decision = PolicyDecision {
        action: PolicyAction::Deny,
        policy_id: Some(Id::new()),
        policy_name: Some("deny-rm".into()),
        reason: "危险命令".into(),
        redact: false,
        dry_run: false,
        quota_id: None,
        degrade_endpoint_id: None,
        eval_micros: 5,
    };
    let mut r = InterceptionRecord::new(
        TenantId::default_tenant(),
        "s",
        InterceptPoint::McpProxy,
        InterceptionVerdict::Forwarded,
        "",
    );
    r = r.with_decision(&decision);
    assert_eq!(r.action, PolicyAction::Deny);
    assert_eq!(r.verdict, InterceptionVerdict::Blocked);
    assert_eq!(r.policy_name.as_deref(), Some("deny-rm"));
    assert_eq!(r.reason, "危险命令");
    assert!(r.enforced);

    // dry-run ⇒ 仅审计且 enforced=false
    let dry = PolicyDecision { dry_run: true, ..decision.clone() };
    let r2 = InterceptionRecord::new(
        TenantId::default_tenant(),
        "s",
        InterceptPoint::McpProxy,
        InterceptionVerdict::Forwarded,
        "",
    )
    .with_decision(&dry);
    assert_eq!(r2.verdict, InterceptionVerdict::Audited);
    assert!(!r2.enforced);
    assert!(!r2.verdict.is_blocking());

    // 脱敏放行
    let red = PolicyDecision { action: PolicyAction::Allow, redact: true, dry_run: false, ..decision };
    let r3 = InterceptionRecord::new(
        TenantId::default_tenant(),
        "s",
        InterceptPoint::McpProxy,
        InterceptionVerdict::Forwarded,
        "",
    )
    .with_decision(&red);
    assert_eq!(r3.verdict, InterceptionVerdict::ForwardedRedacted);
}

#[test]
pub(crate) fn record_builders_and_serialization() {
    let r = InterceptionRecord::new(
        TenantId::default_tenant(),
        "s-1",
        InterceptPoint::AiGateway,
        InterceptionVerdict::Forwarded,
        "无策略命中",
    )
    .with_tool("chat")
    .with_target("api.openai.com")
    .with_excerpt("prompt=...")
    .with_response("completion=...");
    assert_eq!(r.tool_name.as_deref(), Some("chat"));
    assert_eq!(r.target.as_deref(), Some("api.openai.com"));
    assert_eq!(r.response_excerpt.as_deref(), Some("completion=..."));
    let json = serde_json::to_string(&r);
    assert!(json.is_ok());
    let Some(json) = json.ok() else { return };
    let back: Result<InterceptionRecord, _> = serde_json::from_str(&json);
    assert!(back.is_ok());
    assert_eq!(back.ok().map(|v| v.session_id), Some("s-1".to_string()));
}

#[test]
pub(crate) fn clear_resets_the_chain() {
    let mut log = log_with(3);
    assert_eq!(log.total(), 3);
    log.clear();
    assert_eq!(log.total(), 0);
    assert!(log.is_empty());
    assert_eq!(log.tail_hash(), GENESIS_HASH);
    assert!(log.verify().passed);
}

#[test]
pub(crate) fn concurrent_appends_keep_the_chain_consistent() {
    use std::sync::Arc;
    // 容量必须 ≥ 总追加数，否则缓冲滚出会让序号从中间开始（截断行为另有用例覆盖）
    let log = Arc::new(InterceptionAuditLog::with_capacity(200));
    let mut handles = Vec::new();
    for t in 0..8 {
        let log = Arc::clone(&log);
        handles.push(std::thread::spawn(move || {
            for i in 0..10 {
                let r = InterceptionRecord::new(
                    TenantId::default_tenant(),
                    &format!("s-{t}"),
                    InterceptPoint::McpProxy,
                    InterceptionVerdict::Forwarded,
                    &format!("t{t}-{i}"),
                );
                assert!(log.append(r).is_ok());
            }
        }));
    }
    for h in handles {
        assert!(h.join().is_ok());
    }
    assert_eq!(log.total(), 80);
    let report = log.verify();
    assert!(report.passed, "并发追加后链必须依然自洽: {:?}", report.violations);
    let records = log.records();
    for (i, r) in records.iter().enumerate() {
        assert_eq!(r.sequence, i as i64 + 1);
    }
}
