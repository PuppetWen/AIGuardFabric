//! 由 `audit.rs` 拆分：`record` 等 19 个函数（纯搬移，逻辑不变）。
use super::*;
use agf_core::enums::InterceptPoint;

pub(crate) fn record(seq_hint: i64) -> InterceptionRecord {
    let mut r = InterceptionRecord::new(
        TenantId::default_tenant(),
        "s-1",
        InterceptPoint::McpProxy,
        InterceptionVerdict::Blocked,
        "命中黑名单规则 cmd.rm-rf-root",
    );
    r.sequence = seq_hint;
    r
}

#[test]
pub(crate) fn genesis_hash_is_the_same_as_core() {
    assert_eq!(GENESIS_HASH, agf_core::audit::GENESIS_HASH);
    assert_eq!(GENESIS_HASH.len(), 64);
}

#[test]
pub(crate) fn verdict_from_action_covers_all_actions() {
    for action in [
        PolicyAction::Allow,
        PolicyAction::Deny,
        PolicyAction::Audit,
        PolicyAction::Quota,
        PolicyAction::Redact,
        PolicyAction::Throttle,
        PolicyAction::Degrade,
        PolicyAction::CircuitBreak,
        PolicyAction::Isolate,
        PolicyAction::Approval,
    ] {
        let v = InterceptionVerdict::from_action(action, false);
        assert!(!v.as_str().is_empty());
        assert!(!v.display_zh().is_empty());
    }
    assert_eq!(InterceptionVerdict::from_action(PolicyAction::Deny, false), InterceptionVerdict::Blocked);
    assert_eq!(InterceptionVerdict::from_action(PolicyAction::Deny, true), InterceptionVerdict::Audited);
    assert_eq!(InterceptionVerdict::from_action(PolicyAction::Approval, false), InterceptionVerdict::PendingApproval);
    assert!(InterceptionVerdict::PendingApproval.is_blocking());
    assert!(InterceptionVerdict::Throttled.is_blocking());
    assert!(!InterceptionVerdict::ForwardedRedacted.is_blocking());
    assert_eq!(InterceptionVerdict::ForwardedRedacted.display_zh(), "脱敏放行");
}

#[test]
pub(crate) fn seal_and_verify_roundtrip() {
    let mut r = record(1);
    r.seal();
    assert!(r.verify());
    assert_eq!(r.entry_hash.len(), 64);
    assert_eq!(r.compute_hash(), r.compute_hash());
}

#[test]
pub(crate) fn tampering_any_field_is_detected_by_verify() {
    let mut r = record(1);
    r.seal();
    r.reason = "被我改了".into();
    assert!(!r.verify(), "改原因必须被发现");
    let mut r2 = record(1);
    r2.seal();
    r2.verdict = InterceptionVerdict::Forwarded;
    assert!(!r2.verify(), "改处置结果必须被发现");
    let mut r3 = record(1);
    r3.seal();
    r3.request_excerpt = "被替换的摘要".into();
    assert!(!r3.verify());
    let mut r4 = record(1);
    r4.seal();
    // 第 1 条的 prev_hash 本来就是 GENESIS_HASH，必须换成**别的**值才算篡改
    r4.prev_hash = "f".repeat(64);
    assert!(!r4.verify());
}

#[test]
pub(crate) fn legacy_records_without_latency_deserialize_to_zero_and_still_verify() {
    // v0 记录（没有 `latency_micros` 字段）：反序列化必须按 0 处理，
    // 且哈希必须与升级前的算法逐字节一致 ⇒ `verify()` 不得把老记录误报为"被篡改"。
    let mut legacy = record(1);
    legacy.seal();
    let value = serde_json::to_value(&legacy);
    assert!(value.is_ok(), "序列化必须成功");
    let Ok(mut value) = value else { return };
    assert!(
        value.as_object_mut().is_some_and(|object| object.remove("latency_micros").is_some()),
        "新记录必须带 latency_micros 字段"
    );
    let decoded: Result<InterceptionRecord, _> = serde_json::from_value(value);
    assert!(decoded.is_ok(), "缺字段的老记录必须能反序列化");
    let Ok(decoded) = decoded else { return };
    assert_eq!(decoded.latency_micros, 0, "老记录缺字段时必须按 0 处理");
    assert_eq!(decoded.entry_hash, legacy.entry_hash, "老记录的哈希必须保持不变");
    assert!(decoded.verify(), "升级前的合法记录不得被误报为被篡改");
}

#[test]
pub(crate) fn measured_latency_participates_in_the_content_hash() {
    let bare = record(1);
    let mut measured = bare.clone().with_latency_micros(1_234);
    let mut expected_bare = bare.clone();
    expected_bare.seal();
    measured.seal();
    assert!(measured.verify());
    assert_ne!(measured.entry_hash, expected_bare.entry_hash, ">0 的耗时必须并入摘要素材");
    measured.latency_micros = 9_999;
    assert!(!measured.verify(), "改耗时必须被链校验发现");
}

#[test]
pub(crate) fn appended_records_keep_their_measured_latency() {
    let log = InterceptionAuditLog::new();
    let record = record(0).with_latency_micros(777);
    assert!(log.append(record).is_ok());
    let stored = log.records();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].latency_micros, 777, "链上必须保留真实测量值");
    assert!(log.verify().passed, "带耗时的记录仍必须通过链校验");
}

pub(crate) fn log_with(n: usize) -> InterceptionAuditLog {
    let log = InterceptionAuditLog::new();
    for i in 0..n {
        let r = InterceptionRecord::new(
            TenantId::default_tenant(),
            &format!("s-{}", i % 3),
            InterceptPoint::McpProxy,
            if i % 2 == 0 { InterceptionVerdict::Blocked } else { InterceptionVerdict::Forwarded },
            &format!("第 {i} 条"),
        )
        .with_tool("execute_shell")
        .with_excerpt("ls -la");
        assert!(log.append(r).is_ok(), "追加第 {i} 条失败");
    }
    log
}

#[test]
pub(crate) fn append_assigns_monotonic_sequence_and_links_hashes() {
    let log = log_with(5);
    let records = log.records();
    assert_eq!(records.len(), 5);
    assert_eq!(log.total(), 5);
    assert_eq!(records[0].sequence, 1);
    assert_eq!(records[0].prev_hash, GENESIS_HASH);
    for (i, r) in records.iter().enumerate() {
        assert_eq!(r.sequence, i as i64 + 1);
        if i > 0 {
            assert_eq!(r.prev_hash, records[i - 1].entry_hash, "prev_hash 必须衔接");
        }
    }
    assert_eq!(log.tail_hash(), records[4].entry_hash);
}

#[test]
pub(crate) fn chain_verifies_when_intact() {
    let log = log_with(20);
    let report = log.verify();
    assert!(report.passed, "违规: {:?}", report.violations);
    assert_eq!(report.checked, 20);
    assert_eq!(report.first_sequence, Some(1));
    assert_eq!(report.last_sequence, Some(20));
    assert!(report.tail_hash.is_some());
    assert!(report.verified_at.is_some());
    assert!(report.summary().contains("校验通过"));
}

#[test]
pub(crate) fn empty_chain_verifies() {
    let log = InterceptionAuditLog::new();
    let report = log.verify();
    assert!(report.passed);
    assert_eq!(report.checked, 0);
    assert_eq!(report.tail_hash, None);
    assert!(log.is_empty());
    assert_eq!(log.total(), 0);
}

#[test]
pub(crate) fn content_tampering_is_detected_and_breaks_chain() {
    let log = log_with(6);
    assert!(log.verify().passed);
    assert!(log.tamper_reason_for_test(2, "被篡改的原因"));
    let report = log.verify();
    assert!(!report.passed);
    assert!(report.violations.iter().any(|v| v.kind == "hash_mismatch" && v.sequence == 3));
    // 篡改导致的哈希变化还会让后一条 prev_hash 不衔接
    assert!(report.violations.iter().any(|v| v.kind == "prev_gap" && v.sequence == 4));
    assert!(report.summary().contains("校验失败"));
}

#[test]
pub(crate) fn deleting_a_middle_record_is_detected() {
    let log = log_with(6);
    assert!(log.remove_at_for_test(2));
    let report = log.verify();
    assert!(!report.passed);
    assert!(report.violations.iter().any(|v| v.kind == "prev_gap"));
    assert!(report.violations.iter().any(|v| v.kind == "sequence_gap"));
    assert_eq!(log.len(), 5);
    assert_eq!(log.total(), 6, "累计计数不因删除而回退");
}

#[test]
pub(crate) fn forging_prev_hash_is_detected() {
    let log = log_with(4);
    assert!(log.tamper_prev_hash_for_test(3, GENESIS_HASH));
    let report = log.verify();
    assert!(!report.passed);
    assert!(report.violations.iter().any(|v| v.kind == "hash_mismatch"));
    assert!(report.violations.iter().any(|v| v.kind == "prev_gap"));
}

#[test]
pub(crate) fn capacity_is_bounded_and_truncation_is_reported() {
    let log = InterceptionAuditLog::with_capacity(3);
    for i in 0..5 {
        let r = InterceptionRecord::new(
            TenantId::default_tenant(),
            "s",
            InterceptPoint::McpProxy,
            InterceptionVerdict::Forwarded,
            &format!("r{i}"),
        );
        assert!(log.append(r).is_ok());
    }
    assert_eq!(log.len(), 3, "缓冲受容量限制");
    assert_eq!(log.total(), 5, "累计计数不受容量限制");
    assert!(log.is_truncated());
    let records = log.records();
    assert_eq!(records.first().map(|r| r.sequence), Some(3));
    assert_eq!(records.last().map(|r| r.sequence), Some(5));
    // 滚出后的窗口内仍是自洽链
    let report = log.verify();
    assert!(report.passed);
    assert_eq!(report.first_sequence, Some(3));
}

#[test]
pub(crate) fn zero_capacity_falls_back_to_default() {
    let log = InterceptionAuditLog::with_capacity(0);
    let r = InterceptionRecord::new(
        TenantId::default_tenant(),
        "s",
        InterceptPoint::McpProxy,
        InterceptionVerdict::Forwarded,
        "x",
    );
    assert!(log.append(r).is_ok());
    assert_eq!(log.len(), 1, "容量 0 不得导致静默不记录");
}

#[test]
pub(crate) fn filters_and_metrics() {
    let log = log_with(9);
    assert_eq!(log.by_verdict(InterceptionVerdict::Blocked).len(), 5);
    assert_eq!(log.by_verdict(InterceptionVerdict::Forwarded).len(), 4);
    assert_eq!(log.blocked_count(), 5);
    assert_eq!(log.by_tenant(TenantId::default_tenant()).len(), 9);
    assert_eq!(log.by_tenant(TenantId::new()).len(), 0);
    assert_eq!(log.by_session("s-0").len(), 3);
    assert_eq!(log.recent(2).len(), 2);
    assert_eq!(log.recent(2)[0].sequence, 9, "recent 应最新在前");
    assert!(log.records()[0].summary_line().contains("#1"));
}

#[test]
pub(crate) fn intercept_point_is_recorded() {
    let log = InterceptionLogHelper::new();
    assert_eq!(log.record.intercept_point, InterceptPoint::ProcessHook);
}

#[test]
fn session_cursor_skips_history_and_reports_eviction() {
    let log = InterceptionAuditLog::with_capacity(4);
    log.append(record(0)).unwrap();
    let cursor = log.total();
    let mut foreign = record(0);
    foreign.tenant_id = TenantId::new();
    log.append(foreign).unwrap();
    let first = log.append(record(0)).unwrap();
    let mut other_session = record(0);
    other_session.session_id = "other".into();
    log.append(other_session).unwrap();
    let second = log.append(record(0)).unwrap();
    let tenant = TenantId::default_tenant();
    let rows = log.session_since(tenant, "s-1", cursor).unwrap();
    assert_eq!(rows.iter().map(|row| row.id).collect::<Vec<_>>(), vec![first.id, second.id]);
    assert!(log.session_since(tenant, "s-1", log.total()).unwrap().is_empty());
    assert!(log.session_since(tenant, "s-1", 0).is_err());
    log.append(record(0)).unwrap();
    assert!(log.session_since(tenant, "s-1", cursor).is_err());
}
