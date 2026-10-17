//! 由 `sla.rs` 拆分：`EPOCH`/`at` 等 19 项（纯搬移，逻辑不变）。
use super::*;

pub(crate) const EPOCH: &str = "2026-03-02T10:00:00Z";

pub(crate) fn at(offset: i64) -> Timestamp {
    Timestamp::parse_rfc3339(EPOCH).map_or_else(|_| Timestamp::now(), |t| t.offset_secs(offset))
}

pub(crate) fn clock(severity: Severity) -> SlaClock {
    SlaClock::for_severity(TenantId::default_tenant(), Id::new(), at(0), severity).expect("默认策略应合法")
}

#[test]
pub(crate) fn default_targets_are_ordered_and_escalate_with_severity() {
    let critical = SlaPolicy::for_severity(Severity::Critical);
    let info = SlaPolicy::for_severity(Severity::Info);
    assert!(critical.first_response_secs < critical.containment_secs);
    assert!(critical.containment_secs < critical.resolution_secs);
    for target in SlaTarget::all() {
        assert!(critical.target_secs(target) <= info.target_secs(target), "等级越高时限不应更长: {}", target.as_str());
    }
    assert_eq!(critical.first_response_secs, 900);
    assert_eq!(critical.target_secs(SlaTarget::Resolution), 28_800);
    assert_eq!(SlaTarget::all().len(), 3);
    assert_eq!(SlaTarget::FirstResponse.as_str(), "first-response");
    assert_eq!(critical.name, "sla-critical");
}

#[test]
pub(crate) fn pending_then_at_risk_then_breached() {
    let c = clock(Severity::High); // 首次响应 3600s，预警线 2880s
    assert_eq!(c.status(SlaTarget::FirstResponse, at(10)).status, SlaStatus::Pending);
    let risk = c.status(SlaTarget::FirstResponse, at(2_900));
    assert_eq!(risk.status, SlaStatus::AtRisk, "{risk:?}");
    assert!(risk.remaining_secs > 0);
    let breach = c.status(SlaTarget::FirstResponse, at(3_700));
    assert_eq!(breach.status, SlaStatus::Breached);
    assert!(breach.remaining_secs < 0);
    assert!(breach.summary().contains("breached"));
    assert!(c.is_breached(at(3_700)));
    assert_eq!(c.overall(at(3_700)), SlaStatus::Breached);
    assert_eq!(c.overdue_secs(at(3_700)), 100);
}

#[test]
pub(crate) fn met_within_target_is_not_a_breach() {
    let mut c = clock(Severity::High);
    c.reach(SlaTarget::FirstResponse, at(600), None).expect("达成应成功");
    let status = c.status(SlaTarget::FirstResponse, at(9_999));
    assert_eq!(status.status, SlaStatus::Met);
    assert!(!status.timed_out_before_met);
    assert!(!c.is_breached(at(9_999)), "已达成不应因后续时间流逝而违约");
}

#[test]
pub(crate) fn met_after_due_is_breached_but_reported_as_met_timeout() {
    let mut c = clock(Severity::High);
    c.reach(SlaTarget::FirstResponse, at(4_000), None).expect("达成应成功");
    let status = c.status(SlaTarget::FirstResponse, at(5_000));
    assert_eq!(status.status, SlaStatus::Breached);
    assert!(status.timed_out_before_met, "必须标明'达成但已逾期'");
    assert!(status.summary().contains("达成时已逾期"));
}

#[test]
pub(crate) fn pause_windows_extend_the_deadline() {
    let mut c = clock(Severity::High);
    // 无暂停：3700s 时已违约
    assert!(c.is_breached(at(3_700)));
    // 加 2 小时变更窗口 → 有效耗时只有 100s
    c.pause(SlaPauseWindow { from: at(100), to: at(2_100), reason: SlaPauseReason::ChangeWindow }).expect("暂停应成功");
    let status = c.status(SlaTarget::FirstResponse, at(3_700));
    assert_eq!(status.status, SlaStatus::Pending, "暂停应顺延截止: {status:?}");
    assert_eq!(status.paused_secs, 2_000);
    assert_eq!(status.effective_elapsed_secs, 1_700);
    assert_eq!(c.due_at(SlaTarget::FirstResponse), at(5_600));
    assert!(!c.is_breached(at(3_700)));
}

#[test]
pub(crate) fn pause_overlap_is_clamped_to_judgement_window() {
    let window = SlaPauseWindow { from: at(0), to: at(1_000), reason: SlaPauseReason::VendorPending };
    // 判定时刻在窗口内 → 只扣到判定时刻
    assert_eq!(pause_overlap_secs(&window, at(0), at(400)), 400);
    // 判定时刻早于窗口 → 不扣
    assert_eq!(pause_overlap_secs(&window, at(0), at(-100)), 0);
    // 完全覆盖窗口 → 全额扣除
    assert_eq!(pause_overlap_secs(&window, at(0), at(9_999)), 1_000);
    // 窗口结束早于区间 → 不扣
    assert_eq!(pause_overlap_secs(&window, at(2_000), at(3_000)), 0);
}

#[test]
pub(crate) fn illegitimate_pause_is_rejected() {
    let mut c = clock(Severity::High);
    assert!(!SlaPauseReason::Other.is_legitimate());
    assert!(SlaPauseReason::ChangeWindow.is_legitimate());
    let err = c.pause(SlaPauseWindow { from: at(0), to: at(100), reason: SlaPauseReason::Other });
    assert!(matches!(err, Err(SlaError::IllegitimatePause(_))), "Other 不能作为暂停理由: {err:?}");
    let backwards = c.pause(SlaPauseWindow { from: at(200), to: at(100), reason: SlaPauseReason::ChangeWindow });
    assert!(matches!(backwards, Err(SlaError::InvalidTime(_))));
    let before_start = c.pause(SlaPauseWindow { from: at(-500), to: at(-100), reason: SlaPauseReason::ChangeWindow });
    assert!(matches!(before_start, Err(SlaError::InvalidTime(_))), "不允许提前声明暂停");
    let mut policy = SlaPolicy::for_severity(Severity::High);
    policy.pause_windows.push(SlaPauseWindow { from: at(0), to: at(10), reason: SlaPauseReason::Other });
    assert!(matches!(policy.validate(), Err(SlaError::InvalidPolicy(_))));
}

#[test]
pub(crate) fn escalation_ladder_is_monotonic_by_overdue_seconds() {
    let c = clock(Severity::Critical); // L1@900s, L2@3600s 逾期
    assert!(c.due_escalation(at(1_000)).is_none(), "未逾期不升级");
    let l1 = c.due_escalation(at(1_000 + 900 + 1)).expect("应升 L1");
    assert_eq!(l1.level, 1);
    assert_eq!(l1.target, EscalationTarget::OnCall);
    let l2 = c.due_escalation(at(1_000 + 3_600 + 1)).expect("应升 L2");
    assert_eq!(l2.level, 2);
    assert_eq!(l2.target, EscalationTarget::IncidentCommander);
    assert_eq!(EscalationTarget::IncidentCommander.as_str(), "incident-commander");
    let next = c.next_escalation(at(1_000 + 900 + 1));
    assert_eq!(next.map(|s| s.level), Some(2), "已到 L1 时下一档是 L2");
    let info = clock(Severity::Info);
    assert!(info.due_escalation(at(999_999)).is_none(), "Info 无升级阶梯");
    assert!(info.next_escalation(at(0)).is_none());
}

#[test]
pub(crate) fn escalation_uses_earliest_breached_target() {
    let c = clock(Severity::High);
    // 2000s 时首次响应未违约（3600s），遏制也未（14400s）
    assert_eq!(c.overdue_secs(at(2_000)), 0);
    // 3700s 时首次响应逾期 100s
    assert_eq!(c.overdue_secs(at(3_700)), 100);
    // 达成首次响应后，逾期只由遏制决定
    let mut done = c.clone();
    done.reach(SlaTarget::FirstResponse, at(1_000), None).expect("达成应成功");
    assert_eq!(done.overdue_secs(at(3_700)), 0, "已达成目标不再计入逾期");
    assert_eq!(done.overdue_secs(at(15_000)), 600, "遏制逾期 600s");
}

#[test]
pub(crate) fn repeated_reach_keeps_the_earliest() {
    let mut c = clock(Severity::High);
    c.reach(SlaTarget::FirstResponse, at(500), None).expect("达成应成功");
    c.reach(SlaTarget::FirstResponse, at(5_000), None).expect("达成应成功");
    assert_eq!(c.milestone(SlaTarget::FirstResponse).map(|m| m.at), Some(at(500)));
    let early = c.reach(SlaTarget::Containment, at(-10), None);
    assert!(matches!(early, Err(SlaError::InvalidTime(_))), "达成时间不能早于起点");
    assert_eq!(c.status(SlaTarget::FirstResponse, at(999)).status, SlaStatus::Met);
}

#[test]
pub(crate) fn overall_aggregates_worst_status() {
    let mut c = clock(Severity::High);
    assert_eq!(c.overall(at(1)), SlaStatus::Pending);
    c.reach(SlaTarget::FirstResponse, at(10), None).expect("达成应成功");
    c.reach(SlaTarget::Containment, at(20), None).expect("达成应成功");
    assert_eq!(c.overall(at(30)), SlaStatus::Pending, "解决目标未达成且未预警");
    c.reach(SlaTarget::Resolution, at(40), None).expect("达成应成功");
    assert_eq!(c.overall(at(50)), SlaStatus::Met);
    let statuses = c.statuses(at(50));
    assert_eq!(statuses.len(), 3);
    assert!(statuses.iter().all(|s| s.status == SlaStatus::Met));
}

#[test]
pub(crate) fn next_due_and_case_fields() {
    let c = clock(Severity::Critical);
    let (target, due) = c.next_due_at(at(0)).expect("应有最近截止");
    assert_eq!(target, SlaTarget::FirstResponse, "最近截止应是最短的响应目标");
    assert_eq!(due, at(900));
    let (due_field, breached) = case_sla_fields(&c, at(1_000));
    assert_eq!(due_field, at(3_600), "首次响应逾期后最近截止变为遏制");
    assert!(breached);
    let mut done = c.clone();
    for t in SlaTarget::all() {
        done.reach(t, at(10), None).expect("达成应成功");
    }
    assert!(done.next_due_at(at(20)).is_none(), "全部达成后无未达截止");
    let (fallback, ok) = case_sla_fields(&done, at(20));
    assert_eq!(fallback, done.due_at(SlaTarget::Resolution));
    assert!(!ok);
}

#[test]
pub(crate) fn invalid_policy_is_rejected() {
    let mut policy = SlaPolicy::for_severity(Severity::High);
    policy.first_response_secs = 0;
    assert!(matches!(policy.validate(), Err(SlaError::InvalidPolicy(_))));
    let mut policy = SlaPolicy::for_severity(Severity::High);
    policy.warning_ratio = 1.5;
    assert!(matches!(policy.validate(), Err(SlaError::InvalidPolicy(_))));
    let mut policy = SlaPolicy::for_severity(Severity::High);
    policy.escalation = vec![
        EscalationStep { level: 2, overdue_secs: 10, target: EscalationTarget::OnCall },
        EscalationStep { level: 1, overdue_secs: 20, target: EscalationTarget::OnCall },
    ];
    assert!(matches!(policy.validate(), Err(SlaError::InvalidPolicy(_))));
    assert!(SlaClock::new(TenantId::default_tenant(), Id::new(), at(0), policy).is_err());
}

#[test]
pub(crate) fn policy_add_pause_refuses_other_reason() {
    let mut policy = SlaPolicy::for_severity(Severity::Low);
    assert!(policy.add_pause(SlaPauseWindow { from: at(0), to: at(10), reason: SlaPauseReason::AwaitingApproval }));
    assert!(!policy.add_pause(SlaPauseWindow { from: at(0), to: at(10), reason: SlaPauseReason::Other }));
    assert_eq!(policy.pause_windows.len(), 1);
    assert_eq!(SlaPauseReason::AwaitingApproval.as_str(), "awaiting-approval");
}

#[test]
pub(crate) fn tenant_isolation_is_enforced() {
    let c = clock(Severity::High);
    assert!(c.ensure_tenant(TenantId::default_tenant()).is_ok());
    let err = c.ensure_tenant(TenantId::new());
    assert!(matches!(err, Err(SlaError::TenantViolation { .. })), "跨租户必须报错: {err:?}");
}

#[test]
pub(crate) fn total_pause_extends_all_deadlines() {
    let mut c = clock(Severity::Critical);
    c.pause(SlaPauseWindow { from: at(0), to: at(300), reason: SlaPauseReason::BusinessConfirmation })
        .expect("暂停应成功");
    assert_eq!(c.total_paused_secs(), 300);
    assert_eq!(c.due_at(SlaTarget::FirstResponse), at(1_200));
    assert_eq!(c.due_at(SlaTarget::Containment), at(3_900));
    // 预警线随暂停一起顺延：900s 目标 × 0.8 = 720s 有效耗时 ⇒ 墙钟 300 + 720 = 1020s。
    assert_eq!(c.status(SlaTarget::FirstResponse, at(1_000)).status, SlaStatus::Pending);
    assert_eq!(c.status(SlaTarget::FirstResponse, at(1_100)).status, SlaStatus::AtRisk);
}
