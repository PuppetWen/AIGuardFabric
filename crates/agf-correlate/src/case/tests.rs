//! 由 `case.rs` 拆分：`at` 等 17 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn at(offset: i64) -> Timestamp {
    Timestamp::parse_rfc3339("2026-03-02T10:00:00Z").map_or_else(|_| Timestamp::now(), |t| t.offset_secs(offset))
}

pub(crate) fn cluster_of(tenant: TenantId, title: &str, severity: Severity, occurrences: usize) -> EventCluster {
    let mut agg = AlertAggregator::new(AggregationConfig::default(), Vec::new()).expect("配置合法");
    for i in 0..occurrences {
        let input = AlertInput::new(tenant, "model-data", severity, title, at(i as i64))
            .with_entity("t|host|ws-01")
            .with_tag("MD-EXFIL-001");
        agg.ingest(input).expect("摄入应成功");
    }
    agg.report(tenant, at(1_000)).expect("租户匹配").clusters.remove(0)
}

#[test]
pub(crate) fn promote_cluster_creates_case_with_timeline() {
    let t = TenantId::default_tenant();
    let cluster = cluster_of(t, "数据外传", Severity::High, 3);
    let mut manager = CaseManager::new().with_default_owner("soc-oncall");
    let detail = manager.promote_cluster(t, &cluster, 2, "system", at(10)).expect("升级应成功");
    let detail = detail.clone();
    assert_eq!(detail.case.state, CaseState::New);
    assert_eq!(detail.case.severity, Severity::High);
    assert_eq!(detail.case.owner.as_deref(), Some("soc-oncall"));
    assert!(detail.case.code.starts_with("CASE-2026-"));
    assert_eq!(detail.timeline_len(), 1);
    assert_eq!(detail.timeline[0].kind, TimelineKind::Created);
    assert!(detail.case.security_incident, "高危应标记安全事件");
    assert!(!detail.timeline[0].is_automated());
    assert!(detail.timeline[0].render().contains("created"));
}

#[test]
pub(crate) fn severity_policy_escalates_on_spread_and_repeat() {
    let t = TenantId::default_tenant();
    let policy = CaseSeverityPolicy::default();
    let cluster = cluster_of(t, "数据外传", Severity::Medium, 2);
    assert_eq!(policy.derive(&cluster, 1), Severity::Medium);
    assert_eq!(policy.derive(&cluster, 3), Severity::High, "影响面扩散应提升");
    let noisy = cluster_of(t, "数据外传", Severity::Medium, 60);
    assert_eq!(policy.derive(&noisy, 1), Severity::High, "高重复应提升");
    assert_eq!(policy.derive(&noisy, 9), Severity::High, "已到 High 再提升到 Critical");
    let mut capped = cluster_of(t, "数据外传", Severity::Critical, 60);
    capped.severity = Severity::Critical;
    assert_eq!(policy.derive(&capped, 99), Severity::Critical, "Critical 为上限");
    let off = CaseSeverityPolicy { escalate_on_spread: false, ..CaseSeverityPolicy::default() };
    assert_eq!(off.derive(&noisy, 99), Severity::Medium);
}

#[test]
pub(crate) fn legal_transition_chain_and_timeline_order() {
    let t = TenantId::default_tenant();
    let mut manager = CaseManager::new();
    let id = manager.create(t, "疑似外传", Severity::High, None, "analyst", at(0)).expect("创建应成功").case.id;
    manager.transition(t, id, CaseState::Investigating, "analyst", "", at(10)).expect("迁移应成功");
    manager.transition(t, id, CaseState::Containing, "analyst", "", at(20)).expect("迁移应成功");
    manager.transition(t, id, CaseState::Resolved, "analyst", "", at(30)).expect("迁移应成功");
    let detail = manager.transition(t, id, CaseState::Closed, "analyst", "", at(40)).expect("迁移应成功").clone();
    assert!(detail.is_closed());
    assert_eq!(detail.case.closed_at, Some(at(40)));
    assert_eq!(detail.timeline_len(), 5);
    assert_eq!(detail.timeline[4].kind, TimelineKind::Closed);
    // 时间线严格升序
    assert!(detail.timeline.windows(2).all(|w| w[0].at <= w[1].at && w[0].seq < w[1].seq));
}

#[test]
pub(crate) fn illegal_transition_is_rejected() {
    let t = TenantId::default_tenant();
    let mut manager = CaseManager::new();
    let id = manager.create(t, "案件", Severity::Medium, None, "a", at(0)).expect("创建应成功").case.id;
    let err = manager.transition(t, id, CaseState::Closed, "a", "", at(1));
    assert!(matches!(err, Err(CaseError::IllegalTransition { .. })), "new → closed 必须被拒: {err:?}");
    manager.transition(t, id, CaseState::Investigating, "a", "", at(2)).expect("迁移应成功");
    manager.transition(t, id, CaseState::Resolved, "a", "", at(3)).expect("迁移应成功");
    manager.transition(t, id, CaseState::Closed, "a", "", at(4)).expect("迁移应成功");
    let reopened = manager.transition(t, id, CaseState::Investigating, "a", "", at(5));
    assert!(matches!(reopened, Err(CaseError::IllegalTransition { .. })), "closed 不可复活: {reopened:?}");
    assert!(allowed_transitions(CaseState::Closed).is_empty());
    assert_eq!(allowed_transitions(CaseState::New).len(), 2);
    let missing = manager.transition(t, Id::new(), CaseState::Investigating, "a", "", at(6));
    assert!(matches!(missing, Err(CaseError::NotFound(_))));
}

#[test]
pub(crate) fn resolved_can_reopen_for_investigation() {
    let t = TenantId::default_tenant();
    let mut manager = CaseManager::new();
    let id = manager.create(t, "案件", Severity::Low, None, "a", at(0)).expect("创建应成功").case.id;
    manager.transition(t, id, CaseState::Investigating, "a", "", at(1)).expect("迁移应成功");
    manager.transition(t, id, CaseState::Resolved, "a", "", at(2)).expect("迁移应成功");
    manager.transition(t, id, CaseState::Investigating, "a", "复核发现新证据", at(3)).expect("重开应成功");
    let detail = manager.snapshot(t, id).expect("存在");
    assert_eq!(detail.case.state, CaseState::Investigating);
}

#[test]
pub(crate) fn tenant_isolation_on_case_access() {
    let t1 = TenantId::default_tenant();
    let t2 = TenantId::new();
    let mut manager = CaseManager::new();
    let id = manager.create(t1, "案件", Severity::Medium, None, "a", at(0)).expect("创建应成功").case.id;
    let err = manager.get(t2, id);
    assert!(matches!(err, Err(CaseError::TenantViolation { .. })), "跨租户读取必须报错: {err:?}");
    assert!(manager.snapshot(t2, id).is_err());
    assert!(manager.transition(t2, id, CaseState::Investigating, "a", "", at(1)).is_err());
    assert!(manager.assign(t2, id, "bob", "a", at(1)).is_err());
    assert!(manager.list(t2).is_empty(), "列表按租户过滤");
    assert_eq!(manager.list(t1).len(), 1);
    assert_eq!(manager.count_by_state(t1, CaseState::New), 1);
    assert!(manager.get(t1, Id::new()).expect("不存在返回 Ok(None)").is_none());
}

#[test]
pub(crate) fn merge_combines_evidence_and_closes_sources() {
    let t = TenantId::default_tenant();
    let mut manager = CaseManager::new();
    let target = manager.create(t, "主案", Severity::Medium, None, "a", at(0)).expect("创建应成功").case.id;
    let source = manager.create(t, "从案", Severity::Critical, None, "a", at(1)).expect("创建应成功").case.id;
    let f1 = Id::new();
    let f2 = Id::new();
    manager.attach_finding(t, target, f1, "a", at(2)).expect("关联应成功");
    manager.attach_finding(t, source, f1, "a", at(3)).expect("关联应成功");
    manager.attach_finding(t, source, f2, "a", at(4)).expect("关联应成功");
    let plan = manager.merge(t, target, &[source], "lead", at(5)).expect("合并应成功");
    assert_eq!(plan.involved(), 2);
    assert_eq!(plan.target.severity, Severity::Critical, "取最高等级");
    assert_eq!(plan.target.finding_ids.len(), 2);
    assert_eq!(plan.unmoved_findings, vec![f1], "重复 finding 应显式报告");
    assert_eq!(plan.sources[0].state, CaseState::Closed);
    let target_detail = manager.snapshot(t, target).expect("存在");
    assert_eq!(target_detail.timeline.last().map(|e| e.kind), Some(TimelineKind::Merged));
    let source_detail = manager.snapshot(t, source).expect("存在");
    assert!(source_detail.is_closed());
    assert_eq!(source_detail.timeline.last().map(|e| e.kind), Some(TimelineKind::Merged));
    assert!(source_detail.case.resolution.as_deref().is_some_and(|r| r.contains("已合并入")));
}

#[test]
pub(crate) fn merge_rejects_illegal_inputs() {
    let t = TenantId::default_tenant();
    let other = TenantId::new();
    let mut manager = CaseManager::new();
    let a = manager.create(t, "A", Severity::Low, None, "x", at(0)).expect("创建应成功").case.id;
    let b = manager.create(t, "B", Severity::Low, None, "x", at(1)).expect("创建应成功").case.id;
    assert!(matches!(manager.merge(t, a, &[], "x", at(2)), Err(CaseError::InvalidInput(_))));
    assert!(matches!(manager.merge(t, a, &[a], "x", at(2)), Err(CaseError::InvalidInput(_))));
    manager.transition(t, b, CaseState::Investigating, "x", "", at(3)).expect("迁移应成功");
    manager.transition(t, b, CaseState::Resolved, "x", "", at(4)).expect("迁移应成功");
    manager.transition(t, b, CaseState::Closed, "x", "", at(5)).expect("迁移应成功");
    assert!(matches!(manager.merge(t, a, &[b], "x", at(6)), Err(CaseError::StateConflict { .. })));
    let c = manager.create(other, "C", Severity::Low, None, "x", at(7)).expect("创建应成功").case.id;
    assert!(matches!(manager.merge(t, a, &[c], "x", at(8)), Err(CaseError::TenantViolation { .. })));
}

#[test]
pub(crate) fn split_creates_children_and_reports_unassigned() {
    let t = TenantId::default_tenant();
    let mut manager = CaseManager::new();
    let parent = manager.create(t, "总案", Severity::Critical, None, "a", at(0)).expect("创建应成功").case.id;
    let f1 = Id::new();
    let f2 = Id::new();
    let f3 = Id::new();
    for (i, f) in [f1, f2, f3].iter().enumerate() {
        manager.attach_finding(t, parent, *f, "a", at(i as i64 + 1)).expect("关联应成功");
    }
    let specs = vec![
        SubCaseSpec { finding_ids: vec![f1], ..SubCaseSpec::new("外传子案", Severity::High) },
        SubCaseSpec { finding_ids: vec![f2], ..SubCaseSpec::new("凭据子案", Severity::Medium) },
    ];
    let plan = manager.split(t, parent, &specs, "lead", at(10)).expect("拆分应成功");
    assert_eq!(plan.child_count(), 2);
    assert_eq!(plan.children[0].code, format!("{}-S1", plan.parent.code));
    assert_eq!(plan.assigned_findings.len(), 2);
    assert_eq!(plan.unassigned_findings, vec![f3], "未分配 finding 必须显式列出");
    assert_eq!(plan.parent.severity, Severity::Critical, "父案等级不降低");
    assert!(plan.parent.summary.contains("已拆分为 2 个子案"));
    let child_detail = manager.snapshot(t, plan.children[0].id).expect("子案已登记");
    assert_eq!(child_detail.case.state, CaseState::New);
    assert_eq!(child_detail.findings, vec![f1]);
    assert_eq!(child_detail.timeline[0].kind, TimelineKind::Split);
    assert!(child_detail.case.tags.contains(&format!("split-from:{}", plan.parent.code)));
    assert_eq!(manager.count_by_state(t, CaseState::New), 3);
}

#[test]
pub(crate) fn split_rejects_empty_specs_and_duplicate_titles() {
    let t = TenantId::default_tenant();
    let mut manager = CaseManager::new();
    let id = manager.create(t, "总案", Severity::High, None, "a", at(0)).expect("创建应成功").case.id;
    assert!(matches!(manager.split(t, id, &[], "a", at(1)), Err(CaseError::InvalidInput(_))));
    let dup = vec![SubCaseSpec::new("同名", Severity::Low), SubCaseSpec::new(" 同名 ", Severity::High)];
    assert!(matches!(manager.split(t, id, &dup, "a", at(2)), Err(CaseError::InvalidInput(_))));
    let blank = vec![SubCaseSpec::new("   ", Severity::Low)];
    assert!(matches!(manager.split(t, id, &blank, "a", at(3)), Err(CaseError::InvalidInput(_))));
    assert!(matches!(
        plan_split(t, &manager.snapshot(t, id).expect("存在").case, &[], at(4)),
        Err(CaseError::InvalidInput(_))
    ));
}

#[test]
pub(crate) fn assign_comment_escalate_and_sla_marking() {
    let t = TenantId::default_tenant();
    let mut manager = CaseManager::new();
    let id = manager.create(t, "案件", Severity::High, None, "system", at(0)).expect("创建应成功").case.id;
    assert!(manager.assign(t, id, "  ", "a", at(1)).is_err(), "空负责人应被拒");
    manager.assign(t, id, " bob ", "a", at(2)).expect("指派应成功");
    manager.comment(t, id, "soar", "已隔离 Agent", true, at(3)).expect("评论应成功");
    let level = manager.escalate(t, id, "超 SLA", "system", at(4)).expect("升级应成功");
    assert_eq!(level, 1);
    let level2 = manager.escalate(t, id, "", "system", at(5)).expect("升级应成功");
    assert_eq!(level2, 2);
    manager.mark_sla(t, id, at(3_600), true, at(6)).expect("回写应成功");
    let detail = manager.snapshot(t, id).expect("存在");
    assert_eq!(detail.case.owner.as_deref(), Some("bob"));
    assert!(detail.is_overdue());
    assert!(!detail.is_unassigned());
    assert!(detail.timeline.iter().any(CaseTimelineEvent::is_automated));
    assert_eq!(detail.timeline_len(), 6);
    assert_eq!(TimelineKind::Merged.to_core_kind(), CaseEventKind::StateChanged);
    assert_eq!(TimelineKind::Closed.to_core_kind(), CaseEventKind::Closed);
}

#[test]
pub(crate) fn closed_case_cannot_be_assigned_or_escalated() {
    let t = TenantId::default_tenant();
    let mut manager = CaseManager::new();
    let id = manager.create(t, "案件", Severity::Low, None, "a", at(0)).expect("创建应成功").case.id;
    manager.transition(t, id, CaseState::Investigating, "a", "", at(1)).expect("迁移应成功");
    manager.transition(t, id, CaseState::Resolved, "a", "", at(2)).expect("迁移应成功");
    manager.transition(t, id, CaseState::Closed, "a", "", at(3)).expect("迁移应成功");
    assert!(matches!(manager.assign(t, id, "bob", "a", at(4)), Err(CaseError::StateConflict { .. })));
    assert!(matches!(manager.escalate(t, id, "", "a", at(5)), Err(CaseError::StateConflict { .. })));
}

#[test]
pub(crate) fn attach_finding_is_idempotent() {
    let t = TenantId::default_tenant();
    let mut manager = CaseManager::new();
    let id = manager.create(t, "案件", Severity::Low, None, "a", at(0)).expect("创建应成功").case.id;
    let f = Id::new();
    assert_eq!(manager.attach_finding(t, id, f, "a", at(1)).expect("关联应成功"), 1);
    assert_eq!(manager.attach_finding(t, id, f, "a", at(2)).expect("关联应成功"), 0, "重复关联不新增");
    let detail = manager.snapshot(t, id).expect("存在");
    assert_eq!(detail.findings, vec![f]);
    assert_eq!(detail.case.finding_ids, vec![f]);
}

#[test]
pub(crate) fn register_is_guarded_and_rebuilds_sequence() {
    let t = TenantId::default_tenant();
    let mut manager = CaseManager::new();
    let cluster = cluster_of(t, "数据外传", Severity::High, 1);
    let detail = manager.promote_cluster(t, &cluster, 1, "system", at(0)).expect("升级应成功").clone();
    let err = manager.register(detail.case.clone(), Vec::new(), Vec::new());
    assert!(matches!(err, Err(CaseError::Duplicate(_))));
    // 外部案件编号应推动内存序列，避免重号。
    let external = {
        let mut c = detail.case.clone();
        c.id = Id::new();
        c.code = Case::make_code(2026, 42);
        c
    };
    manager.register(external, Vec::new(), Vec::new()).expect("登记应成功");
    let next = manager.create(t, "新案", Severity::Low, None, "a", at(1)).expect("创建应成功").clone();
    assert_eq!(next.case.code, Case::make_code(2026, 43), "编号必须不重号");
    assert_eq!(manager.len(), 3);
    assert!(!manager.is_empty());
}

#[test]
pub(crate) fn promote_cluster_rejects_cross_tenant_and_empty_title() {
    let t1 = TenantId::default_tenant();
    let t2 = TenantId::new();
    let cluster = cluster_of(t1, "数据外传", Severity::High, 1);
    let mut manager = CaseManager::new();
    assert!(matches!(
        manager.promote_cluster(t2, &cluster, 1, "system", at(0)),
        Err(CaseError::TenantViolation { .. })
    ));
    let mut empty = cluster.clone();
    empty.representative_title = "   ".to_string();
    assert!(matches!(manager.promote_cluster(t1, &empty, 1, "system", at(0)), Err(CaseError::InvalidInput(_))));
    assert!(manager.promote_cluster(t1, &cluster, 1, "system", at(0)).is_ok());
    let detail = manager.list(t1).remove(0);
    assert!(detail.case.summary.contains("model-data"));
    assert_eq!(detail.case.tags, vec!["MD-EXFIL-001".to_string()]);
    assert!(!RiskDomain::all().is_empty());
}
