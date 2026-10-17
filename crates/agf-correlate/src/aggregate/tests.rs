//! 由 `aggregate.rs` 拆分：`EPOCH`/`at` 等 22 项（纯搬移，逻辑不变）。
use super::*;

pub(crate) const EPOCH: &str = "2026-03-02T10:00:00Z";

pub(crate) fn at(offset: i64) -> Timestamp {
    Timestamp::parse_rfc3339(EPOCH).map_or_else(|_| Timestamp::now(), |t| t.offset_secs(offset))
}

pub(crate) fn input(tenant: TenantId, title: &str, at: Timestamp) -> AlertInput {
    AlertInput::new(tenant, "prompt-attack", Severity::High, title, at).with_entity("t|host|ws-01")
}

#[test]
pub(crate) fn duplicate_alerts_only_increment_counter() {
    let t = TenantId::default_tenant();
    let mut agg = AlertAggregator::with_defaults().expect("默认配置应合法");
    for i in 0..5 {
        agg.ingest(input(t, "提示词注入尝试", at(i))).expect("摄入应成功");
    }
    assert_eq!(agg.cluster_count(), 1, "完全相同的告警只应产生一个簇");
    let report = agg.report(t, at(10)).expect("租户匹配");
    assert_eq!(report.raw_alerts, 5);
    assert_eq!(report.deduped_alerts, 1, "去重后只算 1 条");
    assert_eq!(report.clusters[0].occurrences, 5);
    assert_eq!(report.clusters[0].dedup_count, 1);
    assert!((report.noise_reduction_ratio() - 0.8).abs() < 1e-9);
    assert!((report.clusters[0].repeat_factor() - 5.0).abs() < 1e-9);
}

#[test]
pub(crate) fn similar_titles_within_window_merge_into_one_cluster() {
    let t = TenantId::default_tenant();
    let mut agg = AlertAggregator::with_defaults().expect("默认配置应合法");
    agg.ingest(input(t, "检测到提示词注入尝试 A", at(0))).expect("摄入应成功");
    agg.ingest(input(t, "检测到提示词注入尝试 B", at(30))).expect("摄入应成功");
    agg.ingest(input(t, "完全无关的磁盘告警", at(31))).expect("摄入应成功");
    let report = agg.report(t, at(60)).expect("租户匹配");
    assert_eq!(report.clusters.len(), 2, "相似标题应合并，无关标题应独立: {report:?}");
    assert_eq!(report.deduped_alerts, 2);
}

#[test]
pub(crate) fn outside_window_is_not_merged() {
    let t = TenantId::default_tenant();
    let mut agg =
        AlertAggregator::new(AggregationConfig::default().with_window_secs(60), Vec::new()).expect("配置合法");
    agg.ingest(input(t, "提示词注入尝试", at(0))).expect("摄入应成功");
    agg.ingest(input(t, "提示词注入尝试", at(120))).expect("摄入应成功");
    let report = agg.report(t, at(200)).expect("租户匹配");
    assert_eq!(report.clusters.len(), 2, "窗外应新建簇");
}

#[test]
pub(crate) fn exact_policy_does_not_merge_near_titles() {
    let t = TenantId::default_tenant();
    let config = AggregationConfig::default().with_similarity(SimilarityPolicy::Exact);
    let mut agg = AlertAggregator::new(config, Vec::new()).expect("配置合法");
    agg.ingest(input(t, "提示词注入尝试 A", at(0))).expect("摄入应成功");
    agg.ingest(input(t, "提示词注入尝试 B", at(1))).expect("摄入应成功");
    assert_eq!(agg.cluster_count(), 2);
    // 本用例的**实质断言**是上面这句：Exact 策略下"提示词注入尝试 A"与"…B"不合并。
    // 下面的相似度只用于说明"高相似 ≠ 可合并"。阈值按该输入的**理论上限**取：
    // 归一化后 s1={提示,示词,词注,注入,入尝,尝试,试A}、s2={…,试B}，
    // 交集 6、并集 8 → Jaccard = 6/8 = 0.75，**任何** 2-gram Jaccard 实现都不可能超过它。
    // （原先写 >0.9 是断言写错，不是实现有 bug；已核算：0.75 恰为该输入的上限。）
    let sim = jaccard_similarity(&normalize_title("提示词注入尝试 A"), &normalize_title("提示词注入尝试 B"));
    assert!(sim >= 0.7, "字符 2-gram 相似度应达到该输入的理论上限附近: {sim}");
    assert!(sim <= 0.8, "两个仅尾字符不同的中文标题，其 2-gram Jaccard 不应虚高: {sim}");
}

#[test]
pub(crate) fn different_category_never_merges() {
    let t = TenantId::default_tenant();
    let mut agg = AlertAggregator::with_defaults().expect("默认配置应合法");
    agg.ingest(input(t, "提示词注入尝试", at(0))).expect("摄入应成功");
    let other =
        AlertInput::new(t, "credential-leak", Severity::High, "提示词注入尝试", at(1)).with_entity("t|host|ws-01");
    agg.ingest(other).expect("摄入应成功");
    assert_eq!(agg.cluster_count(), 2, "类目不同不应聚合");
}

#[test]
pub(crate) fn entity_scope_can_be_disabled() {
    let t = TenantId::default_tenant();
    let config = AggregationConfig::default().without_entity_scope();
    let mut agg = AlertAggregator::new(config, Vec::new()).expect("配置合法");
    agg.ingest(input(t, "提示词注入尝试", at(0))).expect("摄入应成功");
    agg.ingest(input(t, "提示词注入尝试", at(1)).with_entity("t|host|ws-02")).expect("摄入应成功");
    assert_eq!(agg.cluster_count(), 1, "关闭实体分簇后应合并");
    let scoped = AlertAggregator::with_defaults().expect("默认配置应合法");
    let mut scoped = scoped;
    scoped.ingest(input(t, "提示词注入尝试", at(0))).expect("摄入应成功");
    scoped.ingest(input(t, "提示词注入尝试", at(1)).with_entity("t|host|ws-02")).expect("摄入应成功");
    assert_eq!(scoped.cluster_count(), 2, "默认按实体分簇");
}

#[test]
pub(crate) fn cross_tenant_alerts_never_merge() {
    let t1 = TenantId::default_tenant();
    let t2 = TenantId::new();
    let mut agg = AlertAggregator::with_defaults().expect("默认配置应合法");
    agg.ingest(input(t1, "提示词注入尝试", at(0))).expect("摄入应成功");
    agg.ingest(input(t2, "提示词注入尝试", at(0))).expect("摄入应成功");
    assert_eq!(agg.cluster_count(), 2, "跨租户绝不聚合");
    let err = agg.report(t1, at(1));
    assert!(
        matches!(err, Err(AggregateError::TenantViolation { .. })),
        "声明租户与数据不符时必须报错而不是静默过滤: {err:?}"
    );
}

#[test]
pub(crate) fn suppression_marks_child_and_keeps_evidence() {
    let t = TenantId::default_tenant();
    let rule = SuppressionRule::new("SUP-ISOLATED", "主机已隔离，后续外传尝试降噪")
        .parent_titles(&["已隔离"])
        .child_titles(&["外传"])
        .require_same_entity();
    let mut agg = AlertAggregator::new(AggregationConfig::default(), vec![rule]).expect("规则合法");
    agg.ingest(input(t, "主机已隔离完成", at(0))).expect("摄入应成功");
    agg.ingest(input(t, "检测到数据外传尝试", at(1))).expect("摄入应成功");
    let report = agg.report(t, at(2)).expect("租户匹配");
    assert_eq!(report.suppressed().len(), 1);
    let child = report.suppressed()[0];
    assert_eq!(child.suppress_rule.as_deref(), Some("SUP-ISOLATED"));
    assert!(child.suppress_reason.as_deref().is_some_and(|r| r.contains("已隔离")));
    assert!(child.suppressed_by.is_some(), "必须记录抑制来源簇");
    assert_eq!(report.suppressed_alerts, 1);
    assert_eq!(report.actionable().len(), 1, "父簇仍可行动");
    assert!(child.summary().contains("已抑制"));
}

#[test]
pub(crate) fn cross_tenant_suppression_is_refused() {
    let t1 = TenantId::default_tenant();
    let t2 = TenantId::new();
    // 规则本身不限制租户：隔离必须由代码里的租户守卫保证。
    let rule = SuppressionRule::new("SUP-ANY", "等级压制")
        .parent_min_severity(Severity::Critical)
        .child_max_severity(Severity::Low);
    let mut agg = AlertAggregator::new(AggregationConfig::default(), vec![rule]).expect("规则合法");
    let parent =
        AlertInput::new(t1, "prompt-attack", Severity::Critical, "严重事件", at(0)).with_entity("t|host|ws-01");
    let child = AlertInput::new(t2, "prompt-attack", Severity::Low, "低级事件", at(1)).with_entity("t|host|ws-01");
    agg.ingest(parent).expect("摄入应成功");
    agg.ingest(child).expect("摄入应成功");
    // 观察口径：`report` 的租户守卫要求聚合器内不得混有他租户的簇
    // （见 `cross_tenant_alerts_never_merge`：声明租户与数据不符必须报错而不是静默过滤），
    // 因此这里直接从状态里核对"两个租户的簇都没有被抑制"——比逐租户视角更严。
    let all: Vec<&EventCluster> = agg.state().open.values().chain(agg.state().closed.iter()).collect();
    assert!(all.iter().all(|c| !c.suppressed), "跨租户不得抑制: {all:?}");
    assert!(all.iter().any(|c| c.tenant_id == t1), "t1 的父簇应存在");
    assert!(all.iter().any(|c| c.tenant_id == t2), "t2 的子簇应存在");
}

#[test]
pub(crate) fn suppression_requires_shared_rule_key_when_configured() {
    let t = TenantId::default_tenant();
    let rule =
        SuppressionRule::new("SUP-RK", "同规则重复压制").parent_min_severity(Severity::High).require_shared_rule_key();
    let mut agg = AlertAggregator::new(AggregationConfig::default(), vec![rule]).expect("规则合法");
    agg.ingest(input(t, "严重告警一", at(0)).with_rule_key("R-1")).expect("摄入应成功");
    agg.ingest(input(t, "低级告警二", at(1)).with_rule_key("R-2")).expect("摄入应成功");
    let report = agg.report(t, at(2)).expect("租户匹配");
    assert!(report.suppressed().is_empty(), "规则键不同不应抑制");
}

#[test]
pub(crate) fn invalid_config_and_rule_are_rejected() {
    let bad_window = AggregationConfig::default().with_window_secs(0);
    assert!(matches!(bad_window.validate(), Err(AggregateError::InvalidConfig(_))));
    let bad_sim = AggregationConfig::default().with_similarity_threshold(1.5);
    assert!(matches!(bad_sim.validate(), Err(AggregateError::InvalidConfig(_))));
    assert!(AlertAggregator::new(bad_window, Vec::new()).is_err());

    let no_constraint = SuppressionRule::new("SUP-EMPTY", "无约束");
    assert!(matches!(no_constraint.validate(), Err(AggregateError::InvalidRule(_))));
    let no_reason = SuppressionRule { reason: String::new(), ..no_constraint.clone() };
    assert!(matches!(no_reason.validate(), Err(AggregateError::InvalidRule(_))));
    assert!(AlertAggregator::new(AggregationConfig::default(), vec![no_constraint]).is_err());
}

#[test]
pub(crate) fn flush_moves_expired_clusters_and_is_idempotent() {
    let t = TenantId::default_tenant();
    let mut agg =
        AlertAggregator::new(AggregationConfig::default().with_window_secs(60), Vec::new()).expect("配置合法");
    agg.ingest(input(t, "提示词注入尝试", at(0))).expect("摄入应成功");
    assert_eq!(agg.flush(at(30)), 0, "窗内不刷新");
    assert_eq!(agg.flush(at(90)), 1, "窗外应刷新");
    assert_eq!(agg.flush(at(200)), 0, "刷新是幂等的");
    assert_eq!(agg.state().closed.len(), 1);
    assert!(agg.state().open.is_empty());
}

#[test]
pub(crate) fn dedup_key_and_normalization_are_stable() {
    let t = TenantId::default_tenant();
    let a = input(t, "  提示词  注入!! ", at(0));
    let b = input(t, "提示词 注入", at(0));
    assert_eq!(a.dedup_key(), b.dedup_key(), "标点/空白差异不应产生新指纹");
    assert_eq!(normalize_title("A-B_C"), "a b c");
    assert_eq!(normalize_title("   "), "");
    assert!(char_bigrams("").is_empty());
    assert_eq!(char_bigrams("a"), BTreeSet::from(["a".to_string()]));
    assert_eq!(jaccard_similarity("", "x"), 0.0, "空标题不与任何标题相似");
    assert!((jaccard_similarity("abc", "abc") - 1.0).abs() < 1e-9);
}

#[test]
pub(crate) fn cluster_truncation_is_flagged_not_silent() {
    let t = TenantId::default_tenant();
    let config = AggregationConfig { max_alerts_per_cluster: 2, ..AggregationConfig::default() };
    let mut agg = AlertAggregator::new(config, Vec::new()).expect("配置合法");
    for i in 0..5 {
        let mut item = input(t, "提示词注入尝试", at(i));
        item.tags.push(format!("tag-{i}"));
        agg.ingest(item).expect("摄入应成功");
    }
    let report = agg.report(t, at(10)).expect("租户匹配");
    let cluster = &report.clusters[0];
    assert_eq!(cluster.occurrences, 5);
    assert_eq!(cluster.dedup_count, 2, "明细受限");
    assert!(cluster.truncated, "截断必须显式标记，不能静默");
}

#[test]
pub(crate) fn cluster_severity_only_escalates() {
    let t = TenantId::default_tenant();
    let mut agg = AlertAggregator::with_defaults().expect("默认配置应合法");
    agg.ingest(AlertInput::new(t, "prompt-attack", Severity::Low, "提示词注入尝试", at(0)).with_entity("e"))
        .expect("摄入应成功");
    agg.ingest(AlertInput::new(t, "prompt-attack", Severity::Critical, "提示词注入尝试", at(1)).with_entity("e"))
        .expect("摄入应成功");
    agg.ingest(AlertInput::new(t, "prompt-attack", Severity::Low, "提示词注入尝试", at(2)).with_entity("e"))
        .expect("摄入应成功");
    let report = agg.report(t, at(3)).expect("租户匹配");
    assert_eq!(report.clusters[0].severity, Severity::Critical, "簇等级只升不降");
    assert_eq!(report.max_severity(), Some(Severity::Critical));
    assert_eq!(report.affected_entities(), vec!["e".to_string()]);
}

#[test]
pub(crate) fn empty_report_is_zero_not_perfect() {
    let t = TenantId::default_tenant();
    let agg = AlertAggregator::with_defaults().expect("默认配置应合法");
    let report = agg.report(t, at(0)).expect("租户匹配");
    assert_eq!(report.raw_alerts, 0);
    assert_eq!(report.noise_reduction_ratio(), 0.0, "无输入不代表降噪 100%");
    assert!(report.max_severity().is_none());
}

#[test]
pub(crate) fn alert_projection_and_tenant_guard() {
    let t = TenantId::default_tenant();
    let now = at(0);
    let alert = Alert {
        id: Id::new(),
        tenant_id: t,
        title: "数据外传".into(),
        description: String::new(),
        severity: Severity::High,
        domain: Some(RiskDomain::ModelData),
        state: AlertState::Open,
        finding_ids: vec![],
        dedup_count: 1,
        dedup_key: "k".into(),
        asset_ids: vec![],
        event_ids: vec![Id::new()],
        affected_hosts: vec!["ws-01".into()],
        first_seen_at: now,
        last_seen_at: now,
        assignee: None,
        case_id: None,
        escalation_level: 0,
        sla_due_at: None,
        sla_breached: false,
        tags: vec!["MD-EXFIL-001".into()],
        created_at: now,
        updated_at: now,
    };
    let projected = AlertInput::from_alert(&alert, Some("t|host|ws-01"));
    assert_eq!(projected.category, "model-data");
    assert_eq!(projected.alert_id, Some(alert.id));
    assert!(projected.dedup_key().contains("t|host|ws-01"));
    assert!(alert_belongs_to(&alert, t));
    assert!(!alert_belongs_to(&alert, TenantId::new()));
}

#[test]
pub(crate) fn reduce_once_is_convenient_and_consistent() {
    let t = TenantId::default_tenant();
    let inputs = vec![input(t, "提示词注入尝试", at(0)), input(t, "提示词注入尝试", at(1))];
    let report = reduce_once(t, &inputs, AggregationConfig::default(), at(5)).expect("单次聚合应成功");
    assert_eq!(report.clusters.len(), 1);
    assert_eq!(report.raw_alerts, 2);
    assert!(!report.clusters[0].summary().is_empty());
}

#[test]
pub(crate) fn suppression_kind_and_rule_serde() {
    let rule = SuppressionRule::new("S1", "r").parent_min_severity(Severity::High);
    assert_eq!(rule.kind(), SuppressionKind::Severity);
    let rule2 = SuppressionRule::new("S2", "r").require_shared_rule_key();
    assert_eq!(rule2.kind(), SuppressionKind::RuleKey);
    assert_eq!(rule2.kind().as_str(), "rule-key");
    let rule3 = SuppressionRule::new("S3", "r").require_same_category();
    assert_eq!(rule3.kind(), SuppressionKind::Category);
    let with_titles = rule3.clone().parent_titles(&["a"]);
    assert!(with_titles.validate().is_ok());
    assert!(with_titles.parent_title_contains.contains(&"a".to_string()));
    let yaml = serde_yaml::to_string(&rule3);
    assert!(yaml.is_ok());
    let back: Result<SuppressionRule, _> = serde_yaml::from_str(yaml.as_deref().unwrap_or(""));
    assert_eq!(back.ok(), Some(rule3));
    assert_eq!(SimilarityPolicy::Prefix.as_str(), "prefix");
}
