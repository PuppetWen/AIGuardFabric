//! 由 `temporal.rs` 拆分：`ev` 等 15 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn ev(tenant: TenantId, at: i64, host: &str) -> Event {
    let mut e = Event::new(tenant, Id::new(), IngestProtocol::Syslog);
    e.host.name = Some(host.to_string());
    e.time = Timestamp::now().offset_secs(at);
    e
}

#[test]
pub(crate) fn temporal_requires_all_required_steps() {
    let t = TenantId::default_tenant();
    let mut a = ev(t, -300, "ws-01");
    a.category = EventCategory::AiSession;
    let b = ev(t, -200, "ws-01");
    let rule = TemporalRule::new(
        "CHAIN-1",
        "外传后处置",
        600,
        vec![
            RuleStep::required("提示词攻击", 1).with_categories(&["ai-session"]),
            RuleStep::required("工具调用", 1).with_categories(&["network"]),
        ],
        Severity::High,
    );
    let outcome = rule.evaluate(&[a.clone(), b.clone()]);
    assert!(!outcome.matched, "类别不匹配的步不应命中");
    assert_eq!(outcome.missing_steps, vec!["工具调用".to_string()]);
    assert!((outcome.confidence() - 0.5).abs() < 1e-6);
    assert!(outcome.summary().contains("缺失步骤"));
}

#[test]
pub(crate) fn temporal_matches_within_window_and_respects_window() {
    let t = TenantId::default_tenant();
    let mut a = ev(t, -300, "ws-01");
    a.category = EventCategory::AiSession;
    let mut b = ev(t, -200, "ws-01");
    b.category = EventCategory::Network;
    let rule = TemporalRule::new(
        "CHAIN-2",
        "外传链",
        600,
        vec![
            RuleStep::required("会话", 1).with_categories(&["ai-session"]),
            RuleStep::required("外联", 1).with_categories(&["network"]),
        ],
        Severity::Critical,
    );
    let outcome = rule.evaluate(&[a.clone(), b.clone()]);
    assert!(outcome.matched, "{outcome:?}");
    assert!(outcome.window_ok);
    assert!((outcome.confidence() - 1.0).abs() < 1e-6);

    // 窗口收窄到 5 秒 → 跨度 100 秒超出窗口
    let narrow = TemporalRule { window_secs: 5, ..rule };
    let out2 = narrow.evaluate(&[a, b]);
    assert!(!out2.matched);
    assert!(!out2.window_ok);
}

#[test]
pub(crate) fn temporal_order_constraint() {
    let t = TenantId::default_tenant();
    let mut first = ev(t, -300, "ws-01");
    first.category = EventCategory::AiSession;
    let mut second = ev(t, -100, "ws-01");
    second.category = EventCategory::Network;
    let rule = TemporalRule::new(
        "CHAIN-3",
        "顺序链",
        600,
        vec![
            RuleStep::required("第一步", 1).with_categories(&["network"]),
            RuleStep::required("第二步", 1).with_categories(&["ai-session"]),
        ],
        Severity::High,
    )
    .ordered();
    // 顺序要求：网络在前、会话在后 → 交换时间即可满足
    let net = ev(t, -300, "ws-01");
    let mut net = net;
    net.category = EventCategory::Network;
    let mut sess = ev(t, -100, "ws-01");
    sess.category = EventCategory::AiSession;

    // 顺序链的核心语义：**顺序不对就不算命中**（否则每个调用方都得自己记得看
    // `order_ok`，一旦漏看就变成"乱序也算攻击链"）。命中步骤数仍会如实报出，便于排障。
    let outcome = rule.evaluate(&[first.clone(), second.clone()]);
    assert!(!outcome.matched, "顺序链：会话在前、网络在后 ⇒ 不应命中: {outcome:?}");
    assert!(!outcome.order_ok, "order_ok 应如实反映顺序不符");
    assert_eq!(outcome.hit_steps, 2, "两步都已出现，仅顺序不符");
    assert!(outcome.missing_steps.is_empty());

    let reversed = rule.evaluate(&[net, sess]);
    assert!(reversed.order_ok);
    assert!(reversed.matched);
}

#[test]
pub(crate) fn optional_step_does_not_block_and_counts_toward_confidence() {
    let t = TenantId::default_tenant();
    let mut a = ev(t, -10, "ws-01");
    a.category = EventCategory::AiSession;
    let rule = TemporalRule::new(
        "CHAIN-4",
        "可选链",
        600,
        vec![
            RuleStep::required("必需", 1).with_categories(&["ai-session"]),
            RuleStep::optional("可选", 1).with_categories(&["malware"]),
        ],
        Severity::Medium,
    );
    let outcome = rule.evaluate(&[a]);
    assert!(outcome.matched, "可选步缺失不应阻断");
    assert_eq!(outcome.hit_steps, 1);
    assert_eq!(outcome.total_steps, 2);
    assert!((outcome.confidence() - 0.5).abs() < 1e-6);
}

#[test]
pub(crate) fn temporal_min_events_honoured() {
    let t = TenantId::default_tenant();
    let mut a = ev(t, -10, "ws-01");
    a.category = EventCategory::Authentication;
    let rule = TemporalRule::new(
        "BRUTE-1",
        "暴力破解",
        300,
        vec![RuleStep::required("失败登录", 3).with_categories(&["authentication"])],
        Severity::High,
    );
    assert!(!rule.evaluate(std::slice::from_ref(&a)).matched);
    let b = ev(t, -5, "ws-01");
    let mut c = ev(t, -1, "ws-01");
    c.category = EventCategory::Authentication;
    let mut b = b;
    b.category = EventCategory::Authentication;
    let outcome = rule.evaluate(&[a, b, c]);
    assert!(outcome.matched, "{outcome:?}");
    assert_eq!(outcome.matched_event_ids.len(), 3);
}

#[test]
pub(crate) fn rule_step_action_and_rule_key_filters() {
    let t = TenantId::default_tenant();
    let mut e = ev(t, 0, "ws-01");
    e.action = EventAction::Exfiltrate;
    e.action_raw = "vendor-exfil".into();
    e.ai.rule_keys = vec!["MD-EXFIL-001".into()];

    let by_action = RuleStep::required("外传", 1).with_actions(&["exfiltrate"]);
    assert!(by_action.matches(&e));
    let by_raw = RuleStep::required("厂商动作", 1).with_actions(&["vendor-exfil"]);
    assert!(by_raw.matches(&e));
    let by_key = RuleStep::required("规则", 1).with_rule_keys(&["MD-EXFIL-001"]);
    assert!(by_key.matches(&e));
    let miss = RuleStep::required("别的规则", 1).with_rule_keys(&["XX-000"]);
    assert!(!miss.matches(&e));
    let cat = RuleStep::required("类别", 1).with_categories(&["malware"]);
    assert!(!cat.matches(&e));
}

#[test]
pub(crate) fn group_by_modes() {
    let t = TenantId::default_tenant();
    let mut a = ev(t, -10, "ws-01");
    a.source_id = Id::new();
    a.source_name = "edr".into();
    a.ai.session_id = Some("sess-1".into());
    let mut b = ev(t, -9, "ws-02");
    b.source_id = a.source_id;

    let entity = TemporalScanner::new(GroupBy::Entity);
    assert_ne!(entity.group_key(t, &a), entity.group_key(t, &b));
    let source = TemporalScanner::new(GroupBy::Source);
    assert_eq!(source.group_key(t, &a), source.group_key(t, &b));
    let session = TemporalScanner::new(GroupBy::Session);
    assert!(session.group_key(t, &a).is_some());
    assert!(session.group_key(t, &b).is_none(), "无会话 id 的事件不参与会话归组");
    let none = TemporalScanner::new(GroupBy::None);
    assert_eq!(none.group_key(t, &a), Some("all".to_string()));
}

#[test]
pub(crate) fn scanner_partitions_and_sorts_by_time() {
    let t = TenantId::default_tenant();
    let mut late = ev(t, -10, "ws-01");
    late.category = EventCategory::Network;
    let mut early = ev(t, -500, "ws-01");
    early.category = EventCategory::AiSession;
    let scanner = TemporalScanner::new(GroupBy::Entity);
    let groups = scanner.partition(t, &[late.clone(), early.clone()]);
    assert_eq!(groups.len(), 1);
    let group = groups.values().next().expect("应有一组");
    assert_eq!(group[0].id, early.id, "组内必须按时间升序");
    assert_eq!(group[1].id, late.id);
}

#[test]
pub(crate) fn scanner_reports_hits_with_severity_order() {
    let t = TenantId::default_tenant();
    let mut a = ev(t, -300, "ws-01");
    a.category = EventCategory::AiSession;
    let mut b = ev(t, -200, "ws-01");
    b.category = EventCategory::Network;
    let rules = vec![
        TemporalRule::new(
            "LOW",
            "低",
            600,
            vec![RuleStep::required("会话", 1).with_categories(&["ai-session"])],
            Severity::Low,
        ),
        TemporalRule::new(
            "CRIT",
            "高",
            600,
            vec![
                RuleStep::required("会话", 1).with_categories(&["ai-session"]),
                RuleStep::required("外联", 1).with_categories(&["network"]),
            ],
            Severity::Critical,
        ),
    ];
    let hits = TemporalScanner::new(GroupBy::Entity).scan(t, &[a, b], &rules);
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].rule_key, "CRIT", "高等级应排前");
    assert!(hits[0].outcome.matched);
}

#[test]
pub(crate) fn correlation_input_builds_alignment_and_window() {
    let t = TenantId::default_tenant();
    let mut a = ev(t, -300, "ws-01");
    a.network.destination_ip = Some("203.0.113.5".into());
    let b = ev(t, -100, "ws-01");
    let input = CorrelationInput::from_events(t, vec![b.clone(), a.clone()])
        .with_rule_keys(&["X-1"])
        .with_metric("bytes", 42.0);
    assert_eq!(input.event_ids().len(), 2);
    assert_eq!(input.events[0].id, a.id, "应排序为时间升序");
    assert!(input.window.duration_secs() >= 199);
    assert!(!input.alignment.is_empty());
    assert_eq!(input.metrics.get("bytes"), Some(&42.0));
}

#[test]
pub(crate) fn evaluate_simple_match_shape() {
    let t = TenantId::default_tenant();
    let input = CorrelationInput::from_events(t, vec![ev(t, 0, "ws-01")]).with_rule_keys(&["PA-INJ-001"]);
    let rule = CorrelationRule::Match {
        key: "M-1".into(),
        name: "注入".into(),
        rule_keys: vec!["PA-INJ-001".into()],
        severity: Severity::High,
    };
    let hit = evaluate_simple(&rule, &input);
    assert!(hit.is_some());
    let hit = hit.expect("应命中");
    assert!(hit.is_high_confidence());
    assert_eq!(hit.shape, "match");
    assert_eq!(rule.shape(), "match");
    assert_eq!(rule.key(), "M-1");
    assert_eq!(rule.severity(), Severity::High);

    let miss = CorrelationRule::Match {
        key: "M-2".into(),
        name: "别的".into(),
        rule_keys: vec!["ZZ-000".into()],
        severity: Severity::Low,
    };
    assert!(evaluate_simple(&miss, &input).is_none());
}

#[test]
pub(crate) fn evaluate_simple_temporal_and_delegated_shapes() {
    let t = TenantId::default_tenant();
    let mut a = ev(t, -10, "ws-01");
    a.category = EventCategory::Malware;
    let input = CorrelationInput::from_events(t, vec![a]);
    let temporal = CorrelationRule::Temporal(TemporalRule::new(
        "T-1",
        "恶意",
        60,
        vec![RuleStep::required("恶意", 1).with_categories(&["malware"])],
        Severity::Critical,
    ));
    let hit = evaluate_simple(&temporal, &input);
    assert!(hit.is_some());
    assert_eq!(hit.map(|h| h.shape), Some("temporal".to_string()));

    let graph = CorrelationRule::Graph(GraphRule::new("G-1", EntityKind::Host, EntityKind::Domain, 2, Severity::High));
    assert!(evaluate_simple(&graph, &input).is_none(), "图形态由构图层显式分派");
    assert_eq!(graph.shape(), "graph");
    let baseline = CorrelationRule::Baseline(BaselineRule::new("B-1", "outbound_bytes", Severity::Medium));
    assert!(evaluate_simple(&baseline, &input).is_none(), "基线形态由基线检测器显式分派");
    assert_eq!(baseline.shape(), "baseline");
    assert_eq!(baseline.severity(), Severity::Medium);
    assert_eq!(baseline.key(), "B-1");
}

#[test]
pub(crate) fn correlation_rule_serde_roundtrip() {
    let rule = CorrelationRule::Temporal(TemporalRule::new(
        "T-9",
        "往返",
        120,
        vec![RuleStep::required("s", 1)],
        Severity::High,
    ));
    let yaml = serde_yaml::to_string(&rule);
    assert!(yaml.is_ok());
    let back: Result<CorrelationRule, _> = serde_yaml::from_str(yaml.as_deref().unwrap_or(""));
    assert_eq!(back.ok(), Some(rule));
}

#[test]
pub(crate) fn group_by_str_matrix() {
    assert_eq!(GroupBy::Entity.as_str(), "entity");
    assert_eq!(GroupBy::None.as_str(), "none");
    assert_eq!(GroupBy::Session.as_str(), "session");
    assert_eq!(GroupBy::Source.as_str(), "source");
}
