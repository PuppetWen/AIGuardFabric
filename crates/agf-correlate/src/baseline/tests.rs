//! 由 `baseline.rs` 拆分：`rule` 等 12 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn rule() -> BaselineRule {
    BaselineRule::new("BL-OUT-1", "outbound_bytes", Severity::High)
}

pub(crate) fn fixed_at() -> Timestamp {
    Timestamp::parse_rfc3339("2026-03-02T10:00:00Z").unwrap_or_else(|_| Timestamp::now())
}

#[test]
pub(crate) fn cold_start_reports_insufficient_data_not_deviation() {
    let t = TenantId::default_tenant();
    let d = BaselineDetector::new();
    let out = d.evaluate(&rule(), t, "host|ws-01", 9_999.0, fixed_at());
    assert_eq!(out.kind, DeviationKind::InsufficientData);
    assert!(!out.should_alert());
    assert_eq!(out.confidence, 0.0);
    assert_eq!(out.samples, 0);
    assert!(out.summary().contains("insufficient-data"));
}

#[test]
pub(crate) fn warm_profile_detects_spike() {
    let t = TenantId::default_tenant();
    let mut d = BaselineDetector::new();
    let at = fixed_at();
    for _ in 0..20 {
        d.observe(t, "host|ws-01", "outbound_bytes", 100.0, at);
    }
    // 恒定值 → 标准差为 0 → 走极值兜底
    let out = d.evaluate(&rule(), t, "host|ws-01", 500.0, at);
    assert_eq!(out.kind, DeviationKind::OutOfRange);
    assert!(out.should_alert());
    assert!((out.confidence - 1.0).abs() < 1e-6);

    // 引入波动后再看 Z 分数
    let mut d2 = BaselineDetector::new();
    for v in [95.0, 100.0, 105.0, 98.0, 102.0, 100.0, 101.0, 99.0] {
        d2.observe(t, "host|ws-01", "outbound_bytes", v, at);
    }
    let normal = d2.evaluate(&rule(), t, "host|ws-01", 101.0, at);
    assert_eq!(normal.kind, DeviationKind::Normal, "接近均值应为正常: {normal:?}");
    assert!(!normal.should_alert());
    let spike = d2.evaluate(&rule(), t, "host|ws-01", 5_000.0, at);
    assert_eq!(spike.kind, DeviationKind::Spike);
    assert!(spike.z_score.is_some_and(|z| z > 3.0));
    assert!((spike.confidence - 1.0).abs() < 1e-6, "远超阈值 → 置信度饱和");
}

#[test]
pub(crate) fn drop_is_detected_as_negative_deviation() {
    let t = TenantId::default_tenant();
    let mut d = BaselineDetector::new();
    let at = fixed_at();
    for v in [100.0, 110.0, 90.0, 105.0, 95.0, 102.0, 98.0, 101.0] {
        d.observe(t, "host|ws-01", "outbound_bytes", v, at);
    }
    let out = d.evaluate(&rule(), t, "host|ws-01", -10_000.0, at);
    assert_eq!(out.kind, DeviationKind::Drop);
    assert!(out.should_alert());
}

#[test]
pub(crate) fn time_slots_are_isolated() {
    let t = TenantId::default_tenant();
    let mut d = BaselineDetector::new();
    let morning = Timestamp::parse_rfc3339("2026-03-02T09:00:00Z").unwrap_or_else(|_| Timestamp::now());
    let night = Timestamp::parse_rfc3339("2026-03-02T23:00:00Z").unwrap_or_else(|_| Timestamp::now());
    for _ in 0..10 {
        d.observe(t, "host|ws-01", "outbound_bytes", 10.0, morning);
    }
    assert_eq!(d.profile_count(), 1);
    let out = d.evaluate(&rule(), t, "host|ws-01", 10.0, night);
    assert_eq!(out.kind, DeviationKind::InsufficientData, "夜间槽位尚未学习，不能误判");
    assert_eq!(out.samples, 0);
}

#[test]
pub(crate) fn global_slots_share_profile() {
    let t = TenantId::default_tenant();
    let mut d = BaselineDetector::new().global_slots();
    let morning = Timestamp::parse_rfc3339("2026-03-02T09:00:00Z").unwrap_or_else(|_| Timestamp::now());
    let night = Timestamp::parse_rfc3339("2026-03-02T23:00:00Z").unwrap_or_else(|_| Timestamp::now());
    for _ in 0..8 {
        d.observe(t, "host|ws-01", "outbound_bytes", 10.0, morning);
    }
    let out = d.evaluate(&rule(), t, "host|ws-01", 10.0, night);
    assert!(out.samples >= 8, "关闭分槽后应共用画像");
    assert!(!out.should_alert());
    assert_eq!(d.profile_count(), 1);
}

#[test]
pub(crate) fn welford_statistics_match_manual_computation() {
    let t = TenantId::default_tenant();
    let at = fixed_at();
    let mut p = BaselineProfile::new(t, "host|ws-01", "m", at);
    for v in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
        p.observe(v, at);
    }
    assert_eq!(p.samples, 8);
    assert!((p.mean - 5.0).abs() < 1e-9, "mean={}", p.mean);
    // 样本标准差（n-1）= sqrt(32/7) ≈ 2.138
    assert!((p.stddev() - (32.0f64 / 7.0).sqrt()).abs() < 1e-9);
    assert!((p.min - 2.0).abs() < 1e-9);
    assert!((p.max - 9.0).abs() < 1e-9);
    assert!(p.is_warm(5));
    assert!(!p.is_warm(50));
    assert!(p.z_score(5.0).is_some_and(|z| z.abs() < 1e-9));
    assert!(p.key().contains("host|ws-01|m|"));
}

#[test]
pub(crate) fn stddev_zero_yields_no_z_score() {
    let t = TenantId::default_tenant();
    let at = fixed_at();
    let mut p = BaselineProfile::new(t, "e", "m", at);
    p.observe(7.0, at);
    assert_eq!(p.stddev(), 0.0);
    assert!(p.z_score(7.0).is_none());
    p.observe(7.0, at);
    assert_eq!(p.stddev(), 0.0);
    assert!(p.z_score(8.0).is_none());
}

#[test]
pub(crate) fn deviation_kind_semantics() {
    assert!(DeviationKind::Spike.is_deviation());
    assert!(DeviationKind::Drop.is_deviation());
    assert!(DeviationKind::OutOfRange.is_deviation());
    assert!(!DeviationKind::InsufficientData.is_deviation());
    assert!(!DeviationKind::Normal.is_deviation());
    assert_eq!(DeviationKind::OutOfRange.as_str(), "out-of-range");
    assert_eq!(DeviationKind::Normal.as_str(), "normal");
}

#[test]
pub(crate) fn evaluate_many_filters_non_deviations() {
    let t = TenantId::default_tenant();
    let mut d = BaselineDetector::new();
    let at = fixed_at();
    for v in [100.0, 110.0, 90.0, 105.0, 95.0, 102.0, 98.0, 101.0] {
        d.observe(t, "host|ws-01", "outbound_bytes", v, at);
        d.observe(t, "host|ws-01", "tool_calls", v, at);
    }
    let rules = vec![
        BaselineRule::new("BL-1", "outbound_bytes", Severity::High),
        BaselineRule::new("BL-2", "tool_calls", Severity::Medium),
        BaselineRule::new("BL-3", "unobserved_metric", Severity::Low),
    ];
    let obs = BTreeMap::from([("outbound_bytes".to_string(), 9_000.0), ("tool_calls".to_string(), 100.0)]);
    let out = d.evaluate_many(&rules, t, "host|ws-01", &obs, at);
    assert_eq!(out.len(), 1, "只应报出突出的那一项: {out:?}");
    assert_eq!(out[0].metric, "outbound_bytes");
    assert_eq!(out[0].rule_key, "BL-1");
}

#[test]
pub(crate) fn custom_threshold_changes_sensitivity() {
    let t = TenantId::default_tenant();
    let mut d = BaselineDetector::new();
    let at = fixed_at();
    for v in [100.0, 110.0, 90.0, 105.0, 95.0, 102.0, 98.0, 101.0] {
        d.observe(t, "host|ws-01", "outbound_bytes", v, at);
    }
    // z ≈ (130-100)/6.3 ≈ 4.7
    let loose = BaselineRule::new("BL-L", "outbound_bytes", Severity::Low).with_z(10.0);
    let tight = BaselineRule::new("BL-T", "outbound_bytes", Severity::High).with_z(1.0);
    assert!(!d.evaluate(&loose, t, "host|ws-01", 130.0, at).should_alert());
    assert!(d.evaluate(&tight, t, "host|ws-01", 130.0, at).should_alert());
}
