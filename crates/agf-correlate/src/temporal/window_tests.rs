//! 回归真实链路中的旧噪声、乱序、重复事件和租户边界。
use super::*;

fn event(tenant: TenantId, seconds: i64, category: EventCategory) -> Event {
    let mut event = tests::ev(tenant, 0, "same-host");
    event.time = Timestamp::from_unix_secs(1_700_000_000 + seconds).expect("valid fixture time");
    event.category = category;
    event
}
fn rule() -> TemporalRule {
    TemporalRule::new(
        "chain",
        "chain",
        60,
        vec![
            RuleStep::required("login", 1).with_categories(&["authentication"]),
            RuleStep::required("network", 1).with_categories(&["network"]),
        ],
        Severity::High,
    )
    .ordered()
}
#[test]
fn valid_later_sequence_survives_old_noise_and_early_second_step() {
    let t = TenantId::default_tenant();
    let events = [
        event(t, -500, EventCategory::Authentication),
        event(t, 0, EventCategory::Network),
        event(t, 10, EventCategory::Authentication),
        event(t, 20, EventCategory::Network),
    ];
    let hit = rule().evaluate(&events);
    assert!(hit.matched);
    assert_eq!(hit.matched_event_ids, vec![events[2].id, events[3].id]);
    assert_eq!(hit.span_secs, 10);
}
#[test]
fn same_timestamp_uses_input_order_and_distinct_events() {
    let t = TenantId::default_tenant();
    let a = event(t, 0, EventCategory::Authentication);
    let b = event(t, 0, EventCategory::Network);
    assert!(!rule().evaluate(&[b.clone(), a.clone()]).matched);
    assert!(rule().evaluate(&[a.clone(), b]).matched);
    let mut repeated = rule();
    repeated.steps[1] = repeated.steps[0].clone();
    assert!(!repeated.evaluate(&[a.clone(), a]).matched);
}
#[test]
fn each_step_count_must_complete_before_the_next_step() {
    let t = TenantId::default_tenant();
    let mut r = rule();
    r.steps[0].min_events = 2;
    assert!(
        !r.evaluate(&[
            event(t, 0, EventCategory::Authentication),
            event(t, 1, EventCategory::Network),
            event(t, 2, EventCategory::Authentication)
        ])
        .matched
    );
    assert!(
        r.evaluate(&[
            event(t, 0, EventCategory::Authentication),
            event(t, 1, EventCategory::Authentication),
            event(t, 2, EventCategory::Network)
        ])
        .matched
    );
}
#[test]
fn optional_steps_do_not_consume_required_evidence() {
    let t = TenantId::default_tenant();
    let mut r = rule();
    r.steps.insert(1, RuleStep::optional("optional network", 1).with_categories(&["network"]));
    let outcome = r.evaluate(&[event(t, 0, EventCategory::Authentication), event(t, 1, EventCategory::Network)]);
    assert!(outcome.matched);
    assert_eq!(outcome.hit_steps, 2, "可选步骤不能重复借用必需步骤的事件来抬高置信度");
}
#[test]
fn empty_rules_and_cross_tenant_events_cannot_create_hits() {
    let t = TenantId::default_tenant();
    let mut r = rule();
    r.steps.clear();
    assert!(!r.evaluate(&[]).matched);
    let a = event(t, 0, EventCategory::Authentication);
    let b = event(TenantId::new(), 1, EventCategory::Network);
    assert!(!rule().evaluate(&[a.clone(), b.clone()]).matched);
    assert!(TemporalScanner::new(GroupBy::None).scan(t, &[a, b], &[rule()]).is_empty());
}
