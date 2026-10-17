//! 四类规则的可编辑示例；不自动发布，不把样本写入业务事件库。
use super::{Definition, Event, TenantId};
use agf_core::{
    enums::{IngestProtocol, RiskDomain, Severity},
    event::EventCategory,
    ids::Id,
    time::Timestamp,
};
use agf_correlate::{
    entity::EntityKind,
    temporal::{BaselineRule, CorrelationRule, GraphRule, GroupBy, RuleStep, TemporalRule},
};

pub fn examples(tenant: TenantId) -> Vec<Definition> {
    let source = Id::new();
    let time = Timestamp::now().offset_secs(-600);
    let make = |offset: i64| {
        let mut event = Event::new(tenant, source, IngestProtocol::Syslog);
        event.time = time.offset_secs(offset);
        event.ingested_at = event.time;
        event.host.name = Some("example-workstation".into());
        event.raw_hash = agf_core::secret::content_hash(&format!("correlation-example-{offset}"));
        event
    };
    let mut a = make(0);
    a.category = EventCategory::Authentication;
    let mut b = make(10);
    b.category = EventCategory::Network;
    let temporal = Definition {
        rule: CorrelationRule::Temporal(
            TemporalRule::new(
                "login-network-chain",
                "Login followed by network activity",
                300,
                vec![
                    RuleStep::required("Login", 1).with_categories(&["authentication"]),
                    RuleStep::required("Network", 1).with_categories(&["network"]),
                ],
                Severity::High,
            )
            .ordered(),
        ),
        domain: RiskDomain::ToolAbuse,
        enabled: false,
        group_by: GroupBy::Entity,
        window_secs: 300,
        event_filter: RuleStep::default(),
        slot_by_time: false,
        positive: vec![a.clone(), b.clone()],
        negative: vec![b.clone()],
    };
    let mut graph = temporal.clone();
    graph.rule = CorrelationRule::Graph(GraphRule::new(
        "agent-egress-path",
        EntityKind::Agent,
        EntityKind::Domain,
        2,
        Severity::High,
    ));
    graph.group_by = GroupBy::None;
    a.ai.agent_id = Some(Id::new());
    a.user.id = Some("example-user".into());
    a.host.name = None;
    b.user.id = Some("example-user".into());
    b.network.domain = Some("sink.example".into());
    b.host.name = None;
    graph.positive = vec![a.clone(), b.clone()];
    let mut other = b.clone();
    other.user.id = Some("another-user".into());
    graph.negative = vec![a, other];
    let mut baseline = temporal.clone();
    baseline.rule =
        CorrelationRule::Baseline(BaselineRule::new("outbound-byte-spike", "outbound_bytes", Severity::High));
    baseline.positive = (0..6)
        .map(|n| {
            let mut e = make(n);
            e.network.bytes_out = Some(if n == 5 { 5000 } else { 100 });
            e
        })
        .collect();
    baseline.negative = baseline.positive.clone();
    if let Some(last) = baseline.negative.last_mut() {
        last.network.bytes_out = Some(100);
    }
    let mut matching = temporal.clone();
    matching.rule = CorrelationRule::Match {
        key: "matched-rule-route".into(),
        name: "Alert on a published detection rule".into(),
        rule_keys: vec!["MY-DETECTION-RULE".into()],
        severity: Severity::High,
    };
    let mut event = make(0);
    event.ai.rule_keys = vec!["MY-DETECTION-RULE".into()];
    matching.positive = vec![event];
    matching.negative = vec![make(1)];
    vec![temporal, graph, baseline, matching]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn four_examples_pass_positive_and_negative_regression() {
        for definition in examples(TenantId::new()) {
            let result = super::super::registry::validate(&definition).expect("valid example");
            assert_eq!(result["passed"], true, "{}: {result}", definition.rule.key());
        }
    }
}
