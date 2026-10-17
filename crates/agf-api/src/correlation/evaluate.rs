//! 样本预览与自动执行共用同一判定入口；历史从持久化事件重建，当前异常不进入学习。
use super::{Definition, Event, Hit, Id, TenantId, group};
use agf_correlate::{baseline::BaselineDetector, temporal::CorrelationRule};

pub fn run(definition: &Definition, tenant: TenantId, events: &[Event], anchor: Id) -> Option<Hit> {
    let current = events.iter().find(|e| e.id == anchor && e.tenant_id == tenant)?;
    if !definition.event_filter.matches(current) {
        return None;
    }
    let group_key = group(definition, tenant, current)?;
    let mut events: Vec<_> = events
        .iter()
        .filter(|e| {
            e.tenant_id == tenant
                && e.time.since_secs(&current.time).abs() <= definition.window_secs
                && group(definition, tenant, e).as_ref() == Some(&group_key)
                && definition.event_filter.matches(e)
        })
        .cloned()
        .collect();
    events.sort_by_key(|e| (e.time, e.ingested_at, e.id));
    let mut seen = std::collections::BTreeSet::new();
    events.retain(|e| seen.insert(e.id));
    match &definition.rule {
        CorrelationRule::Match { rule_keys, name, .. } => {
            let keys: Vec<_> = current.ai.rule_keys.iter().filter(|key| rule_keys.contains(key)).collect();
            (!keys.is_empty()).then(|| Hit {
                event_ids: vec![anchor],
                confidence: 1.0,
                summary: format!("{name}: {}", keys.iter().map(|key| key.as_str()).collect::<Vec<_>>().join(", ")),
                details: serde_json::json!({"matched_rules":keys}),
            })
        }
        CorrelationRule::Temporal(rule) => {
            let outcome = rule.evaluate_containing(&events, anchor);
            outcome.matched.then(|| Hit {
                event_ids: outcome.matched_event_ids.clone(),
                confidence: outcome.confidence(),
                summary: outcome.summary(),
                details: serde_json::json!(outcome),
            })
        }
        CorrelationRule::Graph(rule) => {
            let path = agf_correlate::graph::find_path(rule, tenant, &events, anchor)?;
            let mut ids = path.event_ids.clone();
            ids.sort();
            ids.dedup();
            Some(Hit {
                event_ids: ids,
                confidence: 1.0,
                summary: format!("{}: {}", rule.name, path.entities.join(" → ")),
                details: serde_json::json!({"relationship":"observed-co-occurrence","path":path}),
            })
        }
        CorrelationRule::Baseline(rule) => {
            let observed = metric(current, &rule.metric)?;
            let mut detector = BaselineDetector::new();
            detector.slot_by_time = definition.slot_by_time;
            let mut learned = Vec::new();
            for event in &events {
                if (event.time, event.ingested_at, event.id) >= (current.time, current.ingested_at, current.id) {
                    break;
                }
                if let Some(value) = metric(event, &rule.metric) {
                    let previous = detector.evaluate(rule, tenant, &group_key, value, event.time);
                    if !previous.should_alert() {
                        detector.observe(tenant, &group_key, &rule.metric, value, event.time);
                        if detector.slot_key(tenant, &group_key, &rule.metric, event.time)
                            == detector.slot_key(tenant, &group_key, &rule.metric, current.time)
                        {
                            learned.push(event.id);
                        }
                    }
                }
            }
            let result = detector.evaluate(rule, tenant, &group_key, observed, current.time);
            if !result.should_alert() {
                return None;
            }
            learned.push(anchor);
            Some(Hit {
                event_ids: learned,
                confidence: result.confidence,
                summary: result.summary(),
                details: serde_json::json!(result),
            })
        }
    }
}

/// 缺失字段表示未观测到，不能作为零值学习。
#[allow(clippy::cast_precision_loss)]
fn metric(event: &Event, name: &str) -> Option<f64> {
    let value = match name {
        "outbound_bytes" | "network.bytes_out" => event.network.bytes_out,
        "inbound_bytes" | "network.bytes_in" => event.network.bytes_in,
        "prompt_tokens" | "ai.prompt_tokens" => event.ai.prompt_tokens,
        "completion_tokens" | "ai.completion_tokens" => event.ai.completion_tokens,
        "cost_micro" | "ai.cost_micro" => event.ai.cost_micro,
        _ => return None,
    }?;
    Some(value as f64)
}

pub const METRICS: &[&str] = &[
    "outbound_bytes",
    "network.bytes_out",
    "inbound_bytes",
    "network.bytes_in",
    "prompt_tokens",
    "ai.prompt_tokens",
    "completion_tokens",
    "ai.completion_tokens",
    "cost_micro",
    "ai.cost_micro",
];
