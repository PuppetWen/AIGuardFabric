//! 从同一条结构化事件中的实体共现建立有证据的关系边；路径不表示已经证明因果关系。
use crate::{
    entity::{EntityAligner, EntityKind, EntityRefStrength},
    temporal::GraphRule,
};
use agf_core::{
    event::Event,
    ids::{Id, TenantId},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// 图命中携带完整实体路径及支撑每条边的事件。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphPath {
    /// 规范化的实体键，从起点到终点。
    pub entities: Vec<String>,
    /// 与路径中的边对应的事件 ID。
    pub event_ids: Vec<Id>,
}

/// 查询包含指定事件的最短实体路径。只采用结构化字段，忽略正文猜测和厂商名称。
#[must_use]
pub fn find_path(rule: &GraphRule, tenant: TenantId, events: &[Event], anchor: Id) -> Option<GraphPath> {
    if rule.max_hops == 0 || rule.max_hops > 8 {
        return None;
    }
    let aligner = EntityAligner { scan_message: false, promote_ip_to_host: false, ..EntityAligner::new() };
    let mut kinds: BTreeMap<String, EntityKind> = BTreeMap::new();
    let mut edges: BTreeMap<String, Vec<(String, Id)>> = BTreeMap::new();
    for event in events.iter().filter(|event| event.tenant_id == tenant) {
        let entities = aligner.extract(event);
        let nodes: Vec<_> = entities
            .refs
            .iter()
            .filter(|r| r.strength >= EntityRefStrength::Medium)
            .filter_map(|r| r.kind.map(|kind| (r.local_key(), kind)))
            .collect();
        for (a, kind) in &nodes {
            kinds.insert(a.clone(), *kind);
            for (b, _) in &nodes {
                if a != b {
                    edges.entry(a.clone()).or_default().push((b.clone(), event.id));
                }
            }
        }
    }
    for (start, _) in kinds.iter().filter(|(_, kind)| **kind == rule.from_kind) {
        let mut queue = VecDeque::from([(vec![start.clone()], Vec::<Id>::new(), false)]);
        let mut visited = BTreeSet::from([(start.clone(), false)]);
        while let Some((nodes, evidence, anchored)) = queue.pop_front() {
            let Some(last) = nodes.last() else { continue };
            if anchored && !evidence.is_empty() && kinds.get(last) == Some(&rule.to_kind) {
                return Some(GraphPath { entities: nodes, event_ids: evidence });
            }
            if evidence.len() >= rule.max_hops {
                continue;
            }
            for (next, event_id) in edges.get(last).into_iter().flatten() {
                let anchored = anchored || *event_id == anchor;
                if nodes.contains(next) || !visited.insert((next.clone(), anchored)) {
                    continue;
                }
                let mut path = nodes.clone();
                path.push(next.clone());
                let mut ids = evidence.clone();
                ids.push(*event_id);
                queue.push_back((path, ids, anchored));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use agf_core::enums::{IngestProtocol, Severity};
    #[test]
    fn follows_cross_source_edges_and_enforces_hops_tenant_and_anchor() {
        let tenant = TenantId::new();
        let mut a = Event::new(tenant, Id::new(), IngestProtocol::Syslog);
        a.ai.agent_id = Some(Id::new());
        a.user.id = Some("operator".into());
        let mut b = Event::new(tenant, Id::new(), IngestProtocol::Otlp);
        b.user.id = Some("operator".into());
        b.network.domain = Some("sink.example".into());
        let rule = GraphRule::new("path", EntityKind::Agent, EntityKind::Domain, 2, Severity::High);
        let path = find_path(&rule, tenant, &[a.clone(), b.clone()], b.id).expect("two edges");
        assert_eq!(path.event_ids, vec![a.id, b.id]);
        let mut short = rule.clone();
        short.max_hops = 1;
        assert!(find_path(&short, tenant, &[a.clone(), b.clone()], b.id).is_none());
        assert!(find_path(&rule, tenant, &[a.clone(), b.clone()], Id::new()).is_none());
        b.tenant_id = TenantId::new();
        assert!(find_path(&rule, tenant, &[a, b.clone()], b.id).is_none());
    }
    #[test]
    fn shared_provider_and_message_text_are_not_identity_edges() {
        let tenant = TenantId::new();
        let mut a = Event::new(tenant, Id::new(), IngestProtocol::Syslog);
        a.ai.agent_id = Some(Id::new());
        a.ai.provider = Some("example-provider".into());
        let mut b = Event::new(tenant, Id::new(), IngestProtocol::Syslog);
        b.ai.provider = a.ai.provider.clone();
        b.message = "https://sink.example".into();
        b.network.domain = Some("sink.example".into());
        let rule = GraphRule::new("path", EntityKind::Agent, EntityKind::Domain, 3, Severity::High);
        assert!(find_path(&rule, tenant, &[a, b.clone()], b.id).is_none());
    }
}
