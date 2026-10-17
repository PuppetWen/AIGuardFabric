#![allow(clippy::unwrap_used, clippy::panic)]
use super::*;
use agf_core::{
    ids::{Id, TenantId},
    time::Timestamp,
};

fn record(span: Option<&str>, parent: Option<&str>) -> AgentTeamsAuditRecord {
    let now = Timestamp::now();
    AgentTeamsAuditRecord {
        id: Id::new(),
        tenant_id: TenantId::new(),
        scope_id: Id::new(),
        source_id: Id::new(),
        binding_id: Id::new(),
        external_event_id: Id::new().to_string(),
        content_hash: "a".repeat(64),
        event_time: now,
        received_at: now,
        kind: "call".into(),
        from_team: Some("team".into()),
        from_worker: Some("caller".into()),
        from_asset: None,
        to_team: Some("team".into()),
        to_worker: Some("callee".into()),
        to_asset: None,
        task_id: Some("same-task".into()),
        trace_id: Some("trace".into()),
        span_id: span.map(str::to_owned),
        parent_span_id: parent.map(str::to_owned),
        status: "unknown".into(),
        duration_ms: None,
        message_preview: "not-in-graph".into(),
        mocked: false,
    }
}

#[test]
fn only_explicit_parent_span_creates_an_edge_and_no_message_is_projected() {
    let records = [record(Some("root"), None), record(Some("child"), Some("root")), record(Some("peer"), None)];
    let graph = build(&records, false);
    assert_eq!(graph["status"], "observed");
    assert_eq!(graph["edges"].as_array().unwrap().len(), 1);
    let edge = &graph["edges"][0];
    assert_eq!(edge["fromNodeId"], json!(records[0].id));
    assert_eq!(edge["toNodeId"], json!(records[1].id));
    assert_eq!(edge["evidence"], "parent_span_id");
    assert!(!graph.to_string().contains("not-in-graph"));
    assert!(graph["nodes"].as_array().unwrap().iter().all(|node| node["authorized"].is_null()));
}

#[test]
fn missing_span_and_parent_remain_unknown_without_inferred_edges() {
    let graph = build(&[record(None, None), record(Some("child"), Some("absent"))], false);
    assert_eq!(graph["status"], "unknown");
    assert!(graph["edges"].as_array().unwrap().is_empty());
    assert_eq!(graph["issues"][0]["kind"], "missing_span");
    assert_eq!(graph["issues"][1]["kind"], "missing_parent");
}

#[test]
fn duplicate_spans_are_distinct_nodes_and_ambiguous_parents_are_not_edges() {
    let graph =
        build(&[record(Some("root"), None), record(Some("root"), None), record(Some("child"), Some("root"))], false);
    assert_eq!(graph["status"], "conflict");
    assert_eq!(graph["nodes"].as_array().unwrap().len(), 3);
    assert!(graph["edges"].as_array().unwrap().is_empty());
    assert_eq!(graph["issues"][2]["kind"], "ambiguous_parent");
}

#[test]
fn cycles_and_their_dependent_edges_are_suppressed_but_safe_components_remain() {
    let graph = build(
        &[
            record(Some("a"), Some("b")),
            record(Some("b"), Some("a")),
            record(Some("dependent"), Some("a")),
            record(Some("self"), Some("self")),
            record(Some("safe"), None),
            record(Some("safe-child"), Some("safe")),
        ],
        false,
    );
    assert_eq!(graph["status"], "conflict");
    assert_eq!(graph["edges"].as_array().unwrap().len(), 1);
    assert_eq!(graph["issues"].as_array().unwrap().iter().filter(|issue| issue["kind"] == "cycle").count(), 3);
    assert!(graph["issues"].as_array().unwrap().iter().any(|issue| issue["kind"] == "conflicted_parent"));
}

#[test]
fn node_cap_truncation_is_unknown_even_when_the_visible_component_has_no_error() {
    assert_eq!(build(&[record(Some("root"), None)], true)["status"], "unknown");
    assert_eq!(build(&[], false)["status"], "unobserved");
}

#[test]
fn two_thousand_span_chain_uses_bounded_iteration_without_recursive_traversal() {
    let records: Vec<_> = (0..2000)
        .map(|index| {
            record(Some(&format!("span-{index}")), (index > 0).then(|| format!("span-{}", index - 1)).as_deref())
        })
        .collect();
    let graph = build(&records, false);
    assert_eq!(graph["status"], "observed");
    assert_eq!(graph["edges"].as_array().unwrap().len(), 1999);
}
