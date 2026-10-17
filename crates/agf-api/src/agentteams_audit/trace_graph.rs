//! Parent-span evidence is the only source of graph edges; ambiguous evidence stays visible.
use agf_ingest::pipeline::AgentTeamsAuditRecord;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn build(records: &[AgentTeamsAuditRecord], truncated: bool) -> Value {
    let mut spans = BTreeMap::<&str, Vec<usize>>::new();
    for (index, record) in records.iter().enumerate() {
        if let Some(span) = record.span_id.as_deref() {
            spans.entry(span).or_default().push(index);
        }
    }
    let mut parents = vec![None; records.len()];
    let mut resolutions = vec!["observed"; records.len()];
    let mut issues = Vec::new();
    for (index, record) in records.iter().enumerate() {
        let Some(span) = record.span_id.as_deref() else {
            issue(&mut issues, record, "missing_span", "unknown");
            resolutions[index] = "unknown";
            continue;
        };
        if spans[span].len() != 1 {
            issue(&mut issues, record, "duplicate_span", "conflict");
            resolutions[index] = "conflict";
            continue;
        }
        let Some(parent) = record.parent_span_id.as_deref() else { continue };
        match spans.get(parent) {
            None => {
                issue(&mut issues, record, "missing_parent", "unknown");
                resolutions[index] = "unknown";
            }
            Some(indices) if indices.len() == 1 => parents[index] = indices.first().copied(),
            Some(_) => {
                issue(&mut issues, record, "ambiguous_parent", "conflict");
                resolutions[index] = "conflict";
            }
        }
    }
    let cycles = cycle_nodes(&parents);
    for index in &cycles {
        issue(&mut issues, &records[*index], "cycle", "conflict");
        resolutions[*index] = "conflict";
    }
    let mut edges = Vec::new();
    for (child, parent) in parents.iter().enumerate().filter_map(|(child, parent)| parent.map(|parent| (child, parent)))
    {
        if cycles.contains(&child) {
            continue;
        }
        if cycles.contains(&parent) {
            issue(&mut issues, &records[child], "conflicted_parent", "conflict");
            resolutions[child] = "conflict";
            continue;
        }
        edges.push(json!({"fromNodeId":records[parent].id,"toNodeId":records[child].id,
            "parentSpanId":records[child].parent_span_id,"evidence":"parent_span_id"}));
    }
    let nodes: Vec<_> = records.iter().zip(&resolutions).map(|(record, resolution)| node(record, resolution)).collect();
    let status = if records.is_empty() {
        "unobserved"
    } else if resolutions.contains(&"conflict") {
        "conflict"
    } else if truncated || resolutions.contains(&"unknown") {
        "unknown"
    } else {
        "observed"
    };
    json!({"status":status,"nodes":nodes,"edges":edges,"issues":issues})
}

fn node(record: &AgentTeamsAuditRecord, resolution: &str) -> Value {
    json!({"id":record.id,"eventId":record.external_event_id,"spanId":record.span_id,
        "parentSpanId":record.parent_span_id,"sourceId":record.source_id,"bindingId":record.binding_id,
        "kind":record.kind,"status":record.status,"eventTime":record.event_time,
        "fromTeam":record.from_team,"fromWorker":record.from_worker,"fromAssetId":record.from_asset,
        "toTeam":record.to_team,"toWorker":record.to_worker,"toAssetId":record.to_asset,
        "taskId":record.task_id,"durationMs":record.duration_ms,"mocked":record.mocked,
        "resolution":resolution,"authorizationStatus":"unknown","authorized":null})
}

fn issue(issues: &mut Vec<Value>, record: &AgentTeamsAuditRecord, kind: &str, status: &str) {
    issues.push(json!({"nodeId":record.id,"spanId":record.span_id,
        "parentSpanId":record.parent_span_id,"kind":kind,"status":status}));
}

// Each span has at most one recorded parent. Iteration avoids recursion on a long trace.
fn cycle_nodes(parents: &[Option<usize>]) -> BTreeSet<usize> {
    let mut complete = vec![false; parents.len()];
    let mut cycles = BTreeSet::new();
    for start in 0..parents.len() {
        if complete[start] {
            continue;
        }
        let mut path = Vec::new();
        let mut positions = BTreeMap::new();
        let mut current = Some(start);
        while let Some(index) = current {
            if complete[index] {
                break;
            }
            if let Some(position) = positions.get(&index) {
                cycles.extend(path[*position..].iter().copied());
                break;
            }
            positions.insert(index, path.len());
            path.push(index);
            current = parents[index];
        }
        for index in path {
            complete[index] = true;
        }
    }
    cycles
}

#[cfg(test)]
mod tests;
