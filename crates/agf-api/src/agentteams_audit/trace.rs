//! Bounded, authenticated trace reads expose observed evidence rather than a complete cloud DAG.
use super::{
    binding,
    trace_cursor::{self, Cursor},
    trace_graph, views,
};
use crate::{source_store, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use agf_ingest::pipeline::{
    AGENTTEAMS_TRACE_NODE_LIMIT, AGENTTEAMS_TRACE_WINDOW_SECS, AgentTeamsAuditCursor, AgentTeamsTraceQuery,
    valid_trace_id,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceQuery {
    pub from: Option<Timestamp>,
    pub until: Option<Timestamp>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

pub async fn view(state: &AppState, tenant: TenantId, trace_id: &str, query: TraceQuery) -> DomainResult<Value> {
    let now = Timestamp::now();
    let limit = query.limit.unwrap_or(50);
    if !valid_trace_id(trace_id) || !(1..=200).contains(&limit) {
        return Err(DomainError::Validation("Trace 标识须为1至128个标识字符，每页事件须为1至200条".into()));
    }
    let context = binding::context(state, tenant).await?;
    let cursor = if let Some(raw) = &query.cursor {
        let context = context.as_ref().ok_or_else(super::stale)?;
        Some(trace_cursor::decode(state, raw, tenant, context, trace_id, &query, now)?)
    } else {
        None
    };
    let until = cursor.as_ref().map_or_else(|| query.until.unwrap_or(now), |cursor| cursor.until);
    let from = if let Some(cursor) = &cursor {
        cursor.from
    } else if let Some(from) = query.from {
        from
    } else {
        until
            .as_datetime()
            .checked_sub_signed(chrono::Duration::days(1))
            .map(Timestamp::from_datetime)
            .ok_or_else(invalid_window)?
    };
    validate_window(from, until, now)?;
    let Some(context) = context else {
        return Ok(unavailable(trace_id, from, until, now));
    };
    let received_until = cursor.as_ref().map_or(now, |cursor| cursor.received_until);
    let snapshot = state
        .ingest_sink
        .agentteams_trace_snapshot(&AgentTeamsTraceQuery {
            tenant_id: tenant,
            scope_id: context.scope_id,
            trace_id: trace_id.into(),
            from,
            until,
            received_until,
            limit: AGENTTEAMS_TRACE_NODE_LIMIT,
        })
        .await?;
    let digest = trace_cursor::digest(&snapshot)?;
    let offset = trace_cursor::offset(cursor.as_ref(), &snapshot.records, &digest)?;
    let end = offset.saturating_add(limit).min(snapshot.records.len());
    let page = &snapshot.records[offset..end];
    let next_cursor = if end < snapshot.records.len() {
        page.last()
            .map(|last| {
                trace_cursor::encode(
                    state,
                    &Cursor {
                        tenant,
                        scope: context.scope_id,
                        trace_id: trace_id.into(),
                        from,
                        until,
                        received_until,
                        issued_at: cursor.as_ref().map_or(now, |cursor| cursor.issued_at),
                        before: AgentTeamsAuditCursor { event_time: last.event_time, id: last.id },
                        emitted: end,
                        snapshot_digest: digest,
                    },
                )
            })
            .transpose()?
    } else {
        None
    };
    let names = source_names(state, tenant, page.iter().map(|record| record.source_id).collect()).await?;
    let items: Vec<_> =
        page.iter().map(|record| views::event(record, names.get(&record.source_id).map(String::as_str))).collect();
    let truncated = snapshot.total > u64::try_from(snapshot.records.len()).unwrap_or(u64::MAX);
    let graph = trace_graph::build(&snapshot.records, truncated);
    // Check after bounded metadata reads too; no old scope is published after a known change.
    let current = binding::context(state, tenant).await?.ok_or_else(super::stale)?;
    if current.scope_id != context.scope_id {
        return Err(super::stale());
    }
    Ok(json!({"traceId":trace_id,"scopeId":context.scope_id,"cloudVersion":context.cloud.version,
        "mocked":context.snapshot.mocked,"inventoryAvailable":true,"windowFrom":from,"windowTo":until,
        "asOfReceivedAt":received_until,"totalEvents":snapshot.total,"items":items,"nextCursor":next_cursor,
        "truncated":truncated,"nodeLimit":AGENTTEAMS_TRACE_NODE_LIMIT,"complete":false,
        "coverage":"observed_only","consistency":"statement","timePrecision":"microsecond",
        "graph":graph}))
}

// Metadata reads are bounded by the selected page, not by the tenant's source collection.
async fn source_names(state: &AppState, tenant: TenantId, ids: BTreeSet<Id>) -> DomainResult<BTreeMap<Id, String>> {
    let mut names = BTreeMap::new();
    for id in ids {
        let record: Option<source_store::Record> = state.configurations.get(tenant, source_store::KIND, id).await?;
        if let Some(source) = record.and_then(|record| record.source) {
            names.insert(id, source.name);
        }
    }
    Ok(names)
}

fn validate_window(from: Timestamp, until: Timestamp, now: Timestamp) -> DomainResult<()> {
    let duration = until.as_datetime().signed_duration_since(from.as_datetime());
    if from >= until
        || duration > chrono::Duration::seconds(AGENTTEAMS_TRACE_WINDOW_SECS)
        || until > now.offset_secs(60)
    {
        return Err(invalid_window());
    }
    Ok(())
}

fn invalid_window() -> DomainError {
    DomainError::Validation("Trace 时间窗口须为正且不超过30天，结束时间不得超过当前时间60秒".into())
}

fn unavailable(trace_id: &str, from: Timestamp, until: Timestamp, now: Timestamp) -> Value {
    json!({"traceId":trace_id,"scopeId":null,"cloudVersion":0,"mocked":null,"inventoryAvailable":false,
        "windowFrom":from,"windowTo":until,"asOfReceivedAt":now,"totalEvents":null,"items":[],"nextCursor":null,
        "truncated":false,"nodeLimit":AGENTTEAMS_TRACE_NODE_LIMIT,"complete":false,
        "coverage":"observed_only","consistency":"statement","timePrecision":"microsecond",
        "graph":{"status":"unavailable","nodes":[],"edges":[],"issues":[]}})
}
