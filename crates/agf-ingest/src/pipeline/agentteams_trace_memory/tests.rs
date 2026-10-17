#![allow(clippy::unwrap_used, clippy::panic)]
use super::*;
use chrono::Timelike;

fn query() -> AgentTeamsTraceQuery {
    let now = Timestamp::now();
    AgentTeamsTraceQuery {
        tenant_id: TenantId::new(),
        scope_id: Id::new(),
        trace_id: "trace-one".into(),
        from: now.offset_secs(-86_400),
        until: now,
        received_until: now,
        limit: 2000,
    }
}

fn record(query: &AgentTeamsTraceQuery, index: usize) -> AgentTeamsAuditRecord {
    AgentTeamsAuditRecord {
        id: Id::new(),
        tenant_id: query.tenant_id,
        scope_id: query.scope_id,
        source_id: Id::new(),
        binding_id: Id::new(),
        external_event_id: format!("event-{index}"),
        content_hash: "a".repeat(64),
        event_time: query.until.offset_secs(-1),
        received_at: query.received_until,
        kind: "call".into(),
        from_team: None,
        from_worker: None,
        from_asset: None,
        to_team: None,
        to_worker: None,
        to_asset: None,
        task_id: None,
        trace_id: Some(query.trace_id.clone()),
        span_id: Some(format!("span-{index}")),
        parent_span_id: None,
        status: "unknown".into(),
        duration_ms: None,
        message_preview: String::new(),
        mocked: false,
    }
}

fn add(state: &mut MemoryState, record: AgentTeamsAuditRecord) {
    state.agentteams.insert((record.tenant_id, record.scope_id, record.external_event_id.clone()), record);
}

#[test]
fn trace_total_ignores_page_cap_and_excludes_other_tenants_scopes_and_traces() {
    let mut state = MemoryState::default();
    let query = query();
    for index in 0..2005 {
        add(&mut state, record(&query, index));
    }
    let mut other = record(&query, 9000);
    other.tenant_id = TenantId::new();
    add(&mut state, other);
    let mut other = record(&query, 9001);
    other.scope_id = Id::new();
    add(&mut state, other);
    let mut other = record(&query, 9002);
    other.trace_id = Some("trace-two".into());
    add(&mut state, other);
    let result = snapshot(&state, &query).unwrap();
    assert_eq!(result.total, 2005);
    assert_eq!(result.records.len(), 2000);
    let smaller = AgentTeamsTraceQuery { limit: 2, ..query };
    let page = snapshot(&state, &smaller).unwrap();
    assert_eq!(page.total, result.total);
    assert_eq!(
        page.records.iter().map(|record| record.id).collect::<Vec<_>>(),
        result.records.iter().take(2).map(|record| record.id).collect::<Vec<_>>()
    );
}

#[test]
fn half_open_window_and_receive_watermark_match_sql_microsecond_precision() {
    let mut state = MemoryState::default();
    let query = query();
    for (index, time) in [(0, query.from), (1, query.until), (2, query.from.offset_secs(-1))] {
        let mut row = record(&query, index);
        row.event_time = time;
        add(&mut state, row);
    }
    let mut late = record(&query, 3);
    late.received_at = query.received_until.offset_secs(1);
    add(&mut state, late);
    let result = snapshot(&state, &query).unwrap();
    assert_eq!(result.total, 1);
    assert_eq!(result.records[0].external_event_id, "event-0");
}

#[test]
fn submicrosecond_ties_order_by_id_as_in_postgresql() {
    let mut state = MemoryState::default();
    let query = query();
    let base = Timestamp::from_unix_millis(query.until.offset_secs(-1).unix_millis()).unwrap();
    let mut low = record(&query, 0);
    low.id = Id::parse("00000000-0000-0000-0000-000000000001").unwrap();
    low.event_time =
        Timestamp::from_datetime(base.as_datetime().with_nanosecond(base.as_datetime().nanosecond() + 200).unwrap());
    let mut high = record(&query, 1);
    high.id = Id::parse("00000000-0000-0000-0000-000000000002").unwrap();
    high.event_time =
        Timestamp::from_datetime(base.as_datetime().with_nanosecond(base.as_datetime().nanosecond() + 100).unwrap());
    add(&mut state, low);
    add(&mut state, high.clone());
    assert_eq!(snapshot(&state, &query).unwrap().records[0].id, high.id);
}

#[test]
fn invalid_trace_windows_scopes_and_limits_are_rejected() {
    let state = MemoryState::default();
    let original = query();
    for bad in [
        AgentTeamsTraceQuery { from: original.until, ..original.clone() },
        AgentTeamsTraceQuery { from: original.until.offset_secs(-30 * 86_400 - 1), ..original.clone() },
        AgentTeamsTraceQuery { until: Timestamp::now().offset_secs(120), ..original.clone() },
        AgentTeamsTraceQuery { scope_id: Id::nil(), ..original.clone() },
        AgentTeamsTraceQuery { trace_id: "../../other".into(), ..original.clone() },
        AgentTeamsTraceQuery { limit: 2001, ..original },
    ] {
        assert!(snapshot(&state, &bad).is_err());
    }
}
