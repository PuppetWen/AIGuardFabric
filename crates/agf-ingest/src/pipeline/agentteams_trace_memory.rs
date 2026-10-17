//! A bounded trace projection and its total share the memory sink's lock.
use super::{agentteams_trace::*, sink::MemoryState, *};

pub(super) fn snapshot(state: &MemoryState, query: &AgentTeamsTraceQuery) -> DomainResult<AgentTeamsTraceSnapshot> {
    validate(query)?;
    let mut total = 0;
    let mut newest = BTreeMap::new();
    let from = query.from.as_datetime().timestamp_micros();
    let until = query.until.as_datetime().timestamp_micros();
    let received_until = query.received_until.as_datetime().timestamp_micros();
    for record in state.agentteams.values() {
        let at = record.event_time.as_datetime().timestamp_micros();
        if record.tenant_id != query.tenant_id
            || record.scope_id != query.scope_id
            || record.trace_id.as_deref() != Some(query.trace_id.as_str())
            || at < from
            || at >= until
            || record.received_at.as_datetime().timestamp_micros() > received_until
        {
            continue;
        }
        total += 1;
        newest.insert((at, record.id), record);
        if newest.len() > query.limit {
            newest.pop_first();
        }
    }
    Ok(AgentTeamsTraceSnapshot { total, records: newest.into_values().rev().cloned().collect() })
}

#[cfg(test)]
mod tests;
