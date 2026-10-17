//! One memory-sink lock supplies the total and newest bounded original records.
use super::{agentteams_failure::*, sink::MemoryState, *};
#[cfg(test)]
mod tests;

pub(super) fn snapshot(state: &MemoryState, query: &AgentTeamsFailureQuery) -> DomainResult<AgentTeamsFailureSnapshot> {
    super::agentteams_failure::validate_query(query)?;
    let mut rows = BTreeMap::new();
    let mut total = 0_u64;
    for row in state.agentteams.values() {
        let at = row.event_time.as_datetime().timestamp_micros();
        if row.tenant_id != query.tenant_id
            || row.kind != "task"
            || row.status != "error"
            || query.source_id.is_some_and(|id| id != row.source_id)
            || query.scope_id.is_some_and(|id| id != row.scope_id)
            || at < query.from.as_datetime().timestamp_micros()
            || at >= query.until.as_datetime().timestamp_micros()
            || row.received_at.as_datetime().timestamp_micros() > query.received_until.as_datetime().timestamp_micros()
        {
            continue;
        }
        validate_agentteams_failure_record(row, query.tenant_id)?;
        total = total.checked_add(1).ok_or_else(corrupt)?;
        if rows.insert((at, row.id), row).is_some() {
            return Err(corrupt());
        }
        if rows.len() > AGENTTEAMS_FAILURE_LIMIT {
            rows.pop_first();
        }
    }
    Ok(AgentTeamsFailureSnapshot {
        total,
        records: rows.into_values().rev().cloned().collect(),
        truncated: total > AGENTTEAMS_FAILURE_LIMIT as u64,
    })
}

pub(super) fn record(state: &MemoryState, tenant: TenantId, id: Id) -> DomainResult<Option<AgentTeamsAuditRecord>> {
    if tenant.as_uuid().is_nil() || id.is_nil() {
        return Err(corrupt());
    }
    let mut matching = state.agentteams.values().filter(|row| row.tenant_id == tenant && row.id == id);
    let Some(row) = matching.next() else {
        return Ok(None);
    };
    if matching.next().is_some() {
        return Err(corrupt());
    }
    if row.kind != "task" || row.status != "error" {
        return Ok(None);
    }
    validate_agentteams_failure_record(row, tenant)?;
    Ok(Some(row.clone()))
}
