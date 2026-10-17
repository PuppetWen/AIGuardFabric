//! Explicitly ephemeral single-process storage; API callers must recheck lifecycle guards.
use super::{agentteams_audit::*, sink::MemoryState, *};

pub(super) fn persist(
    state: &mut MemoryState,
    guard: &AgentTeamsBindingGuard,
    items: &[AgentTeamsIngestItem],
) -> DomainResult<AgentTeamsIngestResult> {
    validate_items(guard, items)?;
    let mut pending = BTreeMap::new();
    let mut accepted = Vec::new();
    let mut result = AgentTeamsIngestResult::default();
    // Validate all claims first. A conflicting later item must not leak earlier writes.
    for item in items {
        let audit = &item.audit;
        let key = (audit.tenant_id, audit.scope_id, audit.external_event_id.clone());
        if let Some(previous) = state.agentteams.get(&key).or_else(|| pending.get(&key)) {
            if previous.content_hash != audit.content_hash {
                return Err(DomainError::Conflict("AgentTeams event ID already has different content".into()));
            }
            result.deduped += 1;
            continue;
        }
        if state.agentteams.values().any(|previous| previous.tenant_id == audit.tenant_id && previous.id == audit.id)
            || pending.values().any(|previous: &AgentTeamsAuditRecord| {
                previous.tenant_id == audit.tenant_id && previous.id == audit.id
            })
            || state.events.iter().any(|event| event.tenant_id == audit.tenant_id && event.id == audit.id)
            || state.raws.iter().any(|raw| raw.id == item.write.raw.id)
            || accepted.iter().any(|previous: &&AgentTeamsIngestItem| previous.write.raw.id == item.write.raw.id)
        {
            return Err(DomainError::Conflict("AgentTeams audit, event or raw identity already exists".into()));
        }
        pending.insert(key, audit.clone());
        accepted.push(item);
        result.accepted += 1;
    }
    for item in accepted {
        state.raws.push(item.write.raw.clone());
        if let Some(event) = &item.write.event {
            state.events.push(event.clone());
        }
    }
    state.agentteams.extend(pending);
    Ok(result)
}

pub(super) fn records(state: &MemoryState, query: &AgentTeamsAuditQuery) -> DomainResult<Vec<AgentTeamsAuditRecord>> {
    validate_query(query)?;
    let mut rows: Vec<_> = window(state, query.tenant_id, query.scope_id, query.from, query.until)
        .filter(|row| query.before.is_none_or(|cursor| (row.event_time, row.id) < (cursor.event_time, cursor.id)))
        .cloned()
        .collect();
    rows.sort_by_key(|row| std::cmp::Reverse((row.event_time, row.id)));
    rows.truncate(query.limit);
    Ok(rows)
}

fn window(
    state: &MemoryState,
    tenant: TenantId,
    scope: Id,
    from: Timestamp,
    until: Timestamp,
) -> impl Iterator<Item = &AgentTeamsAuditRecord> {
    state.agentteams.values().filter(move |row| {
        row.tenant_id == tenant && row.scope_id == scope && row.event_time >= from && row.event_time < until
    })
}

pub(super) fn aggregate(
    state: &MemoryState,
    tenant: TenantId,
    scope: Id,
    from: Timestamp,
    until: Timestamp,
) -> DomainResult<AgentTeamsAuditAggregate> {
    validate_window(from, until)?;
    if scope.is_nil() {
        return Err(DomainError::Validation("Audit aggregate requires a scope".into()));
    }
    let mut result = AgentTeamsAuditAggregate::default();
    let mut workers = BTreeMap::<String, u64>::new();
    let mut cross = BTreeMap::<(String, String, Option<String>), u64>::new();
    let mut sources = BTreeMap::<(Id, Id), AgentTeamsSourceObservation>::new();
    for row in window(state, tenant, scope, from, until) {
        result.last_received_at = result.last_received_at.max(Some(row.received_at));
        let source = sources.entry((row.source_id, row.binding_id)).or_insert_with(|| AgentTeamsSourceObservation {
            source_id: row.source_id,
            binding_id: row.binding_id,
            first_received_at: row.received_at,
            last_received_at: row.received_at,
            last_heartbeat_at: None,
        });
        source.first_received_at = source.first_received_at.min(row.received_at);
        source.last_received_at = source.last_received_at.max(row.received_at);
        if row.kind == "heartbeat" {
            source.last_heartbeat_at = source.last_heartbeat_at.max(Some(row.received_at));
        }
        match row.kind.as_str() {
            "call" => {
                result.invocations += 1;
                if let Some(worker) = row.to_worker.as_ref().or(row.from_worker.as_ref()) {
                    *workers.entry(worker.clone()).or_default() += 1;
                }
                if let (Some(from), Some(to)) = (&row.from_team, &row.to_team) {
                    if from != to {
                        *cross.entry((from.clone(), to.clone(), row.to_worker.clone())).or_default() += 1;
                    }
                }
            }
            "message" => result.messages += 1,
            "task" => result.tasks += 1,
            "heartbeat" => {
                result.heartbeats += 1;
                result.last_heartbeat_at = result.last_heartbeat_at.max(Some(row.received_at));
            }
            _ => {}
        }
    }
    result.workers =
        workers.into_iter().map(|(worker, invocations)| AgentTeamsWorkerCount { worker, invocations }).collect();
    result.sources = sources.into_values().collect();
    result.cross_team_calls = cross
        .into_iter()
        .map(|((from_team, to_team, to_worker), count)| AgentTeamsCrossTeamCount {
            from_team,
            to_team,
            to_worker,
            count,
        })
        .collect();
    Ok(result)
}
