//! Original collector task-error reads. No cloud failure or business replay is inferred.
use super::{AgentTeamsAuditRecord, DomainError, DomainResult, Id, TenantId, Timestamp};
use serde::Deserialize;
use serde_json::Value;

pub const AGENTTEAMS_FAILURE_LIMIT: usize = 2000;

#[derive(Debug, Clone)]
pub struct AgentTeamsFailureQuery {
    pub tenant_id: TenantId,
    pub source_id: Option<Id>,
    pub scope_id: Option<Id>,
    pub from: Timestamp,
    pub until: Timestamp,
    pub received_until: Timestamp,
}

#[derive(Debug, Clone, Default)]
pub struct AgentTeamsFailureSnapshot {
    /// Complete matching count from the same statement or memory lock as the bounded rows.
    pub total: u64,
    pub records: Vec<AgentTeamsAuditRecord>,
    pub truncated: bool,
}

pub(super) fn validate_query(query: &AgentTeamsFailureQuery) -> DomainResult<()> {
    let latest = Timestamp::now().offset_secs(60);
    let duration = query.until.as_datetime().signed_duration_since(query.from.as_datetime());
    if query.tenant_id.as_uuid().is_nil()
        || [query.source_id, query.scope_id].into_iter().flatten().any(|id| id.is_nil())
        || query.from > query.until
        || duration > chrono::Duration::days(30)
        || query.until > latest
        || query.received_until > latest
    {
        return Err(DomainError::Validation(
            "Collector error query needs a bounded 30-day window and valid IDs".into(),
        ));
    }
    Ok(())
}

/// Validate a trusted stored projection, including its deterministic original UUID.
pub fn validate_agentteams_failure_record(row: &AgentTeamsAuditRecord, tenant: TenantId) -> DomainResult<()> {
    let expected = agf_core::ids::deterministic_id(
        "agf.agentteams.event",
        &format!("{tenant}:{}:{}", row.scope_id, row.external_event_id),
    );
    if tenant.as_uuid().is_nil()
        || row.tenant_id != tenant
        || [row.id, row.source_id, row.scope_id, row.binding_id].iter().any(Id::is_nil)
        || row.id != expected
        || row.kind != "task"
        || row.status != "error"
        || row.content_hash.len() != 64
        || !row.content_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !identifier(&row.external_event_id, 256)
        || [&row.task_id, &row.trace_id].into_iter().flatten().any(|value| !identifier(value, 128))
        || row.message_preview.len() > 8192
    {
        return Err(corrupt());
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    id: Id,
    tenant_id: TenantId,
    source_id: Id,
    scope_id: Id,
    binding_id: Id,
    external_event_id: String,
    content_hash: String,
    event_time: Timestamp,
    received_at: Timestamp,
    kind: String,
    payload: AgentTeamsAuditRecord,
}

/// Decode only a server-generated SQL column envelope; payload must agree with real columns.
pub fn agentteams_failure_from_envelope(value: Value, tenant: TenantId) -> DomainResult<AgentTeamsAuditRecord> {
    let row: Envelope = serde_json::from_value(value).map_err(|_| corrupt())?;
    let payload = row.payload;
    validate_agentteams_failure_record(&payload, tenant)?;
    if (row.id, row.tenant_id, row.source_id, row.scope_id, row.binding_id)
        != (payload.id, payload.tenant_id, payload.source_id, payload.scope_id, payload.binding_id)
        || row.external_event_id != payload.external_event_id
        || row.content_hash != payload.content_hash
        || row.kind != payload.kind
        || row.event_time.as_datetime().timestamp_micros() != payload.event_time.as_datetime().timestamp_micros()
        || row.received_at.as_datetime().timestamp_micros() != payload.received_at.as_datetime().timestamp_micros()
    {
        return Err(corrupt());
    }
    Ok(payload)
}

fn identifier(value: &str, cap: usize) -> bool {
    !value.is_empty()
        && value.len() <= cap
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
}
pub(super) fn corrupt() -> DomainError {
    DomainError::Crypto("Original collector task-error identity is invalid".into())
}
