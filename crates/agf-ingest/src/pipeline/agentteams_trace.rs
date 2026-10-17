//! Trace-specific reads do not change the legacy audit-page query contract.
use super::{AgentTeamsAuditRecord, DomainError, DomainResult, Id, TenantId, Timestamp};

pub const AGENTTEAMS_TRACE_NODE_LIMIT: usize = 2000;
pub const AGENTTEAMS_TRACE_WINDOW_SECS: i64 = 30 * 86_400;

#[derive(Debug, Clone)]
pub struct AgentTeamsTraceQuery {
    pub tenant_id: TenantId,
    pub scope_id: Id,
    pub trace_id: String,
    pub from: Timestamp,
    pub until: Timestamp,
    /// Server receive-time watermark. Late commits can still change later statements.
    pub received_until: Timestamp,
    pub limit: usize,
}

#[derive(Debug, Clone, Default)]
pub struct AgentTeamsTraceSnapshot {
    /// All matching events, independent of the bounded record count.
    pub total: u64,
    /// Newest first, using PostgreSQL microsecond event-time precision and then ID.
    pub records: Vec<AgentTeamsAuditRecord>,
}

pub(super) fn validate(query: &AgentTeamsTraceQuery) -> DomainResult<()> {
    let now = Timestamp::now().offset_secs(60);
    let duration = query.until.as_datetime().signed_duration_since(query.from.as_datetime());
    if query.tenant_id.as_uuid().is_nil()
        || query.scope_id.is_nil()
        || !(1..=AGENTTEAMS_TRACE_NODE_LIMIT).contains(&query.limit)
        || query.from >= query.until
        || duration > chrono::Duration::seconds(AGENTTEAMS_TRACE_WINDOW_SECS)
        || query.until > now
        || query.received_until > now
        || !valid_trace_id(&query.trace_id)
    {
        return Err(DomainError::Validation(
            "Trace query requires a valid scope, bounded trace ID and 30-day window".into(),
        ));
    }
    Ok(())
}

#[must_use]
pub fn valid_trace_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
}
