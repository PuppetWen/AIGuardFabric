//! Typed, bounded AgentTeams audit storage. These values come from a verified API binding.
use super::{DomainError, DomainResult, Id, IngestProtocol, IngestWrite, TenantId, Timestamp};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct AgentTeamsBindingGuard {
    pub tenant_id: TenantId,
    pub source_id: Id,
    pub binding_id: Id,
    pub binding_version: u64,
    pub cloud_config_id: Id,
    pub cloud_version: u64,
    pub scope_id: Id,
    pub source_updated_at: Timestamp,
    pub inventory_updated_at: Timestamp,
}

/// Safe projection only: no raw payload, arbitrary attributes or claimed authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentTeamsAuditRecord {
    pub id: Id,
    pub tenant_id: TenantId,
    pub scope_id: Id,
    pub source_id: Id,
    pub binding_id: Id,
    pub external_event_id: String,
    pub content_hash: String,
    pub event_time: Timestamp,
    pub received_at: Timestamp,
    pub kind: String,
    pub from_team: Option<String>,
    pub from_worker: Option<String>,
    pub from_asset: Option<Id>,
    pub to_team: Option<String>,
    pub to_worker: Option<String>,
    pub to_asset: Option<Id>,
    pub task_id: Option<String>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    pub status: String,
    pub duration_ms: Option<u64>,
    pub message_preview: String,
    pub mocked: bool,
}

#[derive(Debug, Clone)]
pub struct AgentTeamsIngestItem {
    pub write: IngestWrite,
    pub audit: AgentTeamsAuditRecord,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentTeamsIngestResult {
    pub accepted: usize,
    pub deduped: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AgentTeamsAuditCursor {
    pub event_time: Timestamp,
    pub id: Id,
}

#[derive(Debug, Clone)]
pub struct AgentTeamsAuditQuery {
    pub tenant_id: TenantId,
    pub scope_id: Id,
    pub from: Timestamp,
    pub until: Timestamp,
    pub before: Option<AgentTeamsAuditCursor>,
    pub limit: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentTeamsAuditAggregate {
    pub invocations: u64,
    pub messages: u64,
    pub tasks: u64,
    pub heartbeats: u64,
    pub last_received_at: Option<Timestamp>,
    pub last_heartbeat_at: Option<Timestamp>,
    pub sources: Vec<AgentTeamsSourceObservation>,
    pub workers: Vec<AgentTeamsWorkerCount>,
    pub cross_team_calls: Vec<AgentTeamsCrossTeamCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTeamsWorkerCount {
    pub worker: String,
    pub invocations: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTeamsSourceObservation {
    pub source_id: Id,
    pub binding_id: Id,
    pub first_received_at: Timestamp,
    pub last_received_at: Timestamp,
    pub last_heartbeat_at: Option<Timestamp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTeamsCrossTeamCount {
    pub from_team: String,
    pub to_team: String,
    pub to_worker: Option<String>,
    pub count: u64,
}

pub(super) fn unsupported() -> DomainError {
    DomainError::PreconditionFailed("This ingest sink does not support atomic AgentTeams audit storage".into())
}

pub(super) fn validate_window(from: Timestamp, until: Timestamp) -> DomainResult<()> {
    if from >= until || until.since_secs(&from) > 31 * 86_400 {
        return Err(DomainError::Validation("Audit window must be positive and at most 31 days".into()));
    }
    Ok(())
}

pub(super) fn validate_query(query: &AgentTeamsAuditQuery) -> DomainResult<()> {
    validate_window(query.from, query.until)?;
    if !(1..=200).contains(&query.limit) || query.scope_id.is_nil() {
        return Err(DomainError::Validation("Audit query needs a scope and limit between 1 and 200".into()));
    }
    Ok(())
}

pub(super) fn validate_items(guard: &AgentTeamsBindingGuard, items: &[AgentTeamsIngestItem]) -> DomainResult<()> {
    if [guard.source_id, guard.binding_id, guard.cloud_config_id, guard.scope_id].iter().any(Id::is_nil)
        || guard.tenant_id.as_uuid().is_nil()
        || guard.binding_version == 0
        || guard.cloud_version == 0
        || items.len() > 1000
    {
        return Err(DomainError::Validation("Invalid audit binding identity or batch size".into()));
    }
    for item in items {
        let audit = &item.audit;
        let event = item
            .write
            .event
            .as_ref()
            .ok_or_else(|| DomainError::Validation("AgentTeams audit requires a normalized event".into()))?;
        // Event.time is the normalized occurrence time mirrored by the audit projection.
        let occurrence_time_matches = audit.event_time == event.time;
        if audit.tenant_id != guard.tenant_id
            || audit.source_id != guard.source_id
            || audit.binding_id != guard.binding_id
            || audit.scope_id != guard.scope_id
            || audit.id.is_nil()
            || audit.id != event.id
            || !occurrence_time_matches
            || audit.received_at != item.write.raw.received_at
            || event.tenant_id != guard.tenant_id
            || event.source_id != guard.source_id
            || event.protocol != IngestProtocol::Webhook
            || item.write.raw.tenant_id != guard.tenant_id
            || item.write.raw.source_id != guard.source_id
            || item.write.raw.protocol != IngestProtocol::Webhook
            || item.write.raw.event_id != Some(event.id)
        {
            return Err(DomainError::Validation(
                "Audit, event and raw evidence identities do not match binding".into(),
            ));
        }
        if !matches!(audit.kind.as_str(), "call" | "message" | "task" | "heartbeat")
            || !matches!(audit.status.as_str(), "success" | "error" | "unknown")
            || audit.content_hash.len() != 64
            || !audit.content_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            || audit.external_event_id.trim().is_empty()
            || audit.external_event_id.len() > 256
            || audit.message_preview.len() > 8192
        {
            return Err(DomainError::Validation(
                "Invalid audit kind, status, event ID, hash or message preview".into(),
            ));
        }
        let fields = [
            Some(audit.external_event_id.as_str()),
            Some(audit.message_preview.as_str()),
            audit.from_team.as_deref(),
            audit.from_worker.as_deref(),
            audit.to_team.as_deref(),
            audit.to_worker.as_deref(),
            audit.task_id.as_deref(),
            audit.trace_id.as_deref(),
            audit.span_id.as_deref(),
            audit.parent_span_id.as_deref(),
        ];
        if fields.into_iter().flatten().any(|value| value.contains('\0'))
            || [
                audit.from_team.as_ref(),
                audit.from_worker.as_ref(),
                audit.to_team.as_ref(),
                audit.to_worker.as_ref(),
                audit.task_id.as_ref(),
                audit.trace_id.as_ref(),
                audit.span_id.as_ref(),
                audit.parent_span_id.as_ref(),
            ]
            .into_iter()
            .flatten()
            .any(|value| value.is_empty() || value.len() > 512)
        {
            return Err(DomainError::Validation("Audit identifiers must be bounded nonempty text without NUL".into()));
        }
    }
    Ok(())
}
