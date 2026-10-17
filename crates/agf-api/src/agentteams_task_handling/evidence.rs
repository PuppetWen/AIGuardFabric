use super::util;
use agf_core::{
    error::DomainResult,
    ids::{Id, TenantId, deterministic_id},
    time::Timestamp,
};
use agf_ingest::pipeline::AgentTeamsAuditRecord;
use serde::{Deserialize, Serialize};

/// Original server record identity; an error declaration is not a cloud failure claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FailureEvidence {
    pub(super) event_id: Id,
    pub(super) tenant: TenantId,
    pub(super) scope_id: Id,
    pub(super) source_id: Id,
    pub(super) binding_id: Id,
    pub(super) external_event_id: String,
    pub(super) reported_content_hash: String,
    pub(super) event_time: Timestamp,
    pub(super) received_at: Timestamp,
    pub(super) task_id: Option<String>,
    pub(super) trace_id: Option<String>,
    pub(super) mocked: bool,
    pub(super) message_preview: String,
    pub(super) from_team: Option<String>,
    pub(super) from_worker: Option<String>,
}
impl FailureEvidence {
    /// Called only with the original tenant-filtered audit row, never an Event.raw reconstruction.
    pub(super) fn derive(tenant: TenantId, row: &AgentTeamsAuditRecord) -> DomainResult<Self> {
        if row.tenant_id != tenant
            || tenant.as_uuid().is_nil()
            || [row.id, row.source_id, row.scope_id, row.binding_id].iter().any(Id::is_nil)
            || row.kind != "task"
            || row.status != "error"
            || !util::identifier(&row.external_event_id, 256)
            || !util::digest(&row.content_hash)
            || row.from_asset.is_none() && row.to_asset.is_none()
            || [row.from_asset, row.to_asset].iter().flatten().any(Id::is_nil)
            || row.task_id.as_ref().is_some_and(|value| !util::identifier(value, 128))
            || row.trace_id.as_ref().is_some_and(|value| !util::identifier(value, 128))
        {
            return Err(util::invalid());
        }
        let expected =
            deterministic_id("agf.agentteams.event", &format!("{tenant}:{}:{}", row.scope_id, row.external_event_id));
        if expected != row.id {
            return Err(util::corrupt());
        }
        let evidence = Self {
            event_id: row.id,
            tenant,
            scope_id: row.scope_id,
            source_id: row.source_id,
            binding_id: row.binding_id,
            external_event_id: row.external_event_id.clone(),
            reported_content_hash: row.content_hash.clone(),
            event_time: row.event_time,
            received_at: row.received_at,
            task_id: row.task_id.clone(),
            trace_id: row.trace_id.clone(),
            mocked: row.mocked,
            message_preview: row.message_preview.clone(),
            from_team: row.from_team.clone(),
            from_worker: row.from_worker.clone(),
        };
        evidence.validate()?;
        Ok(evidence)
    }
    /// Also required after authenticating a stored envelope; serde is not identity validation.
    pub(super) fn validate(&self) -> DomainResult<()> {
        if self.tenant.as_uuid().is_nil()
            || [self.event_id, self.source_id, self.scope_id, self.binding_id].iter().any(Id::is_nil)
            || !util::identifier(&self.external_event_id, 256)
            || !util::digest(&self.reported_content_hash)
            || self.message_preview.len() > 8192
            || self.from_team.as_ref().is_some_and(|value| value.len() > 8192)
            || self.from_worker.as_ref().is_some_and(|value| value.len() > 512 || value.chars().any(char::is_control))
            || self.task_id.as_ref().is_some_and(|value| !util::identifier(value, 128))
            || self.trace_id.as_ref().is_some_and(|value| !util::identifier(value, 128))
            || self.event_id
                != deterministic_id(
                    "agf.agentteams.event",
                    &format!("{}:{}:{}", self.tenant, self.scope_id, self.external_event_id),
                )
        {
            return Err(util::corrupt());
        }
        Ok(())
    }
    pub(super) fn hash(&self) -> DomainResult<String> {
        util::hash(self)
    }
}
