use super::super::{scope::SourceTarget, util};
use super::input::{ApplyInput, PreviewInput};
use agf_alicloud::schedulerx3::managed_jobs::{Kind, Readback, WriteEvidence};
use agf_core::{
    credential::SecretMaterial,
    error::DomainResult,
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(in super::super) const STATE: &str = "scheduler-managed-job-state";
pub(in super::super) const PREVIEW: &str = "scheduler-managed-job-preview";
pub(in super::super) const OPERATION: &str = "scheduler-managed-job-operation";
pub(in super::super) const REQUEST: &str = "scheduler-managed-job-request";
pub(in super::super) const PENDING: &str = "scheduler-managed-job-pending";
pub(super) const MAX_RUNS: usize = 128;
pub(super) const MAX_DETAIL: usize = 256 * 1024;
pub(super) const MAX_STORED: usize = 64 * 1024 * 1024;
pub(super) const MAX_MOCK_JOBS: usize = 128;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Envelope {
    pub(super) tenant: TenantId,
    pub(super) id: Id,
    pub(super) hash: String,
    pub(super) secret: SecretMaterial,
}
impl std::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedEnvelope").field("id", &self.id).finish_non_exhaustive()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Purpose {
    Preview,
    Apply,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Index {
    pub(super) tenant: TenantId,
    pub(super) request_id: Id,
    pub(super) purpose: Purpose,
    pub(super) actor: Id,
    pub(super) hash: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    pub(super) tenant: Option<TenantId>,
    pub(super) version: u64,
    pub(super) generation: u64,
    pub(super) previews: Vec<Id>,
    pub(super) operations: Vec<Id>,
    pub(super) active: Option<Active>,
    pub(super) definitions: Vec<Definition>,
    pub(super) archived_count: u64,
    pub(super) stored_bytes: usize,
    pub(super) unknown: Vec<Uncertain>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Active {
    pub(super) request_id: Id,
    pub(super) claim_id: Id,
    pub(super) scope_id: Id,
    pub(super) expires_at: Timestamp,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Definition {
    pub(super) scope_id: Id,
    pub(super) kind: Kind,
    pub(super) job_id: String,
    pub(super) request_id: Id,
    pub(super) total: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RiskIdentity {
    pub(super) tenant: TenantId,
    pub(super) cluster_id: String,
    pub(super) app_name: String,
}
impl RiskIdentity {
    pub(super) fn of(target: &SourceTarget) -> Self {
        Self { tenant: target.tenant, cluster_id: target.cluster_id.clone(), app_name: target.app_name.clone() }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Uncertain {
    pub(super) resource: RiskIdentity,
    pub(super) request_id: Id,
    pub(super) scope_id: Id,
    pub(super) expires_at: Timestamp,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Preview {
    pub(super) tenant: TenantId,
    pub(super) id: Id,
    pub(super) actor: Id,
    pub(super) input_hash: String,
    pub(super) input: PreviewInput,
    pub(super) target: SourceTarget,
    pub(super) created_at: Timestamp,
    pub(super) expires_at: Timestamp,
    pub(super) app_id: String,
    pub(super) baseline_fingerprint: String,
    pub(super) before: Option<Value>,
    pub(super) desired: Value,
    pub(super) fingerprint: String,
    pub(super) operation_id: Option<Id>,
    pub(super) archived_at: Option<Timestamp>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum PreviewRecord {
    Content(Box<Preview>),
    Archived(Box<ArchivedPreview>),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArchivedPreview {
    pub(super) tenant: TenantId,
    pub(super) id: Id,
    pub(super) actor: Id,
    pub(super) input_hash: String,
    pub(super) target: SourceTarget,
    pub(super) fingerprint: String,
    pub(super) created_at: Timestamp,
    pub(super) archived_at: Timestamp,
    pub(super) operation_id: Option<Id>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum State {
    Started,
    PendingAudit,
    Complete,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Operation {
    pub(super) tenant: TenantId,
    pub(super) request_id: Id,
    pub(super) actor: Id,
    pub(super) claim_id: Id,
    pub(super) input_hash: String,
    pub(super) input: ApplyInput,
    pub(super) target: SourceTarget,
    pub(super) preview: Option<Box<Preview>>,
    pub(super) started_at: Timestamp,
    pub(super) submitted_at: Timestamp,
    pub(super) expires_at: Timestamp,
    pub(super) finished_at: Option<Timestamp>,
    pub(super) state: State,
    pub(super) write: Option<WriteEvidence>,
    pub(super) readback: Readback,
    pub(super) job_id: Option<String>,
    pub(super) action: String,
    pub(super) kind: Kind,
    pub(super) readback_at: Option<Timestamp>,
    pub(super) readback_fingerprint: Option<String>,
    pub(super) archived_at: Option<Timestamp>,
    pub(super) detail_bytes: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Known {
    pub(super) domain: String,
    pub(super) tenant: TenantId,
    pub(super) request_id: Id,
    pub(super) claim_id: Id,
    pub(super) input_hash: String,
    pub(super) write: WriteEvidence,
    pub(super) readback: Readback,
    pub(super) job_id: Option<String>,
    pub(super) staged_at: Timestamp,
}
pub(super) fn bump(journal: &mut Journal, tenant: TenantId) -> DomainResult<()> {
    journal.tenant = Some(tenant);
    journal.version = journal.version.checked_add(1).ok_or_else(util::capacity)?;
    journal.generation = journal.generation.checked_add(1).ok_or_else(util::capacity)?;
    Ok(())
}
pub(super) fn validate_journal(row: &Journal, tenant: TenantId) -> DomainResult<()> {
    if row.tenant.is_some_and(|owner| owner != tenant)
        || row.previews.len() > MAX_RUNS
        || row.operations.len() > MAX_RUNS
        || row.stored_bytes > MAX_STORED
        || row.definitions.len() > 6 * MAX_RUNS
        || row.unknown.len() > MAX_RUNS
    {
        return Err(util::corrupt());
    }
    let mut scopes = std::collections::BTreeSet::new();
    for unknown in &row.unknown {
        if unknown.request_id.is_nil()
            || unknown.scope_id.is_nil()
            || unknown.resource.tenant != tenant
            || !util::text(&unknown.resource.cluster_id, 256)
            || !util::text(&unknown.resource.app_name, 256)
            || !scopes.insert((&unknown.resource.cluster_id, &unknown.resource.app_name))
        {
            return Err(util::corrupt());
        }
    }
    for ids in [&row.previews, &row.operations] {
        if ids.iter().any(Id::is_nil) || ids.iter().collect::<std::collections::BTreeSet<_>>().len() != ids.len() {
            return Err(util::corrupt());
        }
    }
    if row
        .active
        .as_ref()
        .is_some_and(|active| active.request_id.is_nil() || active.claim_id.is_nil() || active.scope_id.is_nil())
    {
        return Err(util::corrupt());
    }
    let mut slots = std::collections::BTreeSet::new();
    let mut jobs = std::collections::BTreeSet::new();
    for definition in &row.definitions {
        if definition.scope_id.is_nil()
            || definition.request_id.is_nil()
            || !util::positive_id(&definition.job_id)
            || definition.total != 1
            || !slots.insert((definition.scope_id, definition.kind.runtime_name()))
            || !jobs.insert((definition.scope_id, &definition.job_id))
        {
            return Err(util::corrupt());
        }
    }
    util::bound(row, MAX_DETAIL)?;
    Ok(())
}
