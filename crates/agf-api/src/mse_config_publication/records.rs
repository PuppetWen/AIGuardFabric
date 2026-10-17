//! Permanent request facts are separate from bounded encrypted content and indices.
use super::{
    contract::{DependencyEvidence, Scope},
    input::PolicyRevision,
};
use agf_core::{
    audit::AuditActor,
    credential::SecretMaterial,
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(super) const STATE: &str = "mse-config-publication-state";
pub(super) const FACT: &str = "mse-config-publication-fact";
pub(super) const DETAIL: &str = "mse-config-publication-detail";
pub(super) const PREVIEW: &str = "mse-config-publication-preview";
pub(super) const PENDING: &str = "mse-config-publication-pending";
pub(super) const POLICY: &str = "signed-policy-registry";

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Main {
    pub tenant: Option<TenantId>,
    pub version: u64,
    pub generation: u64,
    pub observations: Vec<Id>,
    pub previews: Vec<Id>,
    pub operations: Vec<Id>,
    pub latest_observation: Option<Id>,
    pub active: Option<Active>,
    pub archived_count: u64,
    pub stored_content_bytes: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Active {
    pub request_id: Id,
    pub expires_at: Timestamp,
}

/// One fixed-size marker per target scope remembers that old requests may still arrive.
/// The immutable facts retain every unknown result even after detail archival.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Risk {
    pub tenant: TenantId,
    pub scope_id: Id,
    pub latest_unknown: Id,
    pub unknown_count: u64,
    pub lease_expires_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Purpose {
    Observation,
    Preview,
    Operation,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fact {
    pub tenant: TenantId,
    pub request_id: Id,
    pub purpose: Purpose,
    pub request_hash: String,
    pub scope: Scope,
    pub created_at: Timestamp,
    pub actor: AuditActor,
    pub outcome: FactOutcome,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum FactOutcome {
    Reading { finished_at: Option<Timestamp>, failed: bool },
    Prepared { consumed_by: Option<Id> },
    Operation { receipt: Box<Operation> },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Observation {
    pub tenant: TenantId,
    pub request_id: Id,
    pub original_operation_id: Option<Id>,
    pub scope: Scope,
    pub started_at: Timestamp,
    pub observed_at: Timestamp,
    pub content_md5: String,
    pub content_hash: String,
    pub content_bytes: usize,
    pub content: SecretMaterial,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fence {
    pub policies: Vec<PolicyRevision>,
    pub dependencies: Vec<DependencyEvidence>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Prepared {
    pub tenant: TenantId,
    pub request_id: Id,
    pub scope: Scope,
    pub state_version: u64,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub action: Action,
    pub source_publication_id: Option<Id>,
    pub observation_id: Id,
    pub baseline_observed_at: Timestamp,
    pub baseline_md5: String,
    pub baseline_hash: String,
    pub baseline_bytes: usize,
    pub desired_hash: String,
    pub desired_bytes: usize,
    pub source_policy_versions: Vec<PolicyRevision>,
    pub fence: Fence,
    pub acknowledge_unknown_operation_id: Option<Id>,
    pub baseline: SecretMaterial,
    pub desired: SecretMaterial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Action {
    Publish,
    Rollback,
}

/// Operation content reuses the preview ciphertext; verified history adds no third body.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Detail {
    pub tenant: TenantId,
    pub request_id: Id,
    pub prepared: Prepared,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "class", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum DetailRecord {
    Content { data: Box<Detail> },
    Archived { marker: ArchiveMarker },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArchiveMarker {
    pub tenant: TenantId,
    pub request_id: Id,
    pub archived_at: Timestamp,
    pub original_status: Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Status {
    Started,
    Verified,
    Conflict,
    Failed,
    Uncertain,
    Superseded,
    Archived,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum WriteStatus {
    NotAttempted,
    Attempting,
    Accepted,
    Conflict,
    Rejected,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReadStatus {
    NotAttempted,
    Matched,
    Different,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PublicationStatus {
    NotStaged,
    PendingAudit,
    Published,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Operation {
    pub request_id: Id,
    pub preview_id: Id,
    pub action: Action,
    pub source_publication_id: Option<Id>,
    pub submitted_at: Timestamp,
    pub started_at: Timestamp,
    pub lease_expires_at: Timestamp,
    pub finished_at: Option<Timestamp>,
    pub status: Status,
    pub original_status: Option<Status>,
    pub archived_at: Option<Timestamp>,
    pub cloud_write: WriteStatus,
    pub readback: ReadStatus,
    pub readback_observed_at: Option<Timestamp>,
    pub readback_hash: Option<String>,
    pub local_publication: PublicationStatus,
    pub safe_reason: Option<String>,
    pub desired_hash: String,
    pub desired_bytes: usize,
    pub source_policy_versions: Vec<PolicyRevision>,
    pub superseded_by: Option<Id>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pending {
    pub tenant: TenantId,
    pub request_id: Id,
    pub request_hash: String,
    pub completion_hash: String,
    pub completion: SecretMaterial,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Completion {
    pub receipt: Operation,
}

pub(super) type Values = BTreeMap<(String, Id), Option<serde_json::Value>>;
