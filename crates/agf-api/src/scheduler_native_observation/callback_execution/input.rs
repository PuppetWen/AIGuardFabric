use super::super::util;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdmissionInput {
    pub request_id: Id,
    pub kind: String,
    pub app_id: String,
    pub job_id: String,
    pub job_execution_id: String,
    pub partition_index: u16,
    pub partition_total: u16,
    pub binding_version: u64,
    pub configuration_version: u64,
    pub source_fingerprint: String,
}
impl AdmissionInput {
    pub(super) fn validate(&self) -> DomainResult<()> {
        if self.request_id.is_nil()
            || !super::super::KINDS.contains(&self.kind.as_str())
            || !util::positive_id(&self.app_id)
            || !util::positive_id(&self.job_id)
            || self.job_execution_id.is_empty()
            || self.job_execution_id.len() > 160
            || self.job_execution_id.trim() != self.job_execution_id
            || !self.job_execution_id.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_: .".contains(&c))
            || !(1..=256).contains(&self.partition_total)
            || self.partition_index >= self.partition_total
            || self.binding_version == 0
            || self.configuration_version == 0
            || !util::digest(&self.source_fingerprint)
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClaimInput {
    pub claim_id: Id,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Artifact {
    pub sha256: String,
    pub bytes: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Outcome {
    pub ok: bool,
    pub skipped: bool,
    pub degraded: bool,
    pub artifacts: Vec<Artifact>,
}
impl Outcome {
    pub(super) fn validate(&self) -> DomainResult<()> {
        if self.artifacts.len() > 64
            || (self.skipped && !self.artifacts.is_empty())
            || self.artifacts.iter().any(|artifact| !util::digest(&artifact.sha256))
        {
            return Err(invalid());
        }
        util::bound(self, 16 * 1024)?;
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompleteInput {
    pub claim_id: Id,
    pub outcome: Outcome,
}
pub(super) fn invalid() -> DomainError {
    DomainError::Validation("Scheduler callback 字段、标识或有界结果无效".into())
}

// Set membership is used for evidence uniqueness without relying on arbitrary input order.
pub(super) fn unique_ids(ids: impl IntoIterator<Item = Id>) -> bool {
    let mut unique = BTreeSet::new();
    ids.into_iter().all(|id| !id.is_nil() && unique.insert(id))
}
