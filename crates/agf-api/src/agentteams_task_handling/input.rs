use super::{MAX_ARCHIVE, MAX_SOURCE_GUARDS, source_proof::SourceFingerprint, util};
use agf_core::{error::DomainResult, ids::Id};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Decision {
    Acknowledged,
    ExternalActionReported,
    ResolvedByOperator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResolutionInput {
    pub(super) request_id: Id,
    pub(super) expected_version: u64,
    pub(super) expected_cloud_configuration_version: u64,
    pub(super) expected_source_fingerprint: SourceFingerprint,
    pub(super) decision: Decision,
}
impl ResolutionInput {
    pub(super) fn validate(&self) -> DomainResult<()> {
        if self.request_id.is_nil() || self.expected_cloud_configuration_version == 0 {
            return Err(util::invalid());
        }
        self.expected_source_fingerprint.validate()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceExpectation {
    pub(super) source_id: Id,
    pub(super) fingerprint: Option<SourceFingerprint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArchiveInput {
    pub(super) request_id: Id,
    pub(super) expected_generation: u64,
    pub(super) expected_cloud_configuration_version: Option<u64>,
    pub(super) event_ids: Vec<Id>,
    pub(super) sources: Vec<SourceExpectation>,
}
impl ArchiveInput {
    pub(super) fn validate(&self) -> DomainResult<()> {
        let events = self.event_ids.iter().collect::<BTreeSet<_>>();
        let sources = self.sources.iter().map(|source| source.source_id).collect::<BTreeSet<_>>();
        if self.request_id.is_nil()
            || events.is_empty()
            || events.len() > MAX_ARCHIVE
            || events.len() != self.event_ids.len()
            || events.iter().any(|id| id.is_nil())
            || sources.is_empty()
            || sources.len() > MAX_SOURCE_GUARDS
            || sources.len() != self.sources.len()
            || sources.iter().any(Id::is_nil)
            || self.expected_cloud_configuration_version == Some(0)
        {
            return Err(util::invalid());
        }
        for source in &self.sources {
            if let Some(fingerprint) = &source.fingerprint {
                fingerprint.validate()?;
            }
        }
        Ok(())
    }
}
