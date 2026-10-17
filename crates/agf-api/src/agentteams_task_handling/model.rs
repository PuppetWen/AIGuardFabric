use super::{Decision, FailureEvidence, MAX_ACTIVE, MAX_HISTORY, util};
use agf_core::{
    audit::AuditAction,
    error::DomainResult,
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// This value is constructed from the authenticated Principal, never deserialized from a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Actor {
    pub(super) subject_id: Id,
    pub(super) identity_tenant: TenantId,
    pub(super) subject_kind: String,
}
impl Actor {
    pub(super) fn validate(&self) -> DomainResult<()> {
        if self.subject_id.is_nil()
            || self.identity_tenant.as_uuid().is_nil()
            || !matches!(self.subject_kind.as_str(), "user" | "api-key" | "agent" | "service")
        {
            return Err(util::corrupt());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    pub(super) tenant: TenantId,
    pub(super) generation: u64,
    pub(super) active_event_ids: BTreeSet<Id>,
    pub(super) archived_count: u64,
}
impl Journal {
    pub(super) fn new(tenant: TenantId) -> Self {
        Self { tenant, generation: 0, active_event_ids: BTreeSet::new(), archived_count: 0 }
    }
    pub(super) fn validate(&self, tenant: TenantId) -> DomainResult<()> {
        if self.tenant != tenant
            || tenant.as_uuid().is_nil()
            || self.active_event_ids.len() > MAX_ACTIVE
            || self.active_event_ids.iter().any(Id::is_nil)
        {
            return Err(util::corrupt());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Revision {
    pub(super) request_id: Id,
    pub(super) version: u64,
    pub(super) decision: Decision,
    pub(super) subject_id: Id,
    pub(super) subject_kind: String,
    pub(super) at: Timestamp,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Handling {
    pub(super) evidence: FailureEvidence,
    pub(super) current: Revision,
    pub(super) history: Vec<Revision>,
    /// Known original UUIDs remain readable through permanent per-request records after archive.
    pub(super) request_ids: Vec<Id>,
    pub(super) archived_at: Option<Timestamp>,
}
impl Handling {
    pub(super) fn validate(&self, evidence: &FailureEvidence) -> DomainResult<()> {
        evidence.validate()?;
        let ids = self.request_ids.iter().collect::<BTreeSet<_>>();
        if self.evidence != *evidence
            || self.current.version == 0
            || self.current.request_id.is_nil()
            || self.current.subject_id.is_nil()
            || !matches!(self.current.subject_kind.as_str(), "user" | "api-key" | "agent" | "service")
            || self.request_ids.is_empty()
            || self.request_ids.len() > MAX_HISTORY
            || ids.len() != self.request_ids.len()
            || ids.iter().any(|id| id.is_nil())
            || self.request_ids.last() != Some(&self.current.request_id)
            || self.current.version != u64::try_from(self.request_ids.len()).map_err(|_| util::corrupt())?
            || self.history.len() > MAX_HISTORY
        {
            return Err(util::corrupt());
        }
        if self.archived_at.is_some_and(|at| at < self.current.at) {
            return Err(util::corrupt());
        }
        if self.archived_at.is_some() {
            if !self.history.is_empty() {
                return Err(util::corrupt());
            }
        } else {
            if self.history.len() != self.request_ids.len() || self.history.last() != Some(&self.current) {
                return Err(util::corrupt());
            }
            for (offset, row) in self.history.iter().enumerate() {
                if row.version != u64::try_from(offset).map_err(|_| util::corrupt())? + 1
                    || row.request_id != self.request_ids[offset]
                    || row.subject_id.is_nil()
                    || !matches!(row.subject_kind.as_str(), "user" | "api-key" | "agent" | "service")
                {
                    return Err(util::corrupt());
                }
            }
        }
        util::bounded(self, 128 * 1024)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResolutionReceipt {
    pub(super) request_id: Id,
    pub(super) event_id: Id,
    pub(super) version: u64,
    pub(super) decision: Decision,
    pub(super) updated_at: Timestamp,
    pub(super) evidence_identity_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArchiveReceipt {
    pub(super) request_id: Id,
    pub(super) generation: u64,
    pub(super) archived_count: u64,
    pub(super) event_ids: Vec<Id>,
    pub(super) changed_count: usize,
    pub(super) evidence_identity_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "purpose", content = "value", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Receipt {
    Resolution(Box<ResolutionReceipt>),
    Archive(Box<ArchiveReceipt>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RequestFact {
    pub(super) tenant: TenantId,
    pub(super) request_id: Id,
    pub(super) purpose: String,
    pub(super) input_hash: String,
    pub(super) receipt: Receipt,
}
impl RequestFact {
    pub(super) fn validate(&self, tenant: TenantId, request: Id) -> DomainResult<()> {
        if self.tenant != tenant
            || self.request_id != request
            || request.is_nil()
            || !matches!(self.purpose.as_str(), "operator-resolution" | "operator-archive")
            || !util::digest(&self.input_hash)
        {
            return Err(util::corrupt());
        }
        match &self.receipt {
            Receipt::Resolution(row) => {
                if self.purpose != "operator-resolution"
                    || row.request_id != request
                    || row.event_id.is_nil()
                    || row.version == 0
                    || !util::digest(&row.evidence_identity_hash)
                {
                    return Err(util::corrupt());
                }
            }
            Receipt::Archive(row) => {
                let ids = row.event_ids.iter().collect::<BTreeSet<_>>();
                if self.purpose != "operator-archive"
                    || row.request_id != request
                    || ids.is_empty()
                    || ids.len() > super::MAX_ARCHIVE
                    || ids.len() != row.event_ids.len()
                    || ids.iter().any(|id| id.is_nil())
                    || row.changed_count > ids.len()
                    || !util::digest(&row.evidence_identity_hash)
                {
                    return Err(util::corrupt());
                }
            }
        }
        util::bounded(self, 16 * 1024)
    }
    pub(super) fn resolution(&self) -> DomainResult<&ResolutionReceipt> {
        match &self.receipt {
            Receipt::Resolution(row) => Ok(row),
            Receipt::Archive(_) => Err(util::corrupt()),
        }
    }
    pub(super) fn archive(&self) -> DomainResult<&ArchiveReceipt> {
        match &self.receipt {
            Receipt::Archive(row) => Ok(row),
            Receipt::Resolution(_) => Err(util::corrupt()),
        }
    }
}

/// Safe audit intent. The adapter creates the complete AuditLog from the original trusted actor.
#[derive(Debug, Clone, Serialize)]
pub(super) struct AuditSummary {
    pub(super) action: AuditAction,
    pub(super) target_kind: String,
    pub(super) request_id: Id,
    pub(super) event_id: Option<Id>,
    pub(super) from_version: Option<u64>,
    pub(super) to_version: Option<u64>,
    pub(super) decision: Option<Decision>,
    pub(super) archived_count: Option<usize>,
}
pub(super) struct ResolutionChange {
    pub(super) journal: Journal,
    pub(super) handling: Handling,
    pub(super) request_fact: RequestFact,
    pub(super) audit: AuditSummary,
}
pub(super) enum ResolutionPlan {
    Replay(ResolutionReceipt),
    Write(Box<ResolutionChange>),
}
pub(super) struct ArchiveChange {
    pub(super) journal: Journal,
    pub(super) tombstones: Vec<Handling>,
    pub(super) request_fact: RequestFact,
    pub(super) audit: AuditSummary,
}
pub(super) enum ArchivePlan {
    Replay(ArchiveReceipt),
    Write(Box<ArchiveChange>),
}
