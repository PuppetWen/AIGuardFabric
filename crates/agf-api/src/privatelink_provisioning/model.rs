use super::source::Source;
use agf_alicloud::privatelink::provisioning::{AcceptConnection, CreateEndpoint, EndpointObservation};
use agf_core::{
    credential::SecretMaterial,
    ids::{Id, TenantId},
    rbac::SubjectKind,
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
pub(super) type Key = (String, Id);
pub(super) type Values = BTreeMap<Key, Option<Value>>;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Envelope {
    pub tenant: TenantId,
    pub id: Id,
    pub kind: String,
    pub hash: String,
    pub secret: SecretMaterial,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Owner {
    pub tenant: TenantId,
    pub identity_tenant: TenantId,
    pub kind: SubjectKind,
    pub subject: Option<Id>,
    pub agent: Option<Id>,
}
#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    pub tenant: Option<TenantId>,
    pub generation: u64,
    pub facts: u64,
    pub stored_bytes: u64,
    pub items: Vec<Id>,
    pub risks: BTreeMap<String, Id>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Intent {
    Create { target: Box<CreateEndpoint> },
    Accept { target: AcceptConnection, planned: Box<CreateEndpoint>, observation_id: Id },
}
impl Intent {
    pub(super) fn planned(&self) -> &CreateEndpoint {
        match self {
            Self::Create { target } => target,
            Self::Accept { planned, .. } => planned,
        }
    }
    pub(super) fn endpoint(&self) -> Option<&str> {
        match self {
            Self::Create { .. } => None,
            Self::Accept { target, .. } => Some(&target.endpoint_id),
        }
    }
    pub(super) fn prepare(
        &self,
        id: Id,
    ) -> agf_core::error::DomainResult<agf_alicloud::privatelink::provisioning::PreparedChange> {
        match self {
            Self::Create { target } => target.prepare(id),
            Self::Accept { target, .. } => target.prepare(id),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Purpose {
    Preview,
    Apply,
    Observe,
    Archive,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Admitted,
    Started,
    Complete,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Delivery {
    NotSent,
    Acknowledged,
    Rejected,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Write {
    pub delivery: Delivery,
    pub provider_request_id: Option<Id>,
    pub endpoint_id: Option<String>,
    pub finished_at: Timestamp,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Evidence {
    pub plan: Box<CreateEndpoint>,
    pub observation: EndpointObservation,
    pub checked_at: Timestamp,
    pub original_create_id: Option<Id>,
    pub inventory_scope_id: Option<Id>,
    pub inventory_payload_hash: Option<String>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ResultData {
    Preview { expires_at: Timestamp, base_generation: u64 },
    Write { outcome: Write },
    Observed { evidence: Box<Evidence> },
    FailedRead,
    Archived { changed_count: u64, generation: u64 },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fact {
    pub tenant: TenantId,
    pub id: Id,
    pub owner: Owner,
    pub purpose: Purpose,
    pub input_hash: String,
    pub source: Option<Source>,
    pub intent: Option<Intent>,
    pub reference: Option<Id>,
    pub submitted_at: Timestamp,
    pub admitted_at: Timestamp,
    pub lease_expires_at: Timestamp,
    pub claim_id: Id,
    pub phase: Phase,
    pub started_at: Option<Timestamp>,
    pub result: Option<ResultData>,
    pub archived_at: Option<Timestamp>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Package {
    pub tenant: TenantId,
    pub id: Id,
    pub intent: Intent,
    pub source: Source,
    pub base_generation: u64,
    pub expires_at: Timestamp,
    pub consumed_by: Option<Id>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pending {
    pub claim_hash: String,
    pub fact_id: Id,
    pub tenant: TenantId,
    pub outcome: ResultData,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Marker {
    pub tenant: TenantId,
    pub id: Id,
    pub archived_at: Timestamp,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MockEndpoint {
    pub plan: Box<CreateEndpoint>,
    pub connection: String,
}
#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MockRecord {
    pub tenant: Option<TenantId>,
    pub endpoints: BTreeMap<String, MockEndpoint>,
    pub writes: u64,
    pub reads: u64,
}
