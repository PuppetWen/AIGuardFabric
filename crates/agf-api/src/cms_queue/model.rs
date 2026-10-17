use super::source::Source;
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
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Item {
    pub tenant: TenantId,
    pub id: Id,
    pub enqueue_id: Id,
    pub owner: Owner,
    pub source: Source,
    pub name: String,
    pub action: String,
    pub payload_hash: String,
    pub payload_bytes: u64,
    pub queued_at: Timestamp,
    pub attempts: Vec<Id>,
    pub archived_at: Option<Timestamp>,
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
    Accepted,
    Rejected,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Outcome {
    pub delivery: Delivery,
    pub provider_request_id: Option<String>,
    pub finished_at: Timestamp,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Attempt {
    pub tenant: TenantId,
    pub id: Id,
    pub item_id: Id,
    pub request_id: Id,
    pub owner: Owner,
    pub source: Source,
    pub admitted_at: Timestamp,
    pub lease_expires_at: Timestamp,
    pub phase: Phase,
    pub started_at: Option<Timestamp>,
    pub outcome: Option<Outcome>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Purpose {
    Enqueue,
    Send,
    Archive,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub tenant: TenantId,
    pub id: Id,
    pub purpose: Purpose,
    pub input_hash: String,
    pub owner: Owner,
    pub item_ids: Vec<Id>,
    pub attempt_ids: Vec<Id>,
    pub submitted_at: Timestamp,
    pub changed_count: u64,
    pub generation: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Body {
    pub tenant: TenantId,
    pub item_id: Id,
    pub payload: super::input::Payload,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pending {
    pub attempt: Attempt,
    pub outcome: Outcome,
}

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MockRecord {
    pub tenant: Option<TenantId>,
    pub source_id: Option<Id>,
    pub source_hash: String,
    pub accepted: BTreeMap<Id, String>,
}
