use super::{input::Assignment, scope::SourceTarget};
use agf_core::{
    credential::SecretMaterial,
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) const STATE: &str = "scheduler-native-state";
pub(super) const FACT: &str = "scheduler-native-fact";
pub(super) const BODY: &str = "scheduler-native-observation";
pub(super) const BINDING: &str = "scheduler-native-bindings";
pub(super) const MOCK: &str = "scheduler-native-driver-mock";
pub(super) type Values = BTreeMap<(String, Id), Option<Value>>;
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    pub tenant: Option<TenantId>,
    pub version: u64,
    pub generation: u64,
    pub active: Option<Active>,
    pub observations: Vec<Id>,
    pub latest: Option<Id>,
    pub stored_bytes: usize,
    pub archived_count: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Active {
    pub request_id: Id,
    pub claim_id: Id,
    pub generation: u64,
    pub expires_at: Timestamp,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Purpose {
    Observe,
    Replace,
    Disable,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fact {
    pub tenant: TenantId,
    pub request_id: Id,
    pub purpose: Purpose,
    pub input_hash: String,
    pub target: Option<SourceTarget>,
    pub claim_id: Id,
    pub generation: u64,
    pub started_at: Timestamp,
    pub submitted_at: Timestamp,
    pub expires_at: Timestamp,
    pub status: String,
    pub finished_at: Option<Timestamp>,
    pub reason: Option<String>,
    pub total: Option<u32>,
    pub app_id: Option<String>,
    pub fingerprint: Option<String>,
    pub body_bytes: usize,
    pub binding_version: Option<u64>,
    pub binding_result: Option<BindingRecord>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredBody {
    pub tenant: TenantId,
    pub request_id: Id,
    pub target: SourceTarget,
    pub app_id: String,
    pub hash: String,
    pub secret: SecretMaterial,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum BodyRecord {
    Content(Box<StoredBody>),
    Archived { tenant: TenantId, request_id: Id, archived_at: Timestamp, original_status: String },
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BindingRecord {
    pub tenant: Option<TenantId>,
    pub version: u64,
    pub enabled: bool,
    pub target: Option<SourceTarget>,
    pub observation_id: Option<Id>,
    pub app_id: Option<String>,
    pub fingerprint: Option<String>,
    pub verified_at: Option<Timestamp>,
    pub items: Vec<Assignment>,
    #[serde(default)]
    pub adoption_version: u64,
    #[serde(default)]
    pub adopted_proofs: Vec<super::proof::AdoptedProof>,
    #[serde(default)]
    pub eligibility: Vec<super::eligibility::Qualification>,
    #[serde(default)]
    pub qualification_seal: Option<super::proof::AdoptedProof>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MockRecord {
    pub tenant: TenantId,
    pub scope_id: Id,
    pub hash: String,
    pub secret: SecretMaterial,
}
