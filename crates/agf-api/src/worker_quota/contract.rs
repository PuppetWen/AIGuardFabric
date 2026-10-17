use agf_core::{ids::Id, time::Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct Binding {
    pub version: u64,
    pub asset_id: Id,
    pub worker_name: String,
    pub scope_id: Id,
    pub cloud_id: Id,
    pub cloud_version: u64,
    pub mocked: bool,
    pub quota_id: Id,
    pub enabled: bool,
    pub bound_at: Timestamp,
    pub observation: Option<Observation>,
    #[serde(default)]
    pub observation_request_id: Option<Id>,
    pub last_operation: Option<Id>,
    pub active: Option<Active>,
    #[serde(default)]
    pub used_previews: BTreeMap<Id, Timestamp>,
    #[serde(default)]
    pub drift: Option<Drift>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Drift {
    pub fingerprint: String,
    pub alert_id: Id,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Active {
    pub run_id: Id,
    pub expires_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct CloudLimit {
    pub usage_limit: i64,
    pub limit_type: String,
    pub period_type: String,
    pub rule_status: Option<String>,
    pub used_amount: Option<u64>,
    pub over_limit: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Observation {
    pub id: Id,
    pub observed_at: Timestamp,
    pub quota_version: u64,
    pub cloud_version: u64,
    pub binding_version: u64,
    pub mocked: bool,
    pub preview_usable: bool,
    pub cloud: CloudLimit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Operation {
    pub id: Id,
    pub request_id: Id,
    pub request_hash: String,
    pub status: String,
    pub started_at: Timestamp,
    pub finished_at: Option<Timestamp>,
    pub mocked: bool,
    pub changed: bool,
    pub error: Option<String>,
    pub observation: Option<Observation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BindInput {
    pub expected_version: u64,
    pub quota_id: Id,
    pub quota_version: u64,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ObserveInput {
    pub request_id: Id,
    pub expected_binding_version: u64,
    pub expected_quota_version: u64,
    pub configuration_version: u64,
    #[serde(default)]
    pub confirm_live: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SyncInput {
    pub request_id: Id,
    pub expected_binding_version: u64,
    pub expected_quota_version: u64,
    pub configuration_version: u64,
    pub preview_id: Id,
    #[serde(default)]
    pub confirm_live: bool,
}
