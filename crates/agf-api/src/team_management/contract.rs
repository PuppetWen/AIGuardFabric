use super::input::Change;
use agf_core::{ids::Id, time::Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Scope {
    pub id: Id,
    pub cloud_id: Id,
    pub configuration_version: u64,
    pub mocked: bool,
    pub region: String,
    pub instance_id: String,
    pub account_fingerprint: String,
    pub inventory_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Record {
    pub id: Id,
    pub version: u64,
    pub team_name: String,
    pub scope: Option<Scope>,
    pub desired: Option<Change>,
    pub observed: Option<TeamObservation>,
    pub active: Option<Active>,
    pub unresolved_delete: Option<Id>,
    pub previews: BTreeMap<Id, Preview>,
    pub operations: BTreeMap<Id, Operation>,
}
impl Default for Record {
    fn default() -> Self {
        Self {
            id: Id::nil(),
            version: 0,
            team_name: String::new(),
            scope: None,
            desired: None,
            observed: None,
            active: None,
            unresolved_delete: None,
            previews: BTreeMap::new(),
            operations: BTreeMap::new(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Active {
    pub run: Id,
    pub claim: Id,
    pub authorized_at: Timestamp,
    pub expires_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) struct Room {
    pub room_type: String,
    pub room_id: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) struct TeamObservation {
    pub presence: BTreeMap<String, String>,
    pub name: String,
    pub instance_id: String,
    pub description: Option<String>,
    pub member_names: Option<Vec<String>>,
    pub admin_name: Option<String>,
    pub leader_name: Option<String>,
    pub worker_names: Option<Vec<String>>,
    pub rooms: Option<Vec<Room>>,
    pub status: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Preview {
    pub id: Id,
    pub record_id: Id,
    pub request_hash: String,
    pub request_id: Id,
    pub scope: Scope,
    pub state_version: u64,
    pub change: Change,
    pub baseline: Option<TeamObservation>,
    pub baseline_hash: String,
    pub observed_at: Timestamp,
    pub expires_at: Timestamp,
    pub consumed_at: Option<Timestamp>,
    pub verified_users: Vec<UserOption>,
    pub task_count: Option<usize>,
    pub actor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UserOption {
    pub name: String,
    pub display_name: Option<String>,
    pub status: Option<String>,
    pub existence_verified: bool,
    pub admin_eligibility: Option<bool>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct UserQuery {
    pub name_like: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UserDirectory {
    pub snapshot_id: Id,
    pub configuration_version: u64,
    pub scope_id: Id,
    pub mocked: bool,
    pub instance_id: String,
    pub observed_at: Timestamp,
    pub query: UserQuery,
    pub page_complete: bool,
    pub complete: bool,
    pub directory_complete: bool,
    pub next_cursor: Option<String>,
    pub total_count: Option<u64>,
    pub selection_usable: bool,
    pub unusable_reason: Option<String>,
    pub items: Vec<UserOption>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct DirectoryState {
    pub scope: Scope,
    pub latest_request: Id,
    pub latest: Option<UserDirectory>,
    pub cursors: BTreeMap<String, Cursor>,
    #[serde(default)]
    pub requests: BTreeMap<Id, (String, Option<UserDirectory>)>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Cursor {
    pub scope: Scope,
    pub query: UserQuery,
    pub next_token: String,
    pub total: Option<u64>,
    pub pages: u64,
    pub names: Vec<String>,
    pub tokens: Vec<String>,
    pub expires_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Operation {
    pub id: Id,
    pub record_id: Id,
    pub resource_version: u64,
    pub request_id: Id,
    pub request_hash: String,
    pub preview_id: Id,
    pub scope: Scope,
    pub change: Change,
    pub status: String,
    pub started_at: Timestamp,
    pub finished_at: Option<Timestamp>,
    pub lease_expires_at: Timestamp,
    pub cloud_write: CloudWrite,
    pub readback: Readback,
    pub inventory_publish: InventoryPublish,
    pub safe_error: Option<SafeError>,
    pub recovery_request: Option<Id>,
    pub recoveries: BTreeMap<Id, String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CloudWrite {
    pub status: String,
    pub receipt_id: Option<Id>,
    pub provider_request_id: Option<String>,
    pub provider_code: Option<String>,
    pub http_status: Option<u16>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Readback {
    pub status: String,
    pub observed_at: Option<Timestamp>,
    pub resource_state: String,
    pub matched_fields: Vec<String>,
    pub conflict_fields: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct InventoryPublish {
    pub status: String,
    pub checked_at: Option<Timestamp>,
    pub error_code: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SafeError {
    pub code: String,
    pub message: String,
}
