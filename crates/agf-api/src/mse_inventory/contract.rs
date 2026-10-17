//! Public inputs are strict; the ledger contains no provider credentials or raw response bodies.
use agf_core::{credential::SecretMaterial, ids::Id, time::Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyncInput {
    pub request_id: Id,
    pub configuration_version: u64,
    #[serde(default)]
    pub confirm_live: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveInput {
    pub expected_generation: u64,
    pub request_ids: Vec<Id>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Scope {
    pub id: Id,
    pub cloud_id: Id,
    pub configuration_version: u64,
    pub source_identity: String,
    pub region: String,
    pub instance_id: String,
    pub namespace_id: String,
    pub mocked: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct Lease {
    pub run_id: Id,
    pub claim_id: Id,
    pub generation: u64,
    pub expires_at: Timestamp,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct Run {
    pub request_id: Id,
    pub request_hash: String,
    pub scope: Scope,
    pub claim_id: Id,
    pub generation: u64,
    pub status: String,
    pub started_at: Timestamp,
    #[serde(default)]
    pub submitted_at: Option<Timestamp>,
    pub finished_at: Option<Timestamp>,
    pub pages_read: u64,
    pub services_observed: u64,
    pub published: bool,
    pub note: String,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub archived_at: Option<Timestamp>,
    #[serde(default)]
    pub original_status: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct Archived {
    pub run: Run,
    pub archived_at: Timestamp,
}

#[derive(Default, Deserialize, Serialize)]
pub(super) struct Record {
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub archived_count: u64,
    #[serde(default)]
    pub active: Option<Lease>,
    #[serde(default)]
    pub runs: BTreeMap<Id, Run>,
    #[serde(default)]
    pub snapshot: Option<SecretMaterial>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct Service {
    pub key: String,
    pub name: String,
    pub group: String,
    pub instance_count: Option<u64>,
    pub healthy_count: Option<u64>,
    pub cluster_count: Option<u64>,
    pub source: Option<String>,
    pub asset_id: Option<Id>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct Snapshot {
    pub scope: Scope,
    pub started_at: Timestamp,
    pub checked_at: Timestamp,
    pub pages_read: u64,
    pub services: Vec<Service>,
}

impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MseInventoryRecord")
            .field("generation", &self.generation)
            .field("run_count", &self.runs.len())
            .field("snapshot_present", &self.snapshot.is_some())
            .finish_non_exhaustive()
    }
}
