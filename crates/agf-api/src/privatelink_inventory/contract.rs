//! Public inputs are strict; persisted observations use an explicit safe field allowlist.
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
    pub endpoint_id: String,
    pub mocked: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct Lease {
    pub run_id: Id,
    pub claim_id: Id,
    pub generation: u64,
    pub expires_at: Timestamp,
}

#[derive(Debug, Clone, Default)]
pub(super) struct Progress {
    pub pages_read: u64,
    pub endpoints_observed: u64,
    pub zones_observed: u64,
    pub security_groups_observed: u64,
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
    pub submitted_at: Option<Timestamp>,
    pub finished_at: Option<Timestamp>,
    pub pages_read: u64,
    pub endpoints_observed: u64,
    pub zones_observed: u64,
    pub security_groups_observed: u64,
    pub published: bool,
    pub note: String,
    pub archived: bool,
    pub archived_at: Option<Timestamp>,
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
pub(super) struct EndpointObservation {
    pub id: String,
    pub name: Option<String>,
    pub region: Option<String>,
    pub vpc_id: Option<String>,
    pub service_id: Option<String>,
    pub service_region_id: Option<String>,
    pub domain: Option<String>,
    pub endpoint_type: Option<String>,
    pub status: Option<String>,
    pub connection_status: Option<String>,
    pub business_status: Option<String>,
    pub observed_at: Timestamp,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct Zone {
    pub id: String,
    pub region: Option<String>,
    pub status: Option<String>,
    pub eni_id: Option<String>,
    pub vswitch_id: Option<String>,
    pub eni_ip: Option<String>,
    pub ipv6: Option<String>,
    pub domain: Option<String>,
    pub observed_at: Timestamp,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct SecurityGroup {
    pub id: String,
    pub status: Option<String>,
    pub observed_at: Timestamp,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct Snapshot {
    pub scope: Scope,
    pub started_at: Timestamp,
    pub checked_at: Timestamp,
    pub pages_read: u64,
    pub asset_id: Option<Id>,
    pub endpoint: EndpointObservation,
    pub zones: Vec<Zone>,
    pub security_groups: Vec<SecurityGroup>,
}

impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateLinkInventoryRecord")
            .field("generation", &self.generation)
            .field("run_count", &self.runs.len())
            .field("snapshot_present", &self.snapshot.is_some())
            .finish_non_exhaustive()
    }
}
