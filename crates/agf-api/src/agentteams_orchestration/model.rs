use super::*;
use agf_alicloud::agentteams::orchestration::{DefinitionDirection, DefinitionDocument};
use agf_core::credential::SecretMaterial;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    pub(super) request_id: Id,
    pub(super) expected_version: u64,
    pub(super) configuration_version: u64,
    pub(super) inventory_fingerprint: String,
    pub(super) change: Change,
    #[serde(default)]
    pub(super) confirm_application_owned: bool,
    #[serde(default)]
    pub(super) confirm_mock_sync: bool,
    #[serde(default)]
    pub(super) confirm_source_change: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Change {
    SaveDefinition { definition: DefinitionDocument },
    Sync { direction: DefinitionDirection },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Source {
    pub(super) tenant: TenantId,
    pub(super) configuration_version: u64,
    #[serde(rename = "source_hash")]
    pub(super) evidence_hash: String,
    pub(super) region: String,
    pub(super) instance_id: String,
    pub(super) inventory_fingerprint: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Record {
    pub(super) team_name: String,
    pub(super) version: u64,
    pub(super) source: Source,
    pub(super) local: Option<DefinitionDocument>,
    pub(super) receiver: Option<DefinitionDocument>,
    pub(super) updated_at: Timestamp,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Difference {
    pub(super) added: Vec<String>,
    pub(super) removed: Vec<String>,
    pub(super) changed: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Intent {
    pub(super) tenant: TenantId,
    pub(super) actor_id: Id,
    pub(super) request_id: Id,
    pub(super) team_name: String,
    pub(super) body_hash: String,
    pub(super) version: u64,
    pub(super) source: Source,
    pub(super) action: String,
    pub(super) direction: Option<DefinitionDirection>,
    pub(super) local_hash: Option<String>,
    pub(super) receiver_hash: Option<String>,
    pub(super) local_node_count: Option<usize>,
    pub(super) receiver_node_count: Option<usize>,
    pub(super) difference: Difference,
    pub(super) committed_at: Timestamp,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct Registry {
    pub(super) tenant: Option<TenantId>,
    pub(super) generation: u64,
    pub(super) records: BTreeMap<String, Record>,
    pub(super) intents: BTreeMap<Id, Intent>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Envelope {
    pub(super) secret: SecretMaterial,
}

/// Default is used only for a genuinely absent row. Persisted null never resets permanent IDs.
#[derive(Debug, Default)]
pub(super) struct Slot(pub(super) Option<Envelope>);
impl Serialize for Slot {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .as_ref()
            .ok_or_else(|| serde::ser::Error::custom("uninitialized orchestration registry"))?
            .serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for Slot {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Envelope::deserialize(deserializer).map(|row| Self(Some(row)))
    }
}
