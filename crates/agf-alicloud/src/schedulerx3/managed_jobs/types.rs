use serde::{Deserialize, Serialize, de};

/// A canonical platform callback kind, never inferred from a provider job name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    AssetInventory,
    LogPull,
    RedteamCruise,
    RuleHotReload,
    Report,
    Archive,
}
impl Kind {
    /// The existing executor name; report/archive keep their public canonical aliases.
    #[must_use]
    pub const fn runtime_name(self) -> &'static str {
        match self {
            Self::AssetInventory => "asset-inventory",
            Self::LogPull => "log-pull",
            Self::RedteamCruise => "redteam-cruise",
            Self::RuleHotReload => "rule-hot-reload",
            Self::Report => "report-generate",
            Self::Archive => "cold-archive",
        }
    }
}

/// Selection from a current complete observation; this value is not an authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub kind: Kind,
    pub app_id: String,
    pub job_id: String,
    pub observation_fingerprint: String,
}

/// Explicit changes to documented scheduling fields. Missing means preserve; null is invalid.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulePatch {
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub time_type: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub time_expression: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub calendar: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub timezone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub max_attempt: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub attempt_interval: Option<i32>,
}
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)?.map(Some).ok_or_else(|| de::Error::custom("explicit null is invalid"))
}

/// A local Mock declaration; it is not a vendor HTTP request carrier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MockDeclaration {
    pub kind: Kind,
    pub name: String,
    pub schedule: SchedulePatch,
    pub total: u32,
}

/// One explicit action. Enabling can never be an implicit suffix of an update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Change {
    CreateDisabled { declaration: MockDeclaration },
    UpdateSchedule { patch: SchedulePatch },
    Disable,
    Enable,
}

// Internally tagged unit variants otherwise ignore extra fields. Empty struct variants
// validate those maps before converting to the established public unit variants.
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum ChangeInput {
    CreateDisabled { declaration: MockDeclaration },
    UpdateSchedule { patch: SchedulePatch },
    Disable {},
    Enable {},
}
impl<'de> Deserialize<'de> for Change {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        Ok(match ChangeInput::deserialize(deserializer)? {
            ChangeInput::CreateDisabled { declaration } => Self::CreateDisabled { declaration },
            ChangeInput::UpdateSchedule { patch } => Self::UpdateSchedule { patch },
            ChangeInput::Disable {} => Self::Disable,
            ChangeInput::Enable {} => Self::Enable,
        })
    }
}

/// A provider ACK classification, separate from current authority and readback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteStatus {
    Accepted,
    Rejected,
    Unknown,
}

/// Safe post-dispatch evidence. No raw response, error text or HTTP carrier is exposed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WriteEvidence {
    /// True means the transport was entered; it does not prove delivery to the vendor.
    pub attempted: bool,
    pub status: WriteStatus,
    pub provider_request_id: Option<String>,
    /// A false value never discards an already known ACK.
    pub authority_current: bool,
    pub original_deadline_current: bool,
}
