use super::util;
use agf_core::{
    enums::DataClass,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Mode {
    Live,
    MockVector,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Settings {
    pub(crate) chat_endpoint_id: Id,
    pub(crate) chat_model: String,
    pub(crate) chat_model_revision: String,
    pub(crate) embedding_endpoint_id: Id,
    pub(crate) embedding_model: String,
    pub(crate) embedding_model_revision: String,
    pub(crate) dimensions: u16,
    pub(crate) send_dimensions: bool,
    pub(crate) max_input_tokens: u32,
    pub(crate) embedding_micro_per_1k: u64,
    pub(crate) threshold_ppm: u32,
    pub(crate) ttl_seconds: u32,
    pub(crate) classification_floor: DataClass,
    pub(crate) mode: Mode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileInput {
    pub(crate) expected_version: u64,
    pub(crate) enabled: bool,
    pub(crate) settings: Option<Settings>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredProfile {
    pub(super) tenant: TenantId,
    pub(super) id: Id,
    pub(super) version: u64,
    pub(super) enabled: bool,
    pub(super) settings: Option<Settings>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProfileView {
    pub(crate) version: u64,
    pub(crate) enabled: bool,
    pub(crate) settings: Option<Settings>,
    pub(crate) placement_verified: bool,
    pub(crate) provider_weights_revision_verified: bool,
}

impl Settings {
    pub(super) fn validate(&self) -> DomainResult<()> {
        if self.chat_endpoint_id.is_nil()
            || self.embedding_endpoint_id.is_nil()
            || [&self.chat_model, &self.chat_model_revision, &self.embedding_model, &self.embedding_model_revision]
                .iter()
                .any(|value| !identifier(value))
            || !(1..=4096).contains(&self.dimensions)
            || !(1..=8192).contains(&self.max_input_tokens)
            || !(900_000..=1_000_000).contains(&self.threshold_ppm)
            || !(1..=900).contains(&self.ttl_seconds)
            || !matches!(self.classification_floor, DataClass::Public | DataClass::Internal)
            || self.mode == Mode::Live && self.embedding_micro_per_1k == 0
            || self.mode == Mode::MockVector && self.embedding_micro_per_1k != 0
            || configured_cost(1_000_000, self.embedding_micro_per_1k).is_none()
        {
            return Err(util::invalid());
        }
        util::bounded(self, 8192)
    }
    pub(super) fn threshold(&self) -> f64 {
        f64::from(self.threshold_ppm) / 1_000_000.0
    }
}

impl ProfileInput {
    pub(super) fn validate(&self) -> DomainResult<()> {
        if self.enabled && self.settings.is_none() {
            return Err(util::invalid());
        }
        if let Some(settings) = &self.settings {
            settings.validate()?;
        }
        util::bounded(self, 16 * 1024)
    }
    pub(super) fn apply(&self, tenant: TenantId, current: Option<&StoredProfile>) -> DomainResult<StoredProfile> {
        self.validate()?;
        if let Some(row) = current {
            row.validate(tenant)?;
        }
        let version = current.map_or(0, |row| row.version);
        if version != self.expected_version {
            return Err(DomainError::Conflict(
                "Semantic profile changed; read the current version before saving".into(),
            ));
        }
        Ok(StoredProfile {
            tenant,
            id: util::record_id(tenant),
            version: version.checked_add(1).ok_or_else(util::corrupt)?,
            enabled: self.enabled,
            settings: self.settings.clone(),
        })
    }
}

impl StoredProfile {
    pub(super) fn validate(&self, tenant: TenantId) -> DomainResult<()> {
        if self.tenant != tenant
            || self.id != util::record_id(tenant)
            || self.version == 0
            || self.enabled && self.settings.is_none()
        {
            return Err(util::corrupt());
        }
        if let Some(settings) = &self.settings {
            settings.validate().map_err(|_| util::corrupt())?;
        }
        util::bounded(self, 16 * 1024)
    }
    pub(super) fn view(&self) -> ProfileView {
        ProfileView {
            version: self.version,
            enabled: self.enabled,
            settings: self.settings.clone(),
            // A saved mode is configuration intent; only the planner verifies current endpoints.
            placement_verified: false,
            provider_weights_revision_verified: false,
        }
    }
}
pub(super) fn absent_view() -> ProfileView {
    ProfileView {
        version: 0,
        enabled: false,
        settings: None,
        placement_verified: false,
        provider_weights_revision_verified: false,
    }
}
pub(super) fn configured_cost(tokens: u64, price: u64) -> Option<u64> {
    u64::try_from(u128::from(tokens).checked_mul(u128::from(price))?.checked_add(999)? / 1000).ok()
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_.-:/".contains(&byte))
}
