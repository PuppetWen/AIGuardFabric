use super::super::util;
use agf_alicloud::schedulerx3::managed_jobs::{Change, Selection};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use serde::{Deserialize, Serialize, de};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreviewInput {
    pub(super) request_id: Id,
    pub(super) configuration_version: u64,
    pub(super) expected_binding_version: u64,
    pub(super) observation_id: Id,
    pub(super) change: Change,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
    pub(super) selection: Option<Selection>,
}
impl PreviewInput {
    pub(super) fn validate(&self) -> DomainResult<()> {
        if self.request_id.is_nil() || self.observation_id.is_nil() || self.configuration_version == 0 {
            return Err(invalid());
        }
        match (&self.change, &self.selection) {
            (Change::CreateDisabled { declaration }, None) => declaration.validate(),
            (Change::CreateDisabled { .. }, Some(_)) => Err(invalid()),
            (Change::UpdateSchedule { patch }, Some(selected)) => {
                validate_selection(selected)?;
                patch.validate()
            }
            (Change::Disable | Change::Enable, Some(selected)) => validate_selection(selected),
            _ => Err(invalid()),
        }
    }
}
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)?.map(Some).ok_or_else(|| de::Error::custom("explicit null is invalid"))
}
fn validate_selection(selection: &Selection) -> DomainResult<()> {
    if !util::positive_id(&selection.app_id)
        || !util::positive_id(&selection.job_id)
        || !util::digest(&selection.observation_fingerprint)
    {
        return Err(invalid());
    }
    Ok(())
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApplyInput {
    pub(super) preview_id: Id,
    pub(super) preview_fingerprint: String,
    pub(super) confirm_no_cloud_cas: bool,
    pub(super) confirm_callback_unknown: bool,
    #[serde(default)]
    pub(super) confirm_live: bool,
    #[serde(default)]
    pub(super) confirm_unknown_overlap: bool,
}
impl ApplyInput {
    pub(super) fn validate(&self) -> DomainResult<()> {
        if self.preview_id.is_nil()
            || !util::digest(&self.preview_fingerprint)
            || !self.confirm_no_cloud_cas
            || !self.confirm_callback_unknown
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArchiveInput {
    pub(super) expected_generation: u64,
    pub(super) request_ids: Vec<Id>,
    pub(super) confirm_loss_of_preview: bool,
}
impl ArchiveInput {
    pub(super) fn validate(&self) -> DomainResult<()> {
        let ids = self.request_ids.iter().collect::<std::collections::BTreeSet<_>>();
        if self.request_ids.is_empty()
            || self.request_ids.len() > 48
            || ids.len() != self.request_ids.len()
            || self.request_ids.iter().any(Id::is_nil)
            || !self.confirm_loss_of_preview
        {
            return Err(invalid());
        }
        Ok(())
    }
}
pub(super) fn invalid() -> DomainError {
    DomainError::Validation("Scheduler受管请求字段、确认或身份无效".into())
}
