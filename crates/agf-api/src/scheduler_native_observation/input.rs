use super::{KINDS, util};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ObserveInput {
    pub request_id: Id,
    pub configuration_version: u64,
    #[serde(default)]
    pub confirm_live: bool,
    #[serde(default)]
    pub initialize_mock_fixture: bool,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Assignment {
    pub kind: String,
    pub job_id: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum BindingInput {
    Replace {
        request_id: Id,
        expected_version: u64,
        configuration_version: u64,
        observation_id: Id,
        bindings: Vec<Assignment>,
        confirm_local_only: bool,
    },
    Disable {
        request_id: Id,
        expected_version: u64,
    },
}
impl BindingInput {
    pub(super) fn request(&self) -> Id {
        match self {
            Self::Replace { request_id, .. } | Self::Disable { request_id, .. } => *request_id,
        }
    }
    pub(super) fn version(&self) -> u64 {
        match self {
            Self::Replace { expected_version, .. } | Self::Disable { expected_version, .. } => *expected_version,
        }
    }
    pub(super) fn validate(&mut self) -> DomainResult<()> {
        if self.request().is_nil() {
            return Err(invalid());
        }
        if let Self::Replace { configuration_version, observation_id, bindings, confirm_local_only, .. } = self {
            if *configuration_version == 0 || observation_id.is_nil() || !*confirm_local_only || bindings.len() > 6 {
                return Err(invalid());
            }
            let mut kinds = BTreeSet::new();
            let mut jobs = BTreeSet::new();
            for row in bindings.iter() {
                if !KINDS.contains(&row.kind.as_str())
                    || !kinds.insert(&row.kind)
                    || !jobs.insert(&row.job_id)
                    || !util::positive_id(&row.job_id)
                {
                    return Err(invalid());
                }
            }
            bindings.sort_by(|a, b| a.kind.cmp(&b.kind));
        }
        Ok(())
    }
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArchiveInput {
    pub expected_generation: u64,
    pub request_ids: Vec<Id>,
}
impl ArchiveInput {
    pub(super) fn validate(&self) -> DomainResult<()> {
        if self.request_ids.is_empty()
            || self.request_ids.len() > super::MAX_ARCHIVE
            || self.request_ids.iter().any(Id::is_nil)
            || self.request_ids.iter().collect::<BTreeSet<_>>().len() != self.request_ids.len()
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PageQuery {
    #[serde(default = "one")]
    pub page: u32,
    #[serde(default = "hundred")]
    pub page_size: u32,
}
impl Default for PageQuery {
    fn default() -> Self {
        Self { page: 1, page_size: 100 }
    }
}
impl PageQuery {
    pub(super) fn validate(&self) -> DomainResult<()> {
        if self.page == 0 || !(1..=100).contains(&self.page_size) {
            return Err(invalid());
        }
        Ok(())
    }
}
fn one() -> u32 {
    1
}
fn hundred() -> u32 {
    100
}
fn invalid() -> DomainError {
    DomainError::Validation("Scheduler 参数、编号或明确确认无效".into())
}
