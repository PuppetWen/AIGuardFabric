//! The API cannot accept target URLs, raw bundles, credentials or alternative grants.
use super::{MAX_POLICIES, MAX_RELATED};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyRevision {
    pub policy_id: Id,
    pub version: u32,
}

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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum PreviewChange {
    Publish { policies: Vec<PolicyRevision> },
    Rollback { publication_id: Id },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreviewInput {
    pub request_id: Id,
    pub configuration_version: u64,
    pub observation_id: Id,
    pub expected_state_version: u64,
    pub change: PreviewChange,
    #[serde(default, deserialize_with = "optional_id", skip_serializing_if = "Option::is_none")]
    pub acknowledge_unknown_operation_id: Option<Id>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApplyInput {
    pub request_id: Id,
    pub preview_id: Id,
    pub expected_state_version: u64,
    pub confirm_apply: bool,
    pub confirm_scope_difference: bool,
    pub confirm_shared_policy_impact: bool,
    pub confirm_no_cloud_cas: bool,
    #[serde(default)]
    pub confirm_live: bool,
    #[serde(default)]
    pub confirm_unknown_overlap: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArchiveInput {
    pub expected_generation: u64,
    pub request_ids: Vec<Id>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoverInput {}

pub(super) fn parse<T: DeserializeOwned>(value: serde_json::Value) -> DomainResult<T> {
    if !value.is_object() {
        return Err(invalid("工作流请求必须为JSON object"));
    }
    serde_json::from_value(value).map_err(|_| invalid("工作流请求字段缺失、未知、类型或范围错误"))
}

impl ObserveInput {
    pub(super) fn validate(&self) -> DomainResult<()> {
        ids(&[self.request_id])?;
        positive(self.configuration_version)
    }
}

impl PreviewInput {
    pub(super) fn normalize(mut self) -> DomainResult<Self> {
        ids(&[self.request_id, self.observation_id])?;
        positive(self.configuration_version)?;
        if let Some(id) = self.acknowledge_unknown_operation_id {
            ids(&[id])?;
        }
        match &mut self.change {
            PreviewChange::Publish { policies } => {
                if policies.is_empty() || policies.len() > MAX_POLICIES {
                    return Err(invalid("请选择一条确切签名平台配额策略版本"));
                }
                let selected = policies.iter().map(|row| row.policy_id).collect::<Vec<_>>();
                ids(&selected)?;
                if selected.iter().copied().collect::<BTreeSet<_>>().len() != selected.len() {
                    return Err(invalid("策略ID不能重复"));
                }
                if policies.iter().any(|row| row.version == 0) {
                    return Err(invalid("策略版本必须为正整数"));
                }
                policies.sort_by_key(|row| row.policy_id);
            }
            PreviewChange::Rollback { publication_id } => ids(&[*publication_id])?,
        }
        Ok(self)
    }
}

impl ApplyInput {
    pub(super) fn validate(&self) -> DomainResult<()> {
        ids(&[self.request_id, self.preview_id])?;
        if !self.confirm_apply
            || !self.confirm_scope_difference
            || !self.confirm_shared_policy_impact
            || !self.confirm_no_cloud_cas
        {
            return Err(DomainError::PreconditionFailed(
                "请明确确认预览、平台与API全局周期差异、共享策略影响未知和无云CAS的外部编辑风险".into(),
            ));
        }
        Ok(())
    }
}

impl ArchiveInput {
    pub(super) fn normalize(mut self) -> DomainResult<Self> {
        if self.request_ids.is_empty() || self.request_ids.len() > MAX_RELATED {
            return Err(invalid("每次明确归档1到100个已结束请求"));
        }
        ids(&self.request_ids)?;
        if self.request_ids.iter().copied().collect::<BTreeSet<_>>().len() != self.request_ids.len() {
            return Err(invalid("归档编号不能重复"));
        }
        self.request_ids.sort();
        Ok(self)
    }
}

fn optional_id<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Id>, D::Error> {
    Id::deserialize(deserializer).map(Some)
}
fn ids(values: &[Id]) -> DomainResult<()> {
    if values.iter().any(Id::is_nil) {
        return Err(invalid("请求与资源ID不能使用空UUID"));
    }
    Ok(())
}
fn positive(version: u64) -> DomainResult<()> {
    if version == 0 {
        return Err(invalid("配置版本必须为正整数"));
    }
    Ok(())
}
fn invalid(detail: &str) -> DomainError {
    DomainError::Validation(detail.into())
}
