use agf_core::ids::Id;
use serde::{Deserialize, Deserializer, Serialize};

fn non_null<'de, D: Deserializer<'de>, T: Deserialize<'de>>(de: D) -> Result<Option<T>, D::Error> {
    T::deserialize(de).map(Some)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UsersInput {
    pub request_id: Id,
    pub configuration_version: u64,
    #[serde(default)]
    pub confirm_live: bool,
    #[serde(default, deserialize_with = "non_null")]
    pub name_like: Option<String>,
    #[serde(default, deserialize_with = "non_null")]
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreviewInput {
    pub request_id: Id,
    pub configuration_version: u64,
    pub expected_state_version: u64,
    #[serde(default, deserialize_with = "non_null")]
    pub user_snapshot_id: Option<Id>,
    #[serde(default)]
    pub confirm_live: bool,
    pub change: Change,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "lowercase", deny_unknown_fields)]
pub(super) enum Change {
    Create {
        team_name: String,
        #[serde(default, deserialize_with = "non_null", skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        member_names: Vec<String>,
        #[serde(default, deserialize_with = "non_null", skip_serializing_if = "Option::is_none")]
        admin_name: Option<String>,
    },
    Update {
        team_name: String,
        #[serde(default, deserialize_with = "non_null", skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        #[serde(default, deserialize_with = "non_null", skip_serializing_if = "Option::is_none")]
        members: Option<Replacement>,
    },
    Delete {
        team_name: String,
        confirm_team_name: String,
        confirm_async_cleanup: bool,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Replacement {
    pub mode: ReplaceMode,
    pub names: Vec<String>,
    #[serde(rename = "confirm_full_replacement")]
    pub confirmed: bool,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum ReplaceMode {
    Replace,
}

impl Change {
    pub(super) fn team(&self) -> &str {
        match self {
            Self::Create { team_name, .. } | Self::Update { team_name, .. } | Self::Delete { team_name, .. } => {
                team_name
            }
        }
    }
    pub(super) const fn action(&self) -> &'static str {
        match self {
            Self::Create { .. } => "create",
            Self::Update { .. } => "update",
            Self::Delete { .. } => "delete",
        }
    }
    pub(super) const fn cloud_action(&self) -> &'static str {
        match self {
            Self::Create { .. } => "CreateTeam",
            Self::Update { .. } => "UpdateTeam",
            Self::Delete { .. } => "DeleteTeam",
        }
    }
    pub(super) fn members(&self) -> Option<&[String]> {
        match self {
            Self::Create { member_names, .. } => Some(member_names),
            Self::Update { members: Some(members), .. } => Some(&members.names),
            _ => None,
        }
    }
    pub(super) fn description(&self) -> Option<&str> {
        match self {
            Self::Create { description, .. } | Self::Update { description, .. } => description.as_deref(),
            Self::Delete { .. } => None,
        }
    }
    pub(super) fn admin(&self) -> Option<&str> {
        match self {
            Self::Create { admin_name, .. } => admin_name.as_deref(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApplyInput {
    pub request_id: Id,
    pub preview_id: Id,
    pub configuration_version: u64,
    pub expected_state_version: u64,
    #[serde(default)]
    pub confirm_live: bool,
    pub confirm_apply: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryInput {
    pub request_id: Id,
    pub configuration_version: u64,
    #[serde(default)]
    pub confirm_live: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ListQuery {
    pub request_id: Option<Id>,
}
