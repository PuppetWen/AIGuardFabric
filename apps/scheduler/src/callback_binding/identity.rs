use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId, deterministic_id},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Kind {
    AssetInventory,
    LogPull,
    RedteamCruise,
    RuleHotReload,
    Report,
    Archive,
}
impl Kind {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "asset-inventory" => Some(Self::AssetInventory),
            "log-pull" => Some(Self::LogPull),
            "redteam-cruise" => Some(Self::RedteamCruise),
            "rule-hot-reload" => Some(Self::RuleHotReload),
            "report" | "report-generate" => Some(Self::Report),
            "archive" | "cold-archive" => Some(Self::Archive),
            _ => None,
        }
    }
    pub(crate) const fn canonical(self) -> &'static str {
        match self {
            Self::AssetInventory => "asset-inventory",
            Self::LogPull => "log-pull",
            Self::RedteamCruise => "redteam-cruise",
            Self::RuleHotReload => "rule-hot-reload",
            Self::Report => "report",
            Self::Archive => "archive",
        }
    }
    pub(crate) const fn runtime(self) -> &'static str {
        match self {
            Self::Report => "report-generate",
            Self::Archive => "cold-archive",
            _ => self.canonical(),
        }
    }
}

pub(crate) fn positive_id(value: &str) -> bool {
    value.as_bytes().first().is_some_and(|b| (b'1'..=b'9').contains(b))
        && value.bytes().all(|b| b.is_ascii_digit())
        && value.parse::<i64>().is_ok_and(|id| id > 0)
}
pub(crate) fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn valid_execution(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value.trim() == value
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_: .".contains(&b))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Identity {
    pub(crate) kind: Kind,
    pub(crate) app: String,
    pub(crate) job: String,
    pub(crate) execution: String,
    pub(crate) partition: crate::Partition,
}
impl Identity {
    pub(crate) fn validate(&self) -> DomainResult<()> {
        if !positive_id(&self.app)
            || !positive_id(&self.job)
            || !valid_execution(&self.execution)
            || self.partition.total == 0
            || self.partition.total > 256
            || self.partition.index >= self.partition.total
        {
            return Err(DomainError::Validation("云回调身份或分片无效".into()));
        }
        Ok(())
    }
    pub(crate) fn request_id(&self, tenant: TenantId) -> Id {
        deterministic_id(
            "agf.scheduler.callback.request",
            &format!("{tenant}:{}:{}:{}:{}", self.app, self.job, self.execution, self.partition.index),
        )
    }
    pub(crate) fn execution_id(&self) -> String {
        format!("cloud:{}:{}:{}", self.app, self.job, self.execution)
    }
}
