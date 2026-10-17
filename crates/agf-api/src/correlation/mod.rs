//! 租户关联规则的配置、样本回归和自动事件分析。
use agf_core::{
    enums::RiskDomain,
    event::Event,
    ids::{Id, TenantId},
    time::Timestamp,
};
use agf_correlate::temporal::{CorrelationRule, GroupBy, RuleStep};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub mod evaluate;
pub mod registry;
pub mod runtime;
pub mod samples;

/// 发布前必须提供完整正负事件序列；最后一条是本次触发事件。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Definition {
    pub rule: CorrelationRule,
    pub domain: RiskDomain,
    pub enabled: bool,
    pub group_by: GroupBy,
    pub window_secs: i64,
    #[serde(default)]
    pub event_filter: RuleStep,
    #[serde(default)]
    pub slot_by_time: bool,
    pub positive: Vec<Event>,
    pub negative: Vec<Event>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revision {
    pub definition: Definition,
    pub version: u64,
    pub actor: String,
    pub changed_at: Timestamp,
    #[serde(default)]
    pub deleted: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Registry {
    pub entries: BTreeMap<String, Vec<Revision>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hit {
    pub event_ids: Vec<Id>,
    pub confidence: f32,
    pub summary: String,
    pub details: serde_json::Value,
}

pub fn group(definition: &Definition, tenant: TenantId, event: &Event) -> Option<String> {
    agf_correlate::temporal::TemporalScanner::new(definition.group_by).group_key(tenant, event)
}
