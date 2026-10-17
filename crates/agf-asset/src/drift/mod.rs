//! 差异漂移检测（§4.1：基线快照 + 每日 diff，检出未授权 MCP、Skill 篡改、模型端点替换）。
//!
//! 设计要点：
//! - **纯函数核心**（[`DriftScanner::diff`]）不依赖数据库，可对任意两份资产集合做差分；
//! - 判定"高风险漂移"的规则集中在 [`DriftScanner::classify`]，公开可解释；
//! - 未授权资产（新出现且 `lifecycle` 非生产）默认视为需要人工确认的漂移。

pub(crate) use std::collections::BTreeMap;
pub(crate) use std::collections::BTreeSet;

pub(crate) use agf_core::asset::Asset;
pub(crate) use agf_core::asset::AssetChange;
pub(crate) use agf_core::asset::ChangeKind;

pub(crate) use agf_core::enums::AssetKind;
pub(crate) use agf_core::enums::LifecycleState;
pub(crate) use agf_core::enums::RiskDomain;
pub(crate) use agf_core::enums::Severity;

pub(crate) use agf_core::ids::Id;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use crate::fingerprint::asset_content_hash;

#[cfg(test)]
pub(crate) use agf_core::enums::DataClass;
#[cfg(test)]
pub(crate) use agf_core::enums::DiscoverySource;
#[cfg(test)]
pub(crate) use agf_core::enums::Protocol;

#[cfg(test)]
pub(crate) use agf_core::ids::TenantId;

#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 漂移检测器。
#[derive(Debug, Clone)]
pub struct DriftScanner {
    /// 高风险字段集合（变化即视为高风险漂移）。
    risky_fields: BTreeSet<&'static str>,
    /// 是否把"新增的非生产资产"视为高风险（默认 true，覆盖未授权 MCP/Skill）。
    flag_new_unreviewed: bool,
}

/// 漂移汇总。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DriftSummary {
    /// 变更总数。
    pub total: usize,
    /// 新增数。
    pub added: usize,
    /// 消失数。
    pub removed: usize,
    /// 变更数。
    pub modified: usize,
    /// 高风险数。
    pub risky: usize,
    /// 综合等级。
    pub severity: Severity,
    /// 高风险资产清单（id, 类型, 说明）。
    pub risky_assets: Vec<(Id, AssetKind, Option<String>)>,
}

/// 漂移报告（一次日检的产出）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DriftReport {
    /// 租户。
    pub tenant_id: agf_core::ids::TenantId,
    /// 对比的基线日期。
    pub baseline_date: String,
    /// 当前日期。
    pub current_date: String,
    /// 变更列表。
    pub changes: Vec<AssetChange>,
    /// 汇总。
    pub summary: DriftSummary,
    /// 生成时间。
    pub generated_at: Timestamp,
}

mod impl_drift_scanner;
pub(crate) mod package;
#[cfg(test)]
mod tests;
