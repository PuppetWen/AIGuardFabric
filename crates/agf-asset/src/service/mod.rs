//! 资产服务：发现入库（幂等）、生命周期流转、盘点统计、快照与漂移。
//!
//! 与 `agf-auth::service` 相同的设计：核心逻辑通过 [`AssetBackend`] trait 与存储解耦，
//! 生产由 `agf-server` 用 `agf-storage::AssetRepo` 实现，单元测试用
//! [`InMemoryAssetBackend`]，因此"发现 → 归并 → 生命周期 → 漂移"整条链路可离线验证。

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::sync::Mutex;

pub(crate) use agf_core::asset::Asset;
pub(crate) use agf_core::asset::AssetChange;

pub(crate) use agf_core::enums::AssetKind;
pub(crate) use agf_core::enums::DiscoverySource;
pub(crate) use agf_core::enums::LifecycleState;
pub(crate) use agf_core::enums::Severity;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::time::Date;
pub(crate) use agf_core::time::Timestamp;

pub(crate) use async_trait::async_trait;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use tracing::info;
pub(crate) use tracing::warn;

pub(crate) use crate::discovery::DiscoveredAsset;
pub(crate) use crate::discovery::DiscoveryBatch;
pub(crate) use crate::discovery::to_asset;

pub(crate) use crate::drift::DriftReport;
pub(crate) use crate::drift::DriftScanner;

pub(crate) use crate::fingerprint::asset_content_hash;

#[allow(unused_imports)]
pub use impl_in_memory_asset_backend::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 生命周期流转请求（含审批信息，供审计）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleTransition {
    /// 目标资产。
    pub asset_id: Id,
    /// 目标状态。
    pub to: LifecycleState,
    /// 操作人。
    pub actor: String,
    /// 说明/评审意见。
    pub note: String,
    /// 数据分级评审结论（流转到生产时必填）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_class: Option<agf_core::enums::DataClass>,
    /// 归属人（流转到生产时建议填写）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// 归属部门。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
}

/// 资产仓储抽象。
#[async_trait]
pub trait AssetBackend: Send + Sync {
    /// 按指纹查找（用于幂等入库）。
    ///
    /// # Errors
    /// 存储错误。
    async fn find_by_fingerprint(&self, tenant: TenantId, fingerprint: &str) -> DomainResult<Option<Asset>>;

    /// 按 id 查找。
    ///
    /// # Errors
    /// 存储错误。
    async fn find(&self, tenant: TenantId, id: Id) -> DomainResult<Option<Asset>>;

    /// 列出全部资产。
    ///
    /// # Errors
    /// 存储错误。
    async fn list_all(&self, tenant: TenantId) -> DomainResult<Vec<Asset>>;

    /// 插入或更新。
    ///
    /// # Errors
    /// 存储错误。
    async fn upsert(&self, tenant: TenantId, asset: &Asset) -> DomainResult<Id>;

    /// 记录变更。
    ///
    /// # Errors
    /// 存储错误。
    async fn record_change(&self, tenant: TenantId, change: &AssetChange) -> DomainResult<()>;

    /// 记录快照。
    ///
    /// # Errors
    /// 存储错误。
    async fn snapshot(&self, tenant: TenantId, date: &str, asset: &Asset) -> DomainResult<()>;

    /// 读取指定日期快照的 `asset_id → content_hash`。
    ///
    /// # Errors
    /// 存储错误。
    async fn snapshot_hashes(&self, tenant: TenantId, date: &str) -> DomainResult<BTreeMap<Id, String>>;
}

/// 入库统计。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IngestStats {
    /// 新增资产数。
    pub created: usize,
    /// 更新资产数。
    pub updated: usize,
    /// 未变化（指纹命中且内容哈希一致）。
    pub unchanged: usize,
    /// 产生的变更记录数。
    pub changes: usize,
    /// 高风险变更数。
    pub risky_changes: usize,
    /// 新发现凭据数。
    pub credentials: usize,
    /// 警告。
    pub warnings: Vec<String>,
}

/// 盘点统计（资产台账页顶部指标）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InventoryStats {
    /// 资产总数。
    pub total: usize,
    /// 按类型分布。
    pub by_kind: BTreeMap<String, usize>,
    /// 按生命周期分布。
    pub by_lifecycle: BTreeMap<String, usize>,
    /// 按发现来源分布。
    pub by_source: BTreeMap<String, usize>,
    /// 影子资产数（试用状态且非手工登记）。
    pub shadow: usize,
    /// 高暴露资产数（≥70）。
    pub high_exposure: usize,
    /// 含明文凭据的资产数。
    pub with_plaintext_secret: usize,
    /// 平均暴露面评分。
    pub avg_exposure: f32,
}

/// 资产服务。
#[derive(Debug, Clone)]
pub struct AssetService {
    drift: DriftScanner,
}

// ===========================================================================
// 内存后端
// ===========================================================================

/// 内存资产后端（测试与离线演示）。
#[derive(Debug, Default)]
pub struct InMemoryAssetBackend {
    assets: Mutex<BTreeMap<(TenantId, Id), Asset>>,
    changes: Mutex<Vec<AssetChange>>,
    snapshots: Mutex<BTreeMap<(TenantId, String, Id), String>>,
}

mod impl_in_memory_asset_backend;
mod impl_lifecycle_transition;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_legacy_drift;

mod review;
pub use review::{apply_review, next_review_time};
