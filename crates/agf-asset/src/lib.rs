//! # agf-asset — 资产域
//!
//! 覆盖 §4.1 资产管理：发现、盘点、拓扑血缘、生命周期、差异漂移。
//!
//! ## 模块与职责
//!
//! | 模块 | 职责 | 是否纯函数 |
//! |---|---|---|
//! | [`fingerprint`] | 资产指纹（去重键）、类型推断、暴露面入参推导 | ✅ 纯函数 |
//! | [`topology`] | 由资产 + 依赖构图、可达性、外传路径、影响面 | ✅ 纯函数 |
//! | [`drift`] | 基线快照对比、日间 diff、未授权资产判定 | ✅ 纯函数 |
//! | [`discovery`] | 发现来源统一入口（终端上报 / Git 扫描 / 网段 / 手工） | 部分纯函数 |
//! | [`service`] | 资产 CRUD、生命周期流转、盘点统计 | 需要存储 |
//!
//! ## 降级行为
//!
//! | 依赖 | 未配置时 |
//! |---|---|
//! | 网段扫描 | 仅做 TCP 连通性探测，无 Agent 的资产需人工登记（登记 PV-009） |
//! | 云 API | 由 `agf-alicloud` / `agf-adapters` 提供；未配置则该发现源不产出（不报错） |
//! | 远端 Git | 本地目录扫描可用；远端仓库需要凭据（登记 PV-008） |

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![cfg_attr(test, allow(clippy::panic))]

pub mod discovery;
pub mod drift;
pub mod fingerprint;
pub mod service;
pub mod topology;

pub use discovery::{DiscoveredAsset, DiscoveryBatch, GitScanner, NetworkScanTarget, NetworkScanner};
pub use drift::{DriftReport, DriftScanner};
pub use fingerprint::{
    agent_fingerprint, asset_content_hash, asset_fingerprint, asset_id_from_fingerprint, exposure_input_from_asset,
    infer_kind_from_endpoint, infer_kind_from_protocol, mcp_fingerprint, model_endpoint_fingerprint,
};
pub use service::{AssetService, InventoryStats, LifecycleTransition};
pub use topology::{TopologyBuilder, TopologySummary};

/// 平台版本。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
