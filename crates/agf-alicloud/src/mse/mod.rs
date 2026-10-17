//! MSE（微服务引擎）适配器：Nacos 服务清单同步、配置热更新、云原生网关信息（§5.2）。
//!
//! ## 为什么 MSE 是"资产自动发现源"
//!
//! 客户的 MCP Server / Agent / 模型端点通常以 Nacos 服务形式注册。把它们拉回来
//! 转成 [`agf_core::cloud::CloudResourceMapping`] 与 [`agf_core::asset::Asset`]，
//! 就不需要靠"网段扫描碰运气"来发现资产。服务名与 metadata 约定：
//!
//! | metadata 键 | 取值 | 映射资产类型 |
//! |---|---|---|
//! | `kind` | `mcp-server` / `agent` / `model-endpoint` / `skill` | `AssetKind::McpServer` / `Agent` / `ModelEndpoint` / `Skill` |
//! | `protocol` | `mcp-http` / `mcp-sse` / `a2a` / `openai-compat` … | `Protocol` |
//! | `endpoint` | `host:port` | `Asset::endpoint` |
//! | `data_class` | `public` / `internal` / `confidential` / `restricted` | `DataClass` |
//!
//! ## 降级
//!
//! 未配置时停止清单同步与配置热更新，资产发现回退为网段扫描 + 终端上报；
//! **已有资产只标记 `stale`，绝不删除**（云侧抖动不能导致台账丢数据）。

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::sync::Arc;

pub(crate) use agf_core::adapter::Adapter;
pub(crate) use agf_core::adapter::AdapterConfig;
pub(crate) use agf_core::adapter::AdapterDescriptor;
pub(crate) use agf_core::adapter::AdapterHealth;
pub(crate) use agf_core::adapter::PullRequest;
pub(crate) use agf_core::adapter::PullResponse;
pub(crate) use agf_core::adapter::PushPayload;
pub(crate) use agf_core::adapter::SyncDirection;
pub(crate) use agf_core::adapter::SyncOutcome;

pub(crate) use agf_core::asset::Asset;

pub(crate) use agf_core::cloud::CloudResourceMapping;

pub(crate) use agf_core::enums::AliCloudService;
pub(crate) use agf_core::enums::AssetKind;
pub(crate) use agf_core::enums::DataClass;
pub(crate) use agf_core::enums::DiscoverySource;
pub(crate) use agf_core::enums::Protocol;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::NS_ASSET;
pub(crate) use agf_core::ids::TenantId;
pub(crate) use agf_core::ids::deterministic_id;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use async_trait::async_trait;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use crate::AdapterMode;

pub(crate) use crate::http::RpcClient;
pub(crate) use crate::http::json_array;
pub(crate) use crate::http::json_i64;
pub(crate) use crate::http::json_str;

pub(crate) use crate::mock;
pub(crate) use crate::mock::AdapterCore;
pub(crate) use crate::mock::null_transport;

#[cfg(test)]
pub(crate) use crate::http::RecordingTransport;

#[cfg(test)]
pub(crate) use crate::test_support::fixture_config;

#[cfg(test)]
pub(crate) use agf_core::enums::HealthState;

#[allow(unused_imports)]
pub use platform_default_configs::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// MSE API 版本。
pub const MSE_API_VERSION: &str = "2019-05-31";

/// MSE 集群。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MseCluster {
    /// 集群 id。
    pub cluster_id: String,
    /// 名称。
    pub name: String,
    /// 类型（`Nacos` / `Zookeeper` / `Eureka`）。
    pub cluster_type: String,
    /// 版本。
    pub version: String,
    /// 节点数。
    pub instance_count: u32,
    /// 所属 VPC。
    pub vpc_id: String,
    /// 状态。
    pub status: String,
}

/// Nacos 服务实例（资产发现的最小单位）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MseService {
    /// 命名空间。
    pub namespace: String,
    /// 分组。
    pub group_name: String,
    /// 服务名。
    pub service_name: String,
    /// 所属集群。
    pub cluster_id: String,
    /// 实例数。
    pub instance_count: u32,
    /// 健康实例数。
    pub healthy_count: u32,
    /// 服务 metadata（保真存储）。
    #[serde(default)]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

/// MSE 配置项。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MseConfig {
    /// `dataId`。
    pub data_id: String,
    /// 分组。
    pub group_name: String,
    /// 命名空间。
    pub namespace: String,
    /// 内容。
    pub content: String,
    /// 内容 md5。
    pub md5: String,
}

/// 云原生网关信息。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MseGateway {
    /// 网关 id。
    pub gateway_id: String,
    /// 名称。
    pub name: String,
    /// 版本。
    pub version: String,
    /// 承载流量类型（`management-plane` / `business`）。
    pub traffic_kind: String,
    /// 状态。
    pub status: String,
}

/// MSE 服务能力契约。
#[async_trait]
pub trait MseApi: Send + Sync {
    /// 列出集群。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn pull_clusters(&self) -> DomainResult<Vec<MseCluster>>;

    /// 列出 Nacos 服务（资产发现源）。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn pull_services(&self) -> DomainResult<Vec<MseService>>;

    /// 列出配置。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn pull_configs(&self) -> DomainResult<Vec<MseConfig>>;

    /// 下发配置（热更新）。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn push_config(&self, config: &MseConfig) -> DomainResult<String>;

    /// 云原生网关信息。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn pull_gateways(&self) -> DomainResult<Vec<MseGateway>>;
}

/// MSE 适配器。Mock 与真实实现是同一类型的两种模式。
pub struct MseAdapter {
    core: AdapterCore,
    instance_id: Option<String>,
    namespace: String,
    client: Option<Arc<RpcClient>>,
    transport: Arc<crate::http::RecordingTransport>,
    /// 最近一次同步时标记为 `stale` 的资源 id（供上层做台账对账）。
    stale_marks: std::sync::Mutex<Vec<String>>,
}

pub mod config_cas;
mod impl_mse_service;
mod live;
mod platform_default_configs;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_live;
