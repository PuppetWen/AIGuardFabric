//! APIG（AI 网关）适配器：网关/路由/插件盘点、策略下发、访问日志拉取（§5.2）。
//!
//! ## 与 `agf-aigw` 的分工
//!
//! `agf-aigw` 是**平台自己的**南北向 AI 网关；APIG 是**客户的**云上网关。
//! 插件适配与独立 Policy API 使用不同合同，不能把平台策略直接视为云策略。
//! `policy_driver` 限定为已有 ModelAPI 的全局请求/Token 分钟限额；其它策略需要各自的转换与验收。
//!
//! ## 降级
//!
//! 未配置时不下发任何策略（`agf-aigw` 继续用本地策略兜底并记告警），
//! 访问日志改用本地采集通道；已下发的策略在云侧继续生效，不会因为平台断连而失效。

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

pub(crate) use agf_core::enums::AliCloudService;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use async_trait::async_trait;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use crate::AdapterMode;

pub(crate) use crate::http::RpcClient;
pub(crate) use crate::http::json_array;
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
pub use parse_gateways::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// APIG API 版本。
pub const APIG_API_VERSION: &str = "2024-03-27";

/// 网关实例。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApigGateway {
    /// 网关 id。
    pub gateway_id: String,
    /// 名称。
    pub name: String,
    /// 规格。
    pub spec: String,
    /// 状态。
    pub status: String,
    /// 所属 VPC。
    pub vpc_id: String,
    /// 地域。
    pub region: String,
    /// 标签。
    #[serde(default)]
    pub tags: Vec<String>,
}

/// 路由。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApigRoute {
    /// 路由 id。
    pub route_id: String,
    /// 所属网关。
    pub gateway_id: String,
    /// 名称。
    pub name: String,
    /// 匹配路径。
    pub path: String,
    /// 上游（模型服务 / MCP 代理）。
    pub upstream: String,
    /// 挂载的插件名。
    #[serde(default)]
    pub plugins: Vec<String>,
}

/// 插件。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApigPlugin {
    /// 插件 id。
    pub plugin_id: String,
    /// 名称。
    pub name: String,
    /// 类型。
    pub plugin_type: String,
    /// 是否启用。
    pub enabled: bool,
    /// 配置。
    pub config: serde_json::Value,
}

/// 策略类型（对应 §5.2 的四类下发策略）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApigPolicyKind {
    /// 限流。
    RateLimit,
    /// Token 配额。
    TokenQuota,
    /// 内容安全。
    ContentSafety,
    /// 模型路由。
    ModelRouting,
}

/// 待下发的 APIG 策略（平台策略 → 云网关策略的**唯一翻译点**）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApigPolicy {
    /// 策略名（幂等键）。
    pub name: String,
    /// 类型。
    pub kind: ApigPolicyKind,
    /// 作用的路由 id 列表（空 = 全部路由）。
    #[serde(default)]
    pub route_ids: Vec<String>,
    /// 是否启用（`false` 表示下发"关闭"态插件）。
    pub enabled: bool,
    /// 配置体。
    pub config: serde_json::Value,
}

/// APIG 服务能力契约。
#[async_trait]
pub trait ApigApi: Send + Sync {
    /// 列出网关。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn pull_gateways(&self) -> DomainResult<Vec<ApigGateway>>;

    /// 列出路由（可按网关过滤）。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn pull_routes(&self, gateway_id: Option<&str>) -> DomainResult<Vec<ApigRoute>>;

    /// 列出插件。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn pull_plugins(&self) -> DomainResult<Vec<ApigPlugin>>;

    /// 下发策略，返回云端插件 id。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn push_policy(&self, gateway_id: &str, policy: &ApigPolicy) -> DomainResult<String>;

    /// 拉取访问日志（交由 `agf-ingest` 做提示词攻击/外传检测）。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn pull_access_logs(&self, req: &PullRequest) -> DomainResult<Vec<serde_json::Value>>;
}

/// APIG 适配器。Mock 与真实实现是同一类型的两种模式。
pub struct ApigAdapter {
    core: AdapterCore,
    client: Option<Arc<RpcClient>>,
    transport: Arc<crate::http::RecordingTransport>,
}

pub mod config_driver;
mod impl_apig_policy_kind;
mod live;
mod parse_gateways;
pub mod policy_driver;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_live;
