//! PrivateLink（私网链接）适配器：终端节点盘点、私网连通性探测、安全组白名单最小化检查（§5.2）。
//!
//! ## 安全要点
//!
//! §5.2 要求"采集器 / 告警设备 / 数据库全走私网、公网入口最小化"。本适配器把这条要求
//! 落成两个可判定的检查：
//!
//! 1. **连通性**：[`PrivatelinkApi::probe`] 走终端节点做真实探测（`ProbePrivateLink` 能力）；
//! 2. **最小化**：[`PrivatelinkApi::check_security_groups`] 找出 `0.0.0.0/0`、超大网段、
//!    以及未绑定安全组的终端节点。
//!
//! ## 降级
//!
//! 未配置时探测不可用，连通性判定降级为"**未知**"而不是"不通"——
//! 把探测失败误判为不通会导致运维误删可用链路。采集器继续本地缓存，恢复后补传。

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
pub(crate) use crate::http::json_i64;
pub(crate) use crate::http::json_str;

pub(crate) use crate::mock;
pub(crate) use crate::mock::AdapterCore;
pub(crate) use crate::mock::null_transport;

#[cfg(test)]
pub(crate) use crate::test_support::fixture_config;

#[cfg(test)]
pub(crate) use agf_core::enums::HealthState;

#[allow(unused_imports)]
pub use evaluate_security_groups::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// PrivateLink API 版本。
pub const PRIVATELINK_API_VERSION: &str = "2020-04-15";

/// 终端节点。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivatelinkEndpoint {
    /// 终端节点 id。
    pub endpoint_id: String,
    /// 名称。
    pub name: String,
    /// 关联的终端节点服务名。
    pub service_name: String,
    /// 所属 VPC。
    pub vpc_id: String,
    /// 可用区。
    pub zone_ids: Vec<String>,
    /// 状态。
    pub status: String,
    /// 带宽（Mbps）。
    pub bandwidth_mbps: u32,
    /// 绑定的安全组。
    #[serde(default)]
    pub security_groups: Vec<String>,
    /// 连接状态。
    pub connection_status: String,
}

/// 私网连通性探测结果。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivatelinkProbe {
    /// 探测目标。
    pub target: String,
    /// 是否可达。
    pub reachable: bool,
    /// 延迟（毫秒）。
    pub latency_ms: u64,
    /// 使用的终端节点。
    pub endpoint_id: String,
    /// 解析到的私网 IP。
    pub resolved_ip: String,
    /// 说明。
    pub detail: String,
    /// 探测时间。
    pub at: Timestamp,
}

/// 白名单检查结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WhitelistVerdict {
    /// 未取得完整或有效规则，不能推断放行范围。
    Unknown,
    /// 已读取规则，未发现允许入站的 CIDR。
    NoIngress,
    /// 已最小化（仅私网小网段）。
    Minimal,
    /// 过宽（含超大网段）。
    TooBroad,
    /// 对公网开放（`0.0.0.0/0`）。
    PubliclyOpen,
    /// 未绑定安全组（需核对实际默认网络行为）。
    Unbound,
}

/// 单个安全组的白名单检查结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityGroupCheck {
    /// 终端节点 id。
    pub endpoint_id: String,
    /// 安全组 id。
    pub security_group: String,
    /// 允许的来源。
    pub allowed_cidrs: Vec<String>,
    /// 结论。
    pub verdict: WhitelistVerdict,
    /// 说明。
    pub note: String,
}

/// PrivateLink 服务能力契约。
#[async_trait]
pub trait PrivatelinkApi: Send + Sync {
    /// 列出终端节点。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn pull_endpoints(&self) -> DomainResult<Vec<PrivatelinkEndpoint>>;

    /// 探测私网连通性（`ProbePrivateLink` 能力）。
    ///
    /// # Errors
    /// 网络失败（Mock 模式恒为确定性结果，不触网）。
    async fn probe(&self, target: &str) -> DomainResult<PrivatelinkProbe>;

    /// 安全组白名单最小化检查。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn check_security_groups(&self) -> DomainResult<Vec<SecurityGroupCheck>>;
}

/// PrivateLink 适配器。Mock 与真实实现是同一类型的两种模式。
pub struct PrivatelinkAdapter {
    core: AdapterCore,
    probe_port: Option<u16>,
    ecs_endpoint: Option<String>,
    client: Option<Arc<RpcClient>>,
    transport: Arc<crate::http::RecordingTransport>,
}

mod evaluate_security_groups;
mod impl_privatelink_endpoint;
mod live;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_live;

/// Explicit creation and separate provider acceptance.
pub mod provisioning;
