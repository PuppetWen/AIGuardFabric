//! CMS（云监控）适配器：自定义事件 / 指标上报、报警历史拉取、报警回调订阅（§5.2）。
//!
//! | 阿里云 API | 用途 |
//! |---|---|
//! | `PutCustomEvent` | 把平台检出的事件（提示词攻击 / 凭证泄露 …）推进云监控，复用客户既有告警与订阅 |
//! | `PutCustomMetric` | 上报 AgentTeams 运行指标（调用量、Token 用量、被拦截比） |
//! | `DescribeAlertHistoryList` | 拉取云上报警历史进 ingest 做联合分析 |
//! | 报警回调 | 回调 URL 由平台签发，云监控报警回调进入 ingest 的 webhook 通道 |
//!
//! ## 降级
//!
//! 未配置时**不上报**任何数据（本地事件照常落库），报警订阅回退为 ingest 侧本地轮询；
//! 通用适配器及 Scheduler 的直接调用不进入持久补传队列。平台 CMS 队列由显式用户意图驱动；
//! [`crate::deadletter::OfflineQueue`] 仅为进程内库，不能证明重启后补传。

pub mod queue_delivery;

pub(crate) use std::sync::Arc;

pub(crate) use agf_core::adapter::Adapter;
pub(crate) use agf_core::adapter::AdapterCapability;
pub(crate) use agf_core::adapter::AdapterConfig;
pub(crate) use agf_core::adapter::AdapterDescriptor;
pub(crate) use agf_core::adapter::AdapterHealth;
pub(crate) use agf_core::adapter::PullRequest;
pub(crate) use agf_core::adapter::PullResponse;
pub(crate) use agf_core::adapter::PushPayload;
pub(crate) use agf_core::adapter::SyncDirection;
pub(crate) use agf_core::adapter::SyncOutcome;

pub(crate) use agf_core::enums::AliCloudService;
pub(crate) use agf_core::enums::Severity;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use async_trait::async_trait;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use crate::AdapterMode;

pub(crate) use crate::http::RpcClient;
pub(crate) use crate::http::RpcResponse;
pub(crate) use crate::http::json_array;
pub(crate) use crate::http::json_i64;
pub(crate) use crate::http::json_str;

pub(crate) use crate::mock;
pub(crate) use crate::mock::AdapterCore;
pub(crate) use crate::mock::null_transport;

pub(crate) use crate::signer::percent_encode;

#[cfg(test)]
pub(crate) use crate::http::RecordingTransport;

#[cfg(test)]
pub(crate) use crate::test_support::fixture_config;
#[cfg(test)]
pub(crate) use crate::test_support::fixture_integration;

#[cfg(test)]
pub(crate) use agf_core::cloud::CloudCredentialKind;

#[cfg(test)]
pub(crate) use agf_core::enums::HealthState;

#[allow(unused_imports)]
pub(crate) use default_severity::*;
#[allow(unused_imports)]
pub use parse_alarm_histories::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// CMS API 版本（自定义事件/指标）。
pub const CMS_API_VERSION: &str = "2019-01-01";

/// 云监控自定义事件。
///
/// `severity` 与 `group_id` 带 `serde(default)`：云端/上游载荷可能省略它们，
/// 缺省不应导致整条事件被丢弃。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmsEvent {
    /// 事件名（云监控 `EventName`）。
    pub event_name: String,
    /// 事件内容（JSON 字符串，云监控限制 4 KB）。
    pub content: String,
    /// 分组维度（如 `agent_id`）。
    #[serde(default)]
    pub group_id: String,
    /// 时间。
    #[serde(default = "Timestamp::now")]
    pub at: Timestamp,
    /// 平台侧等级（映射为云监控 Level）。
    #[serde(default = "default_severity")]
    pub severity: Severity,
}

/// 云监控自定义指标数据点。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmsMetric {
    /// 云监控应用分组 ID；真实上报必须填写。
    #[serde(default)]
    pub group_id: String,
    /// 指标名。
    pub metric_name: String,
    /// 平台逻辑命名空间；云上自定义指标归属由 group_id 决定。
    #[serde(default = "default_namespace")]
    pub namespace: String,
    /// 维度。
    #[serde(default)]
    pub dimensions: std::collections::BTreeMap<String, String>,
    /// 时间。
    #[serde(default = "Timestamp::now")]
    pub at: Timestamp,
    /// 数值。
    pub value: f64,
    /// 单位。
    #[serde(default = "default_unit")]
    pub unit: String,
}

/// 云监控报警历史条目。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmsAlarmHistory {
    /// 报警 id。
    pub alarm_id: String,
    /// 报警规则名。
    pub rule_name: String,
    /// 云资源 id。
    pub resource_id: String,
    /// 等级（`CRITICAL` / `WARN` / `INFO`）。
    pub level: String,
    /// 报警状态（`ALARM` / `OK` / `INSUFFICIENT_DATA`）。
    pub state: String,
    /// 报警内容。
    pub content: String,
    /// 发生时间。
    pub at: Timestamp,
}

/// 报警回调订阅信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmsAlarmSubscription {
    /// 回调 URL。
    pub callback_url: String,
    /// 校验 token（**仅掩码返回**）。
    pub verify_token_masked: String,
    /// 订阅时间。
    pub subscribed_at: Timestamp,
}

/// CMS 服务能力契约（Mock 与真实实现同一套签名）。
#[async_trait]
pub trait CmsApi: Send + Sync {
    /// 上报自定义事件，返回事件名。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn put_event(&self, event: &CmsEvent) -> DomainResult<String>;

    /// 上报自定义指标，返回指标名。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn put_metric(&self, metric: &CmsMetric) -> DomainResult<String>;

    /// 拉取报警历史。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn pull_alarm_histories(&self, req: &PullRequest) -> DomainResult<Vec<CmsAlarmHistory>>;

    /// 订阅报警回调。
    ///
    /// # Errors
    /// 配置缺失（目前不会失败）。
    fn subscribe_alarm_callback(&self, callback_base: &str) -> DomainResult<CmsAlarmSubscription>;
}

/// CMS 适配器。
///
/// Mock 与真实实现是**同一类型的两种模式**：`mocked()` 构造的实例走
/// [`crate::mock::cms_alarm_histories`] 等确定性 fixtures，且
/// [`crate::http::RpcClient::live`] 会拒绝为其构造客户端，因此不可能触网。
pub struct CmsAdapter {
    core: AdapterCore,
    client: Option<Arc<RpcClient>>,
    transport: Arc<crate::http::RecordingTransport>,
}

/// 能力常量（供文档与测试引用）。
pub const CAPABILITIES: &[AdapterCapability] = &[
    AdapterCapability::PushEvents,
    AdapterCapability::PushMetrics,
    AdapterCapability::PullInventory,
    AdapterCapability::SubscribeEvents,
    AdapterCapability::SelfCheck,
];

mod default_severity;
mod parse_alarm_histories;
#[cfg(test)]
mod tests;
