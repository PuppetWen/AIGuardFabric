//! 上报载荷：资产快照 / 心跳 / 增量变更（diff）三种信封。
//!
//! ## 与平台侧的关系
//!
//! 快照中的 `report` 字段就是 `agf_core::agent::AgentReport`——即
//! `agf-ingest` 的 `decode_agent_report` 与 `agf-asset` 的
//! `DiscoveryBatch::from_agent_report` 直接消费的类型，因此**终端不需要任何服务端 SDK**
//! 就能与既有上报链路对齐；其余终端特有事实（模型端点、Skill、进程、监听端口）放在
//! [`CollectionExtras`]，服务端可忽略未知字段（serde 默认行为）。
//!
//! ## 降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 首次上报（无上一次快照） | [`compute_diff`] 把当前全部资产视为 `added`，不报错 |
//! | 当前快照为空 | diff 的 `removed` 列出上次全部资产（服务端据此标记 `stale`，**不删除**） |
//! | 变更条数超上限 | `truncated = true` 且只保留前 `MAX_DIFF_ITEMS` 条，提示上层改发全量快照 |
//! | 载荷序列化失败 | 返回 `DomainError::Parse`（不静默丢弃） |

pub(crate) use std::collections::BTreeMap;
pub(crate) use std::collections::BTreeSet;

pub(crate) use agf_core::agent::AgentFlavor;
pub(crate) use agf_core::agent::AgentReport;
pub(crate) use agf_core::agent::DetectedAgent;
pub(crate) use agf_core::agent::DetectedCredential;
pub(crate) use agf_core::agent::DetectedMcp;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use sha2::Digest;
pub(crate) use sha2::Sha256;

pub(crate) use crate::identity::AgentIdentity;

#[allow(unused_imports)]
pub use impl_payload_kind::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 上报信封协议名（服务端据此分派与做版本兼容）。
pub const SCHEMA: &str = "agf.agent.v1";

/// 增量变更单次上报的最大条目数（超过则 `truncated`）。
pub const MAX_DIFF_ITEMS: usize = 500;

/// 载荷种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PayloadKind {
    /// 资产快照（全量）。
    Snapshot,
    /// 心跳。
    Heartbeat,
    /// 增量变更。
    Diff,
    /// 注册。
    Register,
}

/// 采集器上行的统一信封。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope<T> {
    /// 协议名与版本。
    pub schema: String,
    /// 载荷种类。
    pub kind: PayloadKind,
    /// 采集器 id。
    pub agent_id: String,
    /// 租户。
    pub tenant_id: TenantId,
    /// 采集器版本。
    pub agent_version: String,
    /// 主机名。
    pub hostname: String,
    /// 发送时间。
    pub sent_at: Timestamp,
    /// 幂等键（服务端据此去重）。
    pub idempotency_key: String,
    /// 载荷。
    pub payload: T,
}

/// 资产快照载荷。
///
/// 不派生 `PartialEq`：内含的 `agf_core::agent::AgentReport` 未派生（core 契约如此），
/// 序列化往返测试逐字段断言即可。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotPayload {
    /// 与平台既有链路对齐的采集报告（`agf-ingest` / `agf-asset` 直接消费）。
    pub report: AgentReport,
    /// 终端特有事实（模型端点 / Skill / 进程 / 监听端口）。
    #[serde(default)]
    pub extras: CollectionExtras,
}

/// 心跳载荷。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HeartbeatPayload {
    /// 运行时长（秒）。
    pub uptime_secs: u64,
    /// 本地队列深度。
    pub queue_depth: usize,
    /// 上次快照时间。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_snapshot_at: Option<Timestamp>,
    /// 各采集器状态。
    #[serde(default)]
    pub collectors: Vec<CollectorStatus>,
}

/// 单采集器执行状态（如实登记支持级别与失败原因）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectorStatus {
    /// 采集器名。
    pub name: String,
    /// 支持级别（`implemented` / `interface-only` / `unsupported`）。
    pub level: String,
    /// 采集到的条目数。
    pub items: usize,
    /// 耗时（毫秒）。
    pub elapsed_ms: u64,
    /// 失败原因（成功为 `None`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// 增量变更载荷。
///
/// 不派生 `PartialEq`：内含的 core 检测类型未派生，测试按条数与字段断言。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffPayload {
    /// 变更基线（Agent 侧的资产键集合指纹）。
    pub base_fingerprint: String,
    /// 新增 Agent。
    #[serde(default)]
    pub added_agents: Vec<DetectedAgent>,
    /// 移除的 Agent 资产键（服务端标记 `stale`，**绝不删除**）。
    #[serde(default)]
    pub removed_agent_keys: Vec<String>,
    /// 变化的 Agent（配置/版本变化）。
    #[serde(default)]
    pub changed_agents: Vec<DetectedAgent>,
    /// 新增 MCP 配置。
    #[serde(default)]
    pub added_mcp: Vec<DetectedMcp>,
    /// 移除的 MCP 资产键。
    #[serde(default)]
    pub removed_mcp_keys: Vec<String>,
    /// 本次新发现的凭据命中（掩码形态，不含明文）。
    #[serde(default)]
    pub credential_hits: Vec<DetectedCredential>,
    /// 是否因超过 [`MAX_DIFF_ITEMS`] 被截断（截断时应改发全量快照）。
    #[serde(default)]
    pub truncated: bool,
}

/// 终端特有采集结果。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CollectionExtras {
    /// 模型端点。
    #[serde(default)]
    pub model_endpoints: Vec<DetectedModelEndpoint>,
    /// 工具与 Skill。
    #[serde(default)]
    pub skills: Vec<DetectedSkill>,
    /// 进程。
    #[serde(default)]
    pub processes: Vec<DetectedProcess>,
    /// 监听端口。
    #[serde(default)]
    pub listening_ports: Vec<ListeningPort>,
}

/// 模型端点检测项。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedModelEndpoint {
    /// 来源文件。
    pub source_file: String,
    /// 配置键名。
    pub key: String,
    /// 端点 URL。
    pub url: String,
    /// 厂商标识推断（`openai` / `dashscope` / `local` …）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_hint: Option<String>,
    /// 是否同处发现明文密钥。
    #[serde(default)]
    pub has_plaintext_key: bool,
}

/// Skill / 工具检测项。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedSkill {
    /// Whole Skill directory observation, separate from the legacy manifest digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<agf_core::skill_package::PackageObservation>,
    /// Digest of the observed file; source content is never uploaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_sha256: Option<String>,
    /// verified, unreadable, too-large, not-regular-file or changed-during-read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash_status: Option<String>,
    /// 来源路径。
    pub source_path: String,
    /// 名称。
    pub name: String,
    /// 形态（`skill` / `command` / `rule`）。
    pub kind: String,
}

/// 进程检测项。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedProcess {
    /// 进程 id。
    pub pid: u32,
    /// 进程名。
    pub name: String,
    /// 命中的 Agent 类型（未命中为 `None`，仅登记疑似 AI 进程）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flavor: Option<String>,
}

/// 监听端口检测项。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListeningPort {
    /// 协议（`tcp` / `tcp6` / `udp`）。
    pub protocol: String,
    /// 本地地址。
    pub local_addr: String,
    /// 端口。
    pub port: u16,
    /// 持有进程 id（可得时）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// 持有进程名（可得时）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
}

mod impl_payload_kind;
#[cfg(test)]
mod tests;
