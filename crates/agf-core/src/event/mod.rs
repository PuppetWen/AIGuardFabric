//! 统一事件模型 AGF-ECS（§4.5 归一化，兼容 ECS/OCSF 语义）。
//!
//! 设计原则：
//! - **原始载荷保真存储**（`raw`），归一化字段只是索引视图，可随时重放重建；
//! - 字段命名对齐 Elastic Common Schema，便于与客户既有 SIEM 对接；
//! - `tenant_id` 强制存在，事件表按 `(tenant_id, time)` 分区。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::enums::{IngestProtocol, Severity};

use crate::ids::{Id, TenantId};

use crate::time::Timestamp;

#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 事件类别（对齐 ECS `event.category`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EventCategory {
    /// 认证与授权。
    Authentication,
    /// 网络活动。
    Network,
    /// 进程与命令执行。
    Process,
    /// 文件操作。
    File,
    /// 数据库操作。
    Database,
    /// Web 请求/响应。
    Web,
    /// AI 会话（提示词/补全）。
    AiSession,
    /// AI 工具调用。
    AiToolCall,
    /// AI 模型事件（路由/降级/异常）。
    AiModel,
    /// 配置变更。
    Configuration,
    /// 云平台控制面。
    CloudControl,
    /// 恶意行为（已判定）。
    Malware,
    /// 漏洞利用。
    Intrusion,
    /// 策略命中。
    Policy,
    /// 其他。
    Other,
}

/// 事件动作（对齐 ECS `event.action`，用字符串承载厂商原始动作 + 归一动作）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EventAction {
    /// 允许。
    Allowed,
    /// 拒绝/阻断。
    Denied,
    /// 创建。
    Created,
    /// 更新。
    Updated,
    /// 删除。
    Deleted,
    /// 登录。
    Login,
    /// 登出。
    Logout,
    /// 读取。
    Read,
    /// 写入。
    Write,
    /// 执行。
    Execute,
    /// 连接。
    Connect,
    /// 断开。
    Disconnect,
    /// 告警。
    Alert,
    /// 检测。
    Detect,
    /// 外传。
    Exfiltrate,
    /// 提权。
    Elevate,
    /// 未知。
    Unknown,
}

/// 网络方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkDirection {
    /// 入站。
    Inbound,
    /// 出站。
    Outbound,
    /// 内部东西向。
    Internal,
    /// 未知。
    Unknown,
}

/// 主机信息（ECS `host.*`）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostInfo {
    /// 主机名。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// 主机 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// IP 列表。
    #[serde(default)]
    pub ips: Vec<String>,
    /// 操作系统。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// 架构。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// 云实例 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_instance_id: Option<String>,
    /// 云账号。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_account: Option<String>,
    /// K8s 命名空间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k8s_namespace: Option<String>,
    /// K8s Pod。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k8s_pod: Option<String>,
}

/// 用户信息（ECS `user.*`）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserInfo {
    /// 用户名。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// 用户 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// 域。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// 邮箱。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// 部门（用于 ABAC 与告警路由）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
}

/// 网络信息（ECS `source.*` / `destination.*`）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// 源 IP。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    /// 源端口。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_port: Option<u16>,
    /// 目的 IP。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_ip: Option<String>,
    /// 目的端口。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    /// 协议（tcp/udp/http/grpc）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// 域名。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// 方向。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<NetworkDirection>,
    /// 字节数（上传）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<u64>,
    /// 字节数（下载）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_in: Option<u64>,
}

/// AI 事件扩展（AGF 自有扩展字段，ECS 未覆盖部分）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiContext {
    /// Agent 资产 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<Id>,
    /// Agent 类型。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_flavor: Option<String>,
    /// 会话 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// MCP Server 资产 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_server_id: Option<Id>,
    /// 工具名。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    /// 模型端点 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_endpoint_id: Option<Id>,
    /// 厂商。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// 模型名。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// 输入 token。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_tokens: Option<u64>,
    /// 输出 token。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_tokens: Option<u64>,
    /// 费用（微元）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_micro: Option<u64>,
    /// 提示词哈希（不存原文，原文在 raw 中保真）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_hash: Option<String>,
    /// 命中的规则键。
    #[serde(default)]
    pub rule_keys: Vec<String>,
    /// 命中的策略 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<Id>,
    /// 处置动作。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// 是否被 Mock 数据替代。
    #[serde(default)]
    pub mocked: bool,
}

/// 归一化事件主体（AGF-ECS）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 事件时间（厂商时间优先，缺失用接入时间）。
    pub time: Timestamp,
    /// 接入时间。
    pub ingested_at: Timestamp,
    /// 事件类别。
    pub category: EventCategory,
    /// 事件动作。
    pub action: EventAction,
    /// 厂商原始动作字符串（保真）。
    #[serde(default)]
    pub action_raw: String,
    /// 严重等级。
    pub severity: Severity,
    /// 日志源 id。
    pub source_id: Id,
    /// 日志源名称。
    #[serde(default)]
    pub source_name: String,
    /// 接入协议。
    pub protocol: IngestProtocol,
    /// 解析器 id（无模板走 AI 推断时为 `None`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parser_id: Option<Id>,
    /// 解析器名称。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parser_name: Option<String>,
    /// 厂商名。
    #[serde(default)]
    pub vendor: String,
    /// 产品名。
    #[serde(default)]
    pub product: String,
    /// 主机信息。
    #[serde(default)]
    pub host: HostInfo,
    /// 用户信息。
    #[serde(default)]
    pub user: UserInfo,
    /// 网络信息。
    #[serde(default)]
    pub network: NetworkInfo,
    /// AI 扩展。
    #[serde(default)]
    pub ai: AiContext,
    /// 原始消息（保真；已按策略脱敏的副本另存 `raw_redacted`）。
    #[serde(default)]
    pub message: String,
    /// 结构化原始载荷（保真，可回放）。
    #[serde(default)]
    pub raw: serde_json::Value,
    /// 原始载荷引用（对象存储 key，大报文走这里）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_ref: Option<String>,
    /// 原始载荷哈希（去重 + 防篡改）。
    #[serde(default)]
    pub raw_hash: String,
    /// 是否已脱敏。
    #[serde(default)]
    pub redacted: bool,
    /// 标签。
    #[serde(default)]
    pub tags: Vec<String>,
    /// 自定义字段（未映射到标准字段的解析结果）。
    #[serde(default)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// 原始日志（保真层，与 `events` 分离存储，便于回放）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawLog {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 日志源 id。
    pub source_id: Id,
    /// 接收时间。
    pub received_at: Timestamp,
    /// 接入协议。
    pub protocol: IngestProtocol,
    /// 原始字节（base64；二进制安全）。
    pub payload_b64: String,
    /// 载荷哈希。
    pub payload_hash: String,
    /// 载荷字节数。
    pub bytes: usize,
    /// 来源（对端地址/文件路径/Kafka topic）。
    #[serde(default)]
    pub origin: String,
    /// 是否已成功解析。
    pub parsed: bool,
    /// 解析失败原因。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_error: Option<String>,
    /// 关联事件 id（解析成功后回填）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<Id>,
}

mod impl_event_category;
#[cfg(test)]
mod tests;
