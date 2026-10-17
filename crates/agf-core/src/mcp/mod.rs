//! MCP（Model Context Protocol）资产模型（§4.1）。
//!
//! 覆盖 MCP Server / Client、能力声明（tools/resources/prompts）、
//! 握手探测结果、工具级风险画像与运行时调用记录。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ids::{Id, TenantId};

use crate::time::Timestamp;

#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// MCP 传输方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum McpTransport {
    /// 标准输入输出（本地子进程）。
    Stdio,
    /// HTTP + SSE（旧版远程传输）。
    Sse,
    /// Streamable HTTP（新版远程传输）。
    Http,
    /// WebSocket（部分实现扩展）。
    WebSocket,
}

/// MCP Server 资产。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServer {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 资产 id。
    pub asset_id: Id,
    /// 服务器名（客户端配置中的 key）。
    pub name: String,
    /// 传输方式。
    pub transport: McpTransport,
    /// stdio 命令。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// stdio 参数。
    #[serde(default)]
    pub args: Vec<String>,
    /// 远程 URL。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// 协议版本（MCP `initialize` 返回）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    /// 服务端实现信息（name/version）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_info: Option<McpServerInfo>,
    /// 能力声明。
    #[serde(default)]
    pub capabilities: McpCapabilities,
    /// 发现的工具清单。
    #[serde(default)]
    pub tools: Vec<McpTool>,
    /// 发现的资源清单。
    #[serde(default)]
    pub resources: Vec<McpResource>,
    /// 发现的提示词模板。
    #[serde(default)]
    pub prompts: Vec<McpPrompt>,
    /// 环境变量键名（值不入库）。
    #[serde(default)]
    pub env_keys: Vec<String>,
    /// 是否存在明文凭据。
    pub has_plaintext_secret: bool,
    /// 是否强制认证（远程 MCP）。
    pub requires_auth: bool,
    /// 归属人/部门。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// 归属部门。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    /// 是否已在平台登记（未登记 = 影子 MCP）。
    pub registered: bool,
    /// 最后握手时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_handshake_at: Option<Timestamp>,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 更新时间。
    pub updated_at: Timestamp,
}

/// MCP 服务端实现信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerInfo {
    /// 实现名。
    pub name: String,
    /// 实现版本。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// 标题（可读名）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

/// MCP 能力声明。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct McpCapabilities {
    /// tools 能力。
    pub tools: bool,
    /// resources 能力。
    pub resources: bool,
    /// prompts 能力。
    pub prompts: bool,
    /// logging 能力。
    pub logging: bool,
    /// sampling（服务端反向请求模型）能力——**高风险**：可能绕过网关直接调用模型。
    pub sampling: bool,
    /// roots（文件系统边界声明）。
    pub roots: bool,
    /// completions。
    pub completions: bool,
    /// 原始能力 JSON（保真）。
    #[serde(default)]
    pub raw: BTreeMap<String, serde_json::Value>,
}

/// MCP 工具描述。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    /// 工具名。
    pub name: String,
    /// 描述。
    #[serde(default)]
    pub description: String,
    /// 输入 schema（JSON Schema）。
    #[serde(default)]
    pub input_schema: serde_json::Value,
    /// 能力画像（平台推断）。
    #[serde(default)]
    pub traits: ToolTraits,
    /// 参数中出现的敏感字段名（如 `token`、`path`）。
    #[serde(default)]
    pub sensitive_params: Vec<String>,
}

/// 工具能力画像（由名称/描述/schema 推断，供策略引擎与红队选型）。
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct ToolTraits {
    /// 可执行 shell 命令。
    pub shell_exec: bool,
    /// 可读文件。
    pub filesystem_read: bool,
    /// 可写文件。
    pub filesystem_write: bool,
    /// 可发起网络请求（SSRF 风险）。
    pub network_egress: bool,
    /// 可接收网络请求（监听/暴露）。
    pub network_ingress: bool,
    /// 可访问数据库。
    pub database: bool,
    /// 可读取凭据/密钥。
    pub credential_access: bool,
    /// 可发送消息/邮件（社工与外传通道）。
    pub messaging: bool,
    /// 可修改云资源。
    pub cloud_mutation: bool,
}

/// MCP 资源描述。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResource {
    /// 资源 URI。
    pub uri: String,
    /// 名称。
    #[serde(default)]
    pub name: String,
    /// MIME 类型。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// 是否可能包含敏感数据（依据 URI 模式推断）。
    pub sensitive: bool,
}

/// MCP 提示词模板描述。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPrompt {
    /// 模板名。
    pub name: String,
    /// 描述。
    #[serde(default)]
    pub description: String,
    /// 参数名列表。
    #[serde(default)]
    pub arguments: Vec<String>,
    /// 是否包含可被注入的占位符（间接注入面）。
    pub injectable: bool,
}

/// MCP 握手探测结果（`agf-scan` 主动探测产出；Mock 模式下由 fixtures 提供）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpHandshake {
    /// 目标（URL 或 `stdio:command`）。
    pub target: String,
    /// 是否成功。
    pub success: bool,
    /// 协议版本。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    /// 服务端信息。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_info: Option<McpServerInfo>,
    /// 能力。
    #[serde(default)]
    pub capabilities: McpCapabilities,
    /// 工具数量。
    pub tool_count: usize,
    /// 耗时（毫秒）。
    pub latency_ms: u64,
    /// 失败原因。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// 探测时间。
    pub probed_at: Timestamp,
}

/// MCP 调用记录（运行时审计，来自 MCP 代理）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpInvocation {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 会话 id。
    pub session_id: String,
    /// Agent 资产 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<Id>,
    /// MCP Server 资产 id。
    pub mcp_server_id: Id,
    /// 工具名。
    pub tool_name: String,
    /// 参数（已按策略脱敏）。
    pub arguments: serde_json::Value,
    /// 结果摘要（截断）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_excerpt: Option<String>,
    /// 策略动作。
    pub action: crate::enums::PolicyAction,
    /// 命中的策略 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<Id>,
    /// 是否被拦截。
    pub blocked: bool,
    /// 耗时（毫秒）。
    pub latency_ms: u64,
    /// 发生时间。
    pub at: Timestamp,
}

mod impl_mcp_transport;
#[cfg(test)]
mod tests;
