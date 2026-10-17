//! 四组资源的对外视图类型（字段名对齐前端 `apps/web/src/types/domain.ts`）。

use super::*;
/// 前端 `ToolCapability` 允许的取值（Skill 能力标签白名单）。
pub(super) const TOOL_CAPABILITIES: [&str; 7] =
    ["read", "write", "execute", "network", "filesystem", "credential", "payment"];

/// 前端 `ModelVendor` 允许的取值。
pub(super) const MODEL_VENDORS: [&str; 11] = [
    "openai",
    "anthropic",
    "azure-openai",
    "qwen",
    "deepseek",
    "zhipu",
    "moonshot",
    "baichuan",
    "ollama",
    "vllm",
    "custom",
];

/// 前端 `AdapterHealth` 允许的取值（`unknown` 之外的取值必须来自台账属性）。
pub(super) const MODEL_HEALTHS: [&str; 3] = ["healthy", "degraded", "unhealthy"];

// ===========================================================================
// 视图（字段名对齐前端类型定义）
// ===========================================================================

/// Agent 视图（前端 `Agent`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AgentView {
    /// 资产 id。
    pub id: String,
    /// 名称。
    pub name: String,
    /// Agent 类型（前端枚举；无法判定时为 `custom`）。
    pub flavor: String,
    /// 版本。
    pub version: String,
    /// 宿主（台账 `endpoint`，无则退化为名称）。
    pub host: String,
    /// 宿主 IP（仅当 `endpoint` 是 IP 字面量时有值）。
    pub ip: String,
    /// 纳管模式（台账无此字段，缺省 `unmanaged`）。
    pub management: String,
    /// 是否近期观察到（不能证明服务在线）（见模块文档的判定规则）。
    pub online: Option<bool>,
    /// 最近发现观察（兼容字段名；不代表运行时心跳，缺少时为 null）。
    #[schema(value_type = Option<String>)]
    pub last_heartbeat_at: Option<Timestamp>,
    /// 上报的心跳间隔（秒；未配置或无效时为 null）。
    pub heartbeat_interval_sec: Option<i64>,
    /// 归属部门。
    pub department: String,
    /// 归属人。
    pub owner: String,
    /// 活跃会话数（未采集为 null，实际 0 保留）。
    pub active_sessions: Option<u64>,
    /// 可用工具数（未采集为 null，实际 0 保留）。
    pub tool_count: Option<u64>,
    /// 风险分（`risk_score` 缺省为 null（未知））。
    pub risk_score: Option<u8>,
}

/// MCP Server 视图（前端 `McpServer`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct McpServerView {
    /// 资产 id。
    pub id: String,
    /// 名称。
    pub name: String,
    /// 传输方式（前端枚举）。
    pub transport: String,
    /// 端点（stdio 命令或 HTTP URL）。
    pub endpoint: String,
    /// 暴露的工具数（未采集为 null，实际 0 保留）。
    pub tool_count: Option<u64>,
    /// 是否影子 MCP（试用且非手工登记，与 `InventoryStats.shadow` 同口径）。
    pub shadow: bool,
    /// 是否含明文凭据。
    pub plaintext_credential: bool,
    /// 归属人。
    pub owner: String,
    /// 归属部门。
    pub department: String,
    /// 是否近期观察到（不能证明服务在线）。
    pub online: Option<bool>,
    /// 登记时间。
    #[schema(value_type = String)]
    pub registered_at: Timestamp,
    /// 最近发现观察；未观察为 null。
    #[schema(value_type = Option<String>)]
    pub last_seen_at: Option<Timestamp>,
    /// 风险分。
    pub risk_score: Option<u8>,
}

/// Skill 视图（前端 `Skill`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SkillView {
    /// 资产 id。
    pub id: String,
    /// 名称。
    pub name: String,
    /// 版本。
    pub version: String,
    /// 发布方（台账 `vendor`）。
    pub publisher: String,
    /// 审批状态（由生命周期映射，见 [`skill_status`]）。
    pub status: String,
    /// 申请人（台账 `owner`）。
    pub requested_by: String,
    /// 申请时间。
    #[schema(value_type = String)]
    pub requested_at: Timestamp,
    /// 当前生命周期实际保存的审批/拒绝/归档时间；旧数据未知。
    #[schema(value_type = Option<String>)]
    pub decided_at: Option<Timestamp>,
    /// 实际认证操作人；旧数据未知。
    pub decided_by: Option<String>,
    /// 风险分。
    pub risk_score: Option<u8>,
    /// 能力标签（前端枚举内的子集）。
    pub capabilities: Vec<String>,
    /// 白名单（`attributes.whitelist`，缺省为空）。
    pub whitelist: SkillWhitelistView,
    /// 挂载的 Agent 数（未采集为 null，实际 0 保留）。
    pub attached_agents: Option<u64>,
    /// 可操作的实际生命周期与并发修订。
    pub review: SkillReviewView,
}

/// Skill 白名单视图（前端 `SkillWhitelist`）。
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct SkillWhitelistView {
    /// 允许访问的域名。
    pub domains: Vec<String>,
    /// 允许访问的路径。
    pub paths: Vec<String>,
}

/// 模型端点视图（前端 `ModelEndpoint`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ModelEndpointView {
    /// 资产 id。
    pub id: String,
    /// 厂商（前端枚举；无法判定时为 `custom`）。
    pub vendor: String,
    /// 模型标识。
    pub model: String,
    /// Base URL。
    pub endpoint: String,
    /// 是否本地/私有化部署（`attributes.local_deployment`，未提供为 null）。
    pub local: Option<bool>,
    /// 是否 Mock 模式（`attributes.mock_mode`，未提供为 null）。
    pub mock_mode: Option<bool>,
    /// 输入单价（元 / 1K token；缺少或无效时为 null）。
    pub input_price_per_k_tok: Option<f64>,
    /// 输出单价（元 / 1K token；缺少或无效时为 null）。
    pub output_price_per_k_tok: Option<f64>,
    /// 路由优先级（数值越小越优先；缺少或无效时为 null）。
    pub priority: Option<u32>,
    /// 是否作为降级目标（未提供为 null）。
    pub fallback: Option<bool>,
    /// P95 时延（毫秒；缺少或无效时为 null）。
    pub latency_p95_ms: Option<u64>,
    /// 健康度（前端枚举；台账无信号时 `unknown`）。
    pub health: String,
}

/// Skill lifecycle review fields read from the same inventory row.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SkillReviewView {
    /// Actual inventory lifecycle.
    pub lifecycle: String,
    /// Legal next states.
    pub allowed_next: Vec<String>,
    /// Optimistic concurrency revision.
    #[schema(value_type = String)]
    pub updated_at: Timestamp,
    /// Current owner.
    pub owner: String,
    /// Current department.
    pub department: String,
    /// Reviewed classification.
    pub data_class: String,
}
