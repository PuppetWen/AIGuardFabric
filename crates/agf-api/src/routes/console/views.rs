//! 控制台只读端点的视图 DTO（字段名按前端 domain.ts 的驼峰倒推为 snake_case）。

use super::*;

// ===========================================================================
// 视图（字段名按 domain.ts 的驼峰倒推成 snake_case）
// ===========================================================================

/// KPI 卡片（前端 `DashboardKpi`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DashboardKpiView {
    /// KPI 键（前端联合类型：`assets`/`openAlerts`/`criticalFindings`/`redteamSuccessRate`/`tokenSpend`）。
    pub key: String,
    /// 前端 i18n 键（页面用 `overview.kpi.<key>` 渲染，此字段仅为契约完整）。
    pub label: String,
    /// 未观测或无权读取时为 null。
    pub value: Option<f64>,
    /// 单位（前端 i18n 键，如 `unit.assets`）。
    pub unit: String,
    /// 没有可比历史时为 null。
    pub delta: Option<f64>,
    /// 迷你趋势（**占位空数组**：无历史序列）。
    pub sparkline: Vec<f64>,
}

/// 时序点（前端 `SeriesPoint`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SeriesPointView {
    /// RFC 3339 时间戳。
    pub ts: String,
    /// 实际观测值；未观测时不创建点。
    pub value: f64,
}

/// 安全域分布（前端 `DomainDistribution`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DomainDistributionView {
    /// 安全域（前端枚举：`asset`/`data`/`identity`/`runtime`/`compliance`）。
    pub domain: String,
    /// 该域资产数。
    pub assets: i64,
    /// 该域发现数。
    pub findings: Option<i64>,
    /// 其中严重等级数。
    pub critical: Option<i64>,
}

/// 资产视图（前端 `Asset`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AssetView {
    /// 资产 id。
    pub id: String,
    /// 租户 id。
    pub tenant_id: String,
    /// 名称。
    pub name: String,
    /// 资产类型（前端 `AssetKind`）。
    pub kind: String,
    /// 归属人。
    pub owner: String,
    /// 部门。
    pub department: String,
    /// 数据分级。
    pub classification: String,
    /// 生命周期（前端 `LifecycleState`）。
    pub lifecycle: String,
    /// 暴露面（前端 `ExposureSurface`）。
    pub exposure: String,
    /// 风险分（0-100）。
    pub risk_score: Option<u8>,
    /// 未关闭发现数。
    pub open_findings: Option<i64>,
    /// 发现来源（前端 `DiscoverySource` 集合）。
    pub sources: Vec<String>,
    /// 标签。
    pub tags: Vec<String>,
    /// 首次发现时间。
    pub first_seen_at: String,
    /// 最近可见时间。
    pub last_seen_at: String,
    /// 一句话描述（由类型/厂商/版本/端点拼接，台账无独立描述字段）。
    pub description: String,
}

/// 最近告警（前端 `RecentAlert`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RecentAlertView {
    /// 告警 id。
    pub id: String,
    /// 标题。
    pub title: String,
    /// 等级。
    pub severity: String,
    /// 安全域（前端枚举，经映射）。
    pub domain: String,
    /// 关联资产名（取不到为空串）。
    pub asset_name: String,
    /// 发生时间（`last_seen_at`）。
    pub occurred_at: String,
    /// 状态（前端 `AlertStatus`，经映射）。
    pub status: String,
}

/// 适配器健康条（前端 `AdapterHealthBar`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AdapterHealthBarView {
    /// 适配器 id（云服务名）。
    pub id: String,
    /// 显示名。
    pub name: String,
    /// 类别（前端 `AdapterCategory`）。
    pub category: String,
    /// 健康度（**占位 `unknown`**：API 进程不主动探活）。
    pub health: String,
    /// 没有历史探活采样时为 null。
    pub uptime_percent: Option<f64>,
    /// 是否 Mock 模式（真实）。
    pub mock: bool,
}

/// 总览响应（前端 `DashboardOverview`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DashboardOverviewView {
    /// KPI 卡片（5 张，键固定）。
    pub kpis: Vec<DashboardKpiView>,
    /// 风险趋势（**只有当前一个点位**）。
    pub risk_trend: Vec<SeriesPointView>,
    /// 安全域分布（5 个域恒在）。
    pub domain_distribution: Vec<DomainDistributionView>,
    /// 高风险资产（按风险分倒序，最多 8 条）。
    pub top_risk_assets: Vec<AssetView>,
    /// 最近告警（按 `last_seen_at` 倒序，最多 6 条）。
    pub recent_alerts: Vec<RecentAlertView>,
    /// 适配器健康条。
    pub adapter_health: Vec<AdapterHealthBarView>,
    /// 当前身份可读取的指标类别。
    pub access: BTreeMap<String, bool>,
    /// 服务端完成采样的时间。
    pub generated_at: String,
}

/// 搜索命中（前端 `demo.SearchHit`，**裸数组**）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SearchHitView {
    /// 命中对象 id。
    pub id: String,
    /// 展示文本。
    pub label: String,
    /// 类型：`asset`/`alert`/`finding`/`rule`/`case`/`redteam`。
    pub kind: String,
    /// 副标题（等级/部门/风险分等）。
    pub hint: String,
    /// 跳转路径（控制台路由，如 `/assets`）。
    pub to: String,
}

/// 拓扑节点（前端 `TopologyNode`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TopologyNodeView {
    /// 节点 id（资产 id）。
    pub id: String,
    /// 显示名。
    pub label: String,
    /// 节点类型（前端字段名是 `type`，Rust 关键字故显式 rename）。
    #[serde(rename = "type")]
    pub node_type: String,
    /// 风险分。
    pub risk_score: Option<u8>,
    /// 是否影子资产。
    pub shadow: bool,
    /// 数据分级（可选）。
    pub classification: Option<String>,
    /// 详情行。
    pub detail: String,
}

/// 拓扑边（前端 `TopologyEdge`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TopologyEdgeView {
    /// 边 id（`<source>-><target>` 稳定可复现）。
    pub id: String,
    /// 起点节点 id。
    pub source: String,
    /// 终点节点 id。
    pub target: String,
    /// 关系类型：`invokes`/`exposes`/`reads`/`writes`/`routes-to`。
    pub kind: String,
    /// 是否携带数据出域。
    pub egress: bool,
    /// 24h 调用量（缺省 0；`attributes.calls_24h` 有值时取真实值）。
    pub calls_24h: i64,
}

/// 拓扑图（前端 `TopologyGraph`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TopologyGraphView {
    /// 节点。
    pub nodes: Vec<TopologyNodeView>,
    /// 边。
    pub edges: Vec<TopologyEdgeView>,
    /// 预计算的数据外传路径（节点 id 序列）。
    pub egress_paths: Vec<Vec<String>>,
}

/// 控制台用户（前端 `User`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserView {
    /// 乐观并发版本，PATCH 必须回传当前值。
    pub version: u64,
    /// 身份来源，避免将同邮箱的企业账号与本地账号混淆。
    pub identity_provider: String,
    /// 用户 id。
    pub id: String,
    /// 租户 id。
    pub tenant_id: String,
    /// 登录名。
    pub username: String,
    /// 显示名。
    pub display_name: String,
    /// 邮箱。
    pub email: String,
    /// 控制台角色（前端 `UserRole`）。
    pub role: String,
    /// 是否启用 MFA。
    pub mfa_enabled: bool,
    /// 是否必须先改密。
    pub must_change_password: bool,
    /// 最近登录时间。
    pub last_login_at: String,
    /// 状态：`active`/`locked`/`disabled`。
    pub status: String,
}

/// 白标配置（前端 `WhiteLabel`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WhiteLabelView {
    /// 产品名。
    pub product_name: String,
    /// Logo 文本。
    pub logo_text: String,
    /// 主色。
    pub primary_color: String,
    /// 站点图标（暂缺，`None`）。
    pub favicon: Option<String>,
}

/// 租户默认配额（前端 `QuotaDefaults`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct QuotaDefaultsView {
    /// 多人编辑版本；旧配置缺失时从 0 开始迁移。
    #[serde(default)]
    pub version: u64,
    /// 租户每日 Token。
    pub tenant_tokens_per_day: i64,
    /// Agent 每小时 Token（无按小时配额时为 0）。
    pub agent_tokens_per_hour: i64,
    /// 会话每轮 Token（无按轮配额时为 0）。
    pub session_tokens_per_turn: i64,
    /// 最大并发会话（取并发维度配额上限）。
    pub max_concurrent_sessions: i64,
}

fn tenant_enabled() -> bool {
    true
}

/// 租户（前端 `Tenant`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TenantView {
    /// 企业资料多人编辑版本。
    #[serde(default)]
    pub version: u64,
    /// 平台租户目录的启停版本，独立于企业资料版本。
    #[serde(default)]
    pub directory_version: u64,
    /// 平台租户目录名称，独立于企业资料展示名称。
    #[serde(default)]
    pub directory_name: String,
    /// 停用后除超管外拒绝访问。
    #[serde(default = "tenant_enabled")]
    pub enabled: bool,
    /// 租户 id。
    pub id: String,
    /// 短名。
    pub slug: String,
    /// 名称。
    pub name: String,
    /// 套餐：`community`/`standard`/`enterprise`。
    pub plan: String,
    /// 区域。
    pub region: String,
    /// 白标。
    pub white_label: WhiteLabelView,
    /// 默认配额。
    pub quota_defaults: QuotaDefaultsView,
    /// 创建时间。
    pub created_at: String,
}

/// API Key（前端 `ApiKey`，**不含指纹与明文**）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiKeyView {
    /// Authenticated Agent binding, if configured.
    pub bound_agent_id: Option<String>,
    /// Key id。
    pub id: String,
    /// 租户 id。
    pub tenant_id: String,
    /// 名称。
    pub name: String,
    /// 前缀（可对外暴露）。
    pub prefix: String,
    /// 权限点。
    pub scopes: Vec<String>,
    /// 创建时间。
    pub created_at: String,
    /// 过期时间（永不过期为 `null`）。
    pub expires_at: Option<String>,
    /// 最近使用时间。
    pub last_used_at: Option<String>,
    /// 是否已吊销。
    pub revoked: bool,
}

/// 口令策略（前端 `PasswordPolicy`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PasswordPolicyView {
    /// 当前持久化版本；旧记录缺失时从 0 开始。
    #[serde(default)]
    pub version: u64,
    /// 四类字符至少三类；逐类要求可独立叠加。
    #[serde(default)]
    pub require_classes: bool,
    /// 最小长度。
    pub min_length: i64,
    /// 是否要求大写（同取 `require_classes`）。
    pub require_uppercase: bool,
    /// 是否要求小写（同取 `require_classes`）。
    pub require_lowercase: bool,
    /// 是否要求数字（同取 `require_classes`）。
    pub require_digit: bool,
    /// 是否要求符号（同取 `require_classes`）。
    pub require_symbol: bool,
    /// 口令有效期（天，0 = 不过期）。
    pub max_age_days: i64,
    /// 禁止复用最近 N 次口令。
    pub history_size: i64,
    /// 连续失败锁定阈值。
    pub lockout_threshold: i64,
    /// 是否强制 MFA（平台无此开关，恒 false）。
    pub mfa_enforced: bool,
}

/// 黑名单条目（前端 `BlacklistEntry`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BlacklistEntryView {
    /// 规则 id。
    pub id: String,
    /// 当前版本；启停与删除必须提交此版本，旧配置返回 409。
    pub version: u64,
    /// 类别：`command`/`domain`（domain.ts 仅支持这两类）。
    pub kind: String,
    /// 匹配模式（`re:` 前缀表示正则）。
    pub pattern: String,
    /// 动作（前端 `PolicyAction`）。
    pub action: String,
    /// 作用域（恒 `tenant`：内置规则是平台级闸门）。
    pub scope: String,
    /// 是否启用。
    pub enabled: bool,
    /// 24h 命中数（**占位 0**：无统计读取接口）。
    pub hits_24h: i64,
    /// 说明（规则自带的命中原因）。
    pub note: String,
    /// 更新时间（**占位：进程启动时间**）。
    pub updated_at: String,
}

/// 拦截事件（前端 `InterceptEvent`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct InterceptEventView {
    /// 事件 id。
    pub id: String,
    /// 发生时间。
    pub ts: String,
    /// 拦截点。
    pub point: String,
    /// Agent 名（由 `agent_id` 反查台账，取不到时为 `-`）。
    pub agent_name: String,
    /// MCP 名（拦截链无该字段，恒 `null`）。
    pub mcp_name: Option<String>,
    /// 工具名。
    pub tool_name: Option<String>,
    /// 策略动作（前端 `PolicyAction`，经映射）。
    pub action: String,
    /// 命中的策略名。
    pub policy_name: String,
    /// 原因。
    pub reason: String,
    /// 载荷摘要（取拦截链条目的哈希，稳定可校验）。
    pub payload_digest: String,
    /// 拦截耗时（毫秒，来自审计链的实测微秒）。
    pub latency_ms: f64,
    /// 等级（缺省 `info`）。
    pub severity: String,
}

/// 拦截点状态（前端 `InterceptPointStatus`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct InterceptPointStatusView {
    /// 拦截点（前端枚举：`mcp-proxy`/`ai-gateway`/`process-hook`/`egress-proxy`）。
    pub point: String,
    /// 是否启用（API 进程内没有承载该点的代理进程，恒 false）。
    pub enabled: bool,
    /// 模式：`enforce`/`monitor`/`bypass`。
    pub mode: String,
    /// 健康度（恒 `unknown`：无探活）。
    pub health: String,
    /// 最近一分钟审计记录数。
    pub throughput_per_min: i64,
    /// 24h 阻断数（来自拦截审计链，真实）。
    pub blocked_24h: i64,
    /// 最近窗口的 P95 时延（毫秒；无样本时为 0）。
    pub p95_latency_ms: i64,
    /// 版本（取平台版本）。
    pub version: String,
    /// 最近错误（说明该点的实际归属）。
    pub last_error: Option<String>,
}

/// 配额用量（前端 `QuotaUsage`）。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct QuotaUsageView {
    /// 作用域：`tenant`/`agent`/`session`。
    pub scope: String,
    /// 作用域对象 id。
    pub scope_id: String,
    /// 作用域对象名。
    pub scope_name: String,
    /// 单位：`tokens`/`calls`/`sessions`。
    pub unit: String,
    /// 已用量（真实）。
    pub used: i64,
    /// 上限（真实）。
    pub limit: i64,
    /// 窗口开始（按窗口精度计算）。
    pub window_start: String,
    /// 窗口结束（取请求时刻）。
    pub window_end: String,
    /// 是否已超限（= `Quota::is_exceeded`）。
    pub throttled: bool,
}
