//! 统一适配器契约（§5.3）。
//!
//! 所有外部系统（大模型厂商、阿里云五服务、青藤云、各厂商 WAF、消息中间件）
//! 都实现同一个 [`Adapter`] trait：`init / health / sync / push / pull / shutdown`。
//!
//! 三条硬约束：
//! 1. **配置驱动 + 热插拔**：适配器由 [`AdapterConfig`] 描述，运行时可增删；
//! 2. **未配置即降级**：`init` 返回 [`HealthState::Unconfigured`] 而不是错误，
//!    由 `MockAdapter`（各 crate 内 `mock` 模块）接管，保证平台永远可启动；
//! 3. **熔断 + 重试 + 死信隔离**：`invoke` 必须经过 [`CircuitBreakerConfig`] 包裹，
//!    连续失败进死信队列（[`DeadLetterEntry`]），不阻塞主流程。

use std::collections::BTreeMap;

use async_trait::async_trait;

use serde::{Deserialize, Serialize};

use crate::enums::HealthState;

use crate::error::DomainResult;

use crate::ids::{Id, TenantId};

use crate::time::Timestamp;

#[allow(unused_imports)]
pub use impl_adapter_capability::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 适配器能力标签。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdapterCapability {
    /// 拉取远端台账/资源清单。
    PullInventory,
    /// 推送平台配置/策略到远端。
    PushConfig,
    /// 上报指标。
    PushMetrics,
    /// 上报事件/告警。
    PushEvents,
    /// 订阅远端事件流。
    SubscribeEvents,
    /// 查询远端日志。
    QueryLogs,
    /// 下发拦截/封禁策略。
    EnforcePolicy,
    /// 注册/触发任务调度。
    ScheduleTask,
    /// 健康与权限自检。
    SelfCheck,
    /// 跨账号 AssumeRole。
    AssumeRole,
    /// 私网连通性探测。
    ProbePrivateLink,
}

/// 适配器配置（DB 实体，`adapter_configs` 表）。
///
/// 敏感值一律通过 `secret_refs` 指向 `credentials` 表（密文），
/// `settings` 只放非敏感参数（区域、endpoint、超时、开关）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterConfig {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 适配器注册名（如 `alicloud-cms`、`llm-openai`、`qingteng`）。
    pub adapter: String,
    /// 显示名。
    pub display_name: String,
    /// 是否启用。
    pub enabled: bool,
    /// 非敏感设置。
    #[serde(default)]
    pub settings: BTreeMap<String, serde_json::Value>,
    /// 凭据引用（键 = 用途名，如 `access_key_id`）。
    #[serde(default)]
    pub secret_refs: BTreeMap<String, Id>,
    /// 熔断配置。
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    /// 重试配置。
    #[serde(default)]
    pub retry: RetryConfig,
    /// 请求超时（秒）。
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// 是否走 Mock（不触达真实外部系统）。
    #[serde(default)]
    pub mock: bool,
    /// 是否为该适配器类型的默认实例。
    #[serde(default)]
    pub is_default: bool,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 更新时间。
    pub updated_at: Timestamp,
}

const fn default_timeout() -> u64 {
    30
}

/// 熔断配置。
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// 是否启用。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 连续失败阈值（达到即开路）。
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    /// 开路持续时间（秒），之后进入半开。
    #[serde(default = "default_open_secs")]
    pub open_secs: i64,
    /// 半开状态允许的探测请求数。
    #[serde(default = "default_half_open")]
    pub half_open_probes: u32,
}

const fn default_true() -> bool {
    true
}

const fn default_failure_threshold() -> u32 {
    5
}

const fn default_open_secs() -> i64 {
    30
}

const fn default_half_open() -> u32 {
    1
}

/// 熔断器运行态（内存态，不落库）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CircuitState {
    /// 闭合（正常）。
    Closed,
    /// 开路（快速失败）。
    Open,
    /// 半开（探测）。
    HalfOpen,
}

/// 可序列化的熔断器状态（用于跨请求保留，实际实现见 `agf-adapters::circuit`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitSnapshot {
    /// 状态。
    pub state: CircuitState,
    /// 连续失败数。
    pub consecutive_failures: u32,
    /// 开路起始时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opened_at: Option<Timestamp>,
    /// 半开探测剩余次数。
    pub probes_left: u32,
    /// 累计成功。
    pub total_success: u64,
    /// 累计失败。
    pub total_failure: u64,
    /// 最近错误。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// 重试配置（指数退避）。
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RetryConfig {
    /// 最大尝试次数（含首次）。
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    /// 初始退避（毫秒）。
    #[serde(default = "default_backoff")]
    pub initial_backoff_ms: u64,
    /// 退避倍数。
    #[serde(default = "default_multiplier")]
    pub multiplier: f32,
    /// 最大退避（毫秒）。
    #[serde(default = "default_max_backoff")]
    pub max_backoff_ms: u64,
    /// 是否加入抖动（避免惊群）。
    #[serde(default = "default_true")]
    pub jitter: bool,
}

const fn default_max_attempts() -> u32 {
    3
}

const fn default_backoff() -> u64 {
    200
}

const fn default_multiplier() -> f32 {
    2.0
}

const fn default_max_backoff() -> u64 {
    10_000
}

/// 适配器健康报告。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterHealth {
    /// 适配器名。
    pub adapter: String,
    /// 状态。
    pub state: HealthState,
    /// 是否配置齐全。
    pub configured: bool,
    /// 是否 Mock 模式。
    pub mocked: bool,
    /// 延迟（毫秒）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    /// 熔断快照。
    pub circuit: CircuitSnapshot,
    /// 能力列表。
    #[serde(default)]
    pub capabilities: Vec<AdapterCapability>,
    /// 说明/错误。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// 检查时间。
    pub checked_at: Timestamp,
}

/// 同步结果（`sync` 的返回值）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncOutcome {
    /// 拉取到的条目数。
    pub pulled: usize,
    /// 推送成功的条目数。
    pub pushed: usize,
    /// 跳过（未变化）的条目数。
    pub skipped: usize,
    /// 失败条目数。
    pub failed: usize,
    /// 是否使用了 Mock 数据。
    pub mocked: bool,
    /// 是否因降级而只做部分同步。
    pub degraded: bool,
    /// 变化摘要（`实体类型 → 变更数`）。
    #[serde(default)]
    pub changes: BTreeMap<String, usize>,
    /// 警告。
    #[serde(default)]
    pub warnings: Vec<String>,
    /// 耗时（毫秒）。
    pub elapsed_ms: u64,
    /// 完成时间。
    pub finished_at: Option<Timestamp>,
}

/// 同步方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyncDirection {
    /// 仅拉取（远端 → 平台）。
    Pull,
    /// 仅推送（平台 → 远端）。
    Push,
    /// 双向（冲突以平台为准并告警）。
    Both,
}

/// 推送载荷（平台 → 远端）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushPayload {
    /// 目标实体类型（`policy` / `metric` / `event` / `schedule`）。
    pub entity: String,
    /// 实体id。
    pub entity_id: String,
    /// 载荷体。
    pub body: serde_json::Value,
    /// 幂等键（远端据此去重）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

/// 拉取请求（平台 ← 远端）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PullRequest {
    /// 资源类型（`agents` / `teams` / `services` / `alarms`）。
    #[serde(default)]
    pub resource: String,
    /// 过滤条件（远端语法，透传）。
    #[serde(default)]
    pub filter: BTreeMap<String, String>,
    /// 游标（增量拉取）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// 最大条数。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// 拉取结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullResponse {
    /// 条目。
    pub items: Vec<serde_json::Value>,
    /// 下一页游标。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// 是否 Mock。
    #[serde(default)]
    pub mocked: bool,
    /// 来源（真实 endpoint 或 fixture 路径，便于排障）。
    #[serde(default)]
    pub origin: String,
}

/// 死信条目（连续失败后落库，不阻塞主流程）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadLetterEntry {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 适配器名。
    pub adapter: String,
    /// 操作名（`sync` / `push` / `pull`）。
    pub operation: String,
    /// 载荷。
    pub payload: serde_json::Value,
    /// 最后一次错误。
    pub error: String,
    /// 尝试次数。
    pub attempts: u32,
    /// 是否已重放成功。
    #[serde(default)]
    pub replayed: bool,
    /// 首次失败时间。
    pub first_failed_at: Timestamp,
    /// 最近失败时间。
    pub last_failed_at: Timestamp,
}

/// 适配器元信息（注册表用，用于控制台"接入管理"页展示）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterDescriptor {
    /// 注册名。
    pub name: String,
    /// 显示名。
    pub display_name: String,
    /// 分类（`alicloud` / `llm` / `siem` / `waf` / `message` / `identity`）。
    pub category: String,
    /// 必需凭据键。
    #[serde(default)]
    pub required_secrets: Vec<String>,
    /// 可选凭据键。
    #[serde(default)]
    pub optional_secrets: Vec<String>,
    /// 能力。
    #[serde(default)]
    pub capabilities: Vec<AdapterCapability>,
    /// **未配置时的降级行为说明**（§12.4 强制要求写明）。
    pub degradation: String,
    /// Mock 实现位置（文件路径或模块名）。
    pub mock_location: String,
    /// 是否有真实实现。
    pub real_implementation: bool,
    /// 文档链接（`docs/adapter-spec.md` 锚点）。
    #[serde(default)]
    pub doc_anchor: String,
}

/// 统一适配器契约。
///
/// 实现者注意：
/// - `init` **不应**在未配置时返回 `Err`，而是返回 `Ok(())` 并通过 [`Self::health`]
///   暴露 [`HealthState::Unconfigured`]，让上层决定是否切到 Mock；
/// - 所有网络调用必须走 `invoke` 包装（熔断 + 重试 + 死信），不要直接 `await` 底层客户端；
/// - `shutdown` 必须幂等，允许重复调用。
#[async_trait]
pub trait Adapter: Send + Sync {
    /// 适配器注册名。
    fn name(&self) -> &str;

    /// 适配器元信息。
    fn descriptor(&self) -> AdapterDescriptor;

    /// 初始化（建立连接、加载配置、预热）。未配置时返回 `Ok(())` 并标记未配置。
    ///
    /// # Errors
    /// 仅当**配置存在但非法**（如 URL 格式错误、凭据解密失败）时返回错误。
    async fn init(&mut self, config: &AdapterConfig) -> DomainResult<()>;

    /// 健康检查（同时更新熔断状态）。
    ///
    /// # Errors
    /// 探测过程本身的不可恢复错误（如配置损坏）；网络失败应映射为健康状态而非错误。
    async fn health(&self) -> DomainResult<AdapterHealth>;

    /// 同步：按 `direction` 拉取/推送台账与配置。
    ///
    /// # Errors
    /// 返回可重试错误，由调用方决定是否进死信队列。
    async fn sync(&self, direction: SyncDirection, req: &PullRequest) -> DomainResult<SyncOutcome>;

    /// 推送单个实体到远端。
    ///
    /// # Errors
    /// 远端拒绝或网络失败。
    async fn push(&self, payload: &PushPayload) -> DomainResult<()>;

    /// 从远端拉取。
    ///
    /// # Errors
    /// 远端拒绝或网络失败。
    async fn pull(&self, req: &PullRequest) -> DomainResult<PullResponse>;

    /// 自检（连通性 / 最小权限 / 配额余量），供"云环境自检"页调用。
    ///
    /// # Errors
    /// 自检本身无法执行时返回错误；单项检查不通过应体现在 [`AdapterHealth`] 中。
    async fn self_check(&self) -> DomainResult<AdapterHealth> {
        self.health().await
    }

    /// 关闭（幂等）。
    ///
    /// # Errors
    /// 关闭过程中的错误。
    async fn shutdown(&mut self) -> DomainResult<()>;
}

mod impl_adapter_capability;
#[cfg(test)]
mod tests;
