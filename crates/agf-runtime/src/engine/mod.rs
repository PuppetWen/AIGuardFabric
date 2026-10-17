//! 运行时防御编排器（§4.3 对外唯一入口）。
//!
//! # 公开 API（`agf-api` / MCP 代理 / AI 网关共同依赖的契约）
//!
//! ```text
//! pub async fn evaluate(&self, ctx: PolicyContext) -> DomainResult<PolicyDecision>
//! pub async fn intercept_mcp_request(&self, ctx: PolicyContext, raw: &str) -> DomainResult<InterceptOutcome>
//! pub async fn complete_call(&self, ctx: &PolicyContext, consumption: QuotaConsumption) -> DomainResult<()>
//! pub async fn guard_report(&self) -> GuardReport
//! ```
//!
//! 这四个方法是**稳定契约**：上层只依赖它们，不直接触碰 [`crate::policy::PolicyEngine`]、
//! [`crate::quota::QuotaService`] 等内部件（内部件可通过 `*_mut` 访问器在装配期配置）。
//!
//! # 离线可构造
//!
//! [`RuntimeEngine::in_memory`] 不需要 Redis / PostgreSQL，装配出的是**功能完整**的引擎：
//! 策略（含 Rego/CEL）、内置黑名单、三级配额（内存计数）、审批（内存）、审计哈希链、自检。
//! 唯一的差别是配额计数为单进程近似值、审计链只保留最近 N 条——两者在报告里都会标注。
//!
//! # 与三个拦截点的关系
//!
//! | 拦截点 | 接入方式 |
//! |---|---|
//! | MCP 代理（stdio/SSE/HTTP） | [`RuntimeEngine::intercept_mcp_request`] / [`crate::mcp_proxy`] |
//! | AI 网关南北向 | [`RuntimeEngine::evaluate`]（网关侧自行做转发/改写） |
//! | eBPF/进程 Hook 东西向 | [`RuntimeEngine::evaluate_command`]（只有命令文本，没有完整上下文） |
//!
//! 网关与 eBPF 接入**不需要**依赖 `agf-aigw`：`evaluate` 的输入输出都是 `agf-core` 类型。

pub(crate) use std::sync::Arc;

pub(crate) use agf_core::enums::InterceptPoint;
pub(crate) use agf_core::enums::PolicyAction;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::mcp::McpTransport;

pub(crate) use agf_core::policy::PolicyContext;
pub(crate) use agf_core::policy::PolicyDecision;

pub(crate) use agf_core::quota::Quota;
pub(crate) use agf_core::quota::QuotaConsumption;

pub(crate) use agf_core::redact::RedactionMode;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use tokio::sync::Mutex;
pub(crate) use tokio::sync::RwLock;

pub(crate) use crate::approval::ApprovalStore;
pub(crate) use crate::approval::InMemoryApprovalStore;

pub(crate) use crate::audit::InterceptionAuditLog;
pub(crate) use crate::audit::InterceptionRecord;
pub(crate) use crate::audit::InterceptionVerdict;

pub(crate) use crate::blocklist::Blocklist;

pub(crate) use crate::guard::GuardReport;
pub(crate) use crate::guard::HeartbeatMonitor;
pub(crate) use crate::guard::ManagedEndpoint;
pub(crate) use crate::guard::SelfCheck;

pub(crate) use crate::mcp_proxy::InterceptOutcome;
pub(crate) use crate::mcp_proxy::JsonRpcFrame;
pub(crate) use crate::mcp_proxy::McpProxy;
pub(crate) use crate::mcp_proxy::McpProxySession;

pub(crate) use crate::policy::EvalErrorMode;
pub(crate) use crate::policy::HitSource;
pub(crate) use crate::policy::PolicyEngine;
pub(crate) use crate::policy::SignatureMode;

pub(crate) use crate::quota::InMemoryQuotaStore;
pub(crate) use crate::quota::QuotaService;

pub(crate) use crate::signature::PolicySigner;

#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests_2::*;

/// 引擎装配配置。
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// 租户（单实例多租户场景由调用方在上下文中给出具体租户；此处为默认租户）。
    pub tenant_id: TenantId,
    /// 必须被策略覆盖的拦截点（自检项 `intercept.points` 的判定依据）。
    required_points: Vec<InterceptPoint>,
    /// 脱敏模式。
    pub redaction_mode: RedactionMode,
    /// 审计缓冲容量。
    pub audit_capacity: usize,
    /// 是否注册心跳端点（离线演示默认注册一个代理端点）。
    pub enroll_self_proxy: bool,
    /// 心跳期望间隔（秒）。
    pub heartbeat_interval_secs: i64,
}

/// 运行时防御编排器。
///
/// 全部共享件都是 `Arc`，因此 `RuntimeEngine` 可被多个传输任务共享（`Arc<RuntimeEngine>`）。
/// 需要热重载的部件（策略、黑名单、配额）包在 `RwLock` / `Mutex` 中，
/// 由 `reload_*` 方法在**不中断服务**的前提下替换。
#[derive(Debug)]
pub struct RuntimeEngine {
    /// 配置。
    config: EngineConfig,
    /// 策略引擎（可热重载）。
    engine: RwLock<PolicyEngine>,
    /// 黑名单（可热重载）。
    blocklist: Mutex<Blocklist>,
    /// 配额服务（可热重载）。
    quotas: RwLock<Option<QuotaService>>,
    /// 审批存储。
    approvals: Arc<dyn ApprovalStore>,
    /// 拦截审计链。
    audit: Arc<InterceptionAuditLog>,
    /// 心跳监控。
    heartbeats: HeartbeatMonitor,
    /// MCP 代理内核（延迟构造：需要与热重载共享同一份策略/黑名单引用）。
    ///
    /// 这里**不**复用 [`McpProxy`]，因为代理需要读取"当前"策略与黑名单快照，
    /// 而 `McpProxy` 持有的是构造时的引擎副本。引擎入口在每次拦截时按当前快照
    /// 构造轻量代理，保证热重载立即生效。
    proxy_builder: ProxyBuilder,
}

/// 代理构造参数（与引擎共享副本，每次拦截时快照）。
#[derive(Debug, Clone)]
struct ProxyBuilder {
    /// 脱敏模式。
    redaction_mode: RedactionMode,
    /// 帧大小上限。
    max_frame_bytes: usize,
}

mod impl_engine_config;
mod impl_runtime_engine;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_2;
