//! MCP 代理拦截（§4.3 拦截点：MCP 代理 stdio/SSE/HTTP）。
//!
//! # 定位：拦截**逻辑**，不是 socket 服务器
//!
//! 本模块实现 MCP 代理的**判定与改写内核**，不实现真实监听/转发：
//! 上层（`apps/server` 的 stdio 包装、SSE/HTTP 网关）负责读写字节流，
//! 把每个 JSON-RPC 帧交给 [`McpProxy::intercept_request`] /
//! [`McpProxy::intercept_response`]，再按 [`InterceptOutcome`] 决定
//! 转发、改写、拒绝或延迟。这样做的原因：
//!
//! - 判定逻辑可**离线单测**（无需真起 MCP 服务）；
//! - stdio / SSE / HTTP 三种传输共用同一内核，避免三份策略判定漂移；
//! - 传输实现可以被替换（也是 `agf-runtime` 不依赖 `agf-aigw` 的边界）。
//!
//! # JSON-RPC 2.0 帧契约
//!
//! MCP 使用 JSON-RPC 2.0。请求形如：
//!
//! ```json
//! {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_shell","arguments":{"command":"ls"}}}
//! ```
//!
//! 平台关心的字段（[`JsonRpcFrame`]）：`method`、`params.name`（工具名）、
//! `params.arguments`（工具参数）。非 `tools/call` 方法（`initialize`、`tools/list`、
//! `notifications/*`…）会**直接转发**，但仍是合法可解析的帧。
//!
//! ## 会话 id 的来源（重要）
//!
//! MCP 帧里**没有**会话概念（协议只有 `id` 请求关联符）。平台的"会话"是**代理侧**概念：
//! [`McpProxySession::with_session_id`] 在建立连接时由代理分配并固定下来，
//! 因此三级配额的会话级配额与审计的 `session_id` 都取代理侧值，而不是帧里的 `id`。
//!
//! # 拦截结论（[`InterceptOutcome`]）
//!
//! | 结论 | 触发条件 | 代理动作 |
//! |---|---|---|
//! | `Forward` | 全部放行 | 原样转发 |
//! | `ForwardRedacted { payload }` | 策略要求脱敏 | 用新的载荷替换原帧后转发 |
//! | `Blocked { decision }` | 策略 `deny`/`isolate`、黑名单命中 | 返回 JSON-RPC error 给客户端，**不转发** |
//! | `Throttled { retry_after }` | 配额超限且动作为限流 | 返回 429 语义 + 重试等待 |
//! | `Degraded { reason }` | 配额超限动作为降级 / 策略 degrade | 转发到本地模型或缓存 |
//! | `NeedsApproval { id }` | 策略 `approval` | **拒绝本次调用**并提示审批单 id |

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::sync::atomic::AtomicU64;
pub(crate) use std::sync::atomic::Ordering;

pub(crate) use std::time::Instant;

pub(crate) use agf_core::enums::InterceptPoint;
pub(crate) use agf_core::enums::PolicyAction;
pub(crate) use agf_core::enums::QuotaScope;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::mcp::McpInvocation;
pub(crate) use agf_core::mcp::McpTransport;

pub(crate) use agf_core::policy::PolicyContext;
pub(crate) use agf_core::policy::PolicyDecision;

pub(crate) use agf_core::quota::QuotaConsumption;

pub(crate) use agf_core::redact::RedactOutcome;
pub(crate) use agf_core::redact::RedactionMap;
pub(crate) use agf_core::redact::RedactionMode;
pub(crate) use agf_core::redact::redact_json;
pub(crate) use agf_core::redact::redact_text;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use tokio::sync::Mutex;

pub(crate) use crate::audit::InterceptionAuditLog;
pub(crate) use crate::audit::InterceptionRecord;
pub(crate) use crate::audit::InterceptionVerdict;
pub(crate) use crate::audit::elapsed_micros;

pub(crate) use crate::blocklist::Blocklist;
pub(crate) use crate::blocklist::RuleHit;

pub(crate) use crate::policy::PolicyEngine;

pub(crate) use crate::quota::QuotaService;

pub(crate) use crate::signature::PolicySigner;

#[allow(unused_imports)]
pub(crate) use impl_json_rpc_parse_error::*;
#[allow(unused_imports)]
pub use impl_mcp_proxy_2::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests_2::*;

/// MCP 请求/响应帧（JSON-RPC 2.0 子集 + 修改后的序列化）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcFrame {
    /// 协议版本，固定 `"2.0"`。
    pub jsonrpc: String,
    /// 请求关联 id（通知为 `None`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    /// 方法名（`tools/call`、`tools/list`、`initialize`…）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// 参数（`tools/call` 时为 `{name, arguments}`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    /// 响应结果。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// 响应错误。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<serde_json::Value>,
}

/// JSON-RPC 帧解析错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonRpcParseError {
    /// 不是合法 JSON。
    InvalidJson(String),
    /// 顶层不是对象。
    NotAnObject,
    /// `jsonrpc` 字段缺失或不为 `"2.0"`。
    BadVersion(String),
    /// 既无 `method` 也无 `result`/`error`（无法判定方向）。
    UnknownShape,
    /// 帧过大（超过 `max_bytes`）。
    TooLarge {
        /// 实际大小。
        actual: usize,
        /// 上限。
        limit: usize,
    },
}

/// 帧中提取出的目标（供黑名单与策略判定）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FrameTargets {
    /// 命令文本。
    pub command: Option<String>,
    /// 文件路径。
    pub path: Option<String>,
    /// 域名。
    pub domain: Option<String>,
}

/// 拦截结论。
///
/// **不实现 `PartialEq`**：`Blocked` 携带的 [`PolicyDecision`] 不适合做结构相等比较
/// （`eval_micros` 每次不同），测试请用 `matches!` 断言具体变体。
#[derive(Debug, Clone)]
pub enum InterceptOutcome {
    /// 原样转发。
    Forward,
    /// 用脱敏后的载荷转发（`payload` 是完整的新帧文本）。
    ForwardRedacted {
        /// 改写后的 JSON-RPC 帧文本。
        payload: String,
        /// 脱敏条目数。
        redactions: usize,
    },
    /// 阻断（附决策）。
    Blocked {
        /// 决策（含原因与命中策略）。
        decision: Box<PolicyDecision>,
    },
    /// 限流（附建议重试等待秒数）。
    Throttled {
        /// 建议重试等待（秒）。
        retry_after: i64,
    },
    /// 降级。
    Degraded {
        /// 降级原因。
        reason: String,
    },
    /// 需要人工审批（**本次拒绝**，附审批单 id）。
    NeedsApproval {
        /// 审批单 id。
        id: Id,
        /// 控制台链接。
        link: String,
    },
}

/// MCP 代理会话（连接级状态机）。
///
/// 生命周期：建立连接 ⇒ [`McpProxySession::new`] ⇒ 逐帧
/// [`McpProxySession::intercept_request`] / [`McpProxySession::intercept_response`]
/// ⇒ 结束 [`McpProxySession::finish`]（归还并发额度）。
///
/// 会话状态由内部 [`Mutex`] 保护，因此多个传输任务（stdio 读 / SSE 写）可并发调用。
#[derive(Debug)]
pub struct McpProxySession {
    /// 会话 id（代理侧分配）。
    session_id: String,
    /// 租户。
    tenant_id: TenantId,
    /// Agent 资产 id。
    agent_id: Option<Id>,
    context: Option<PolicyContext>,
    /// 传输方式。
    transport: McpTransport,
    /// 目标 MCP Server 资产 id。
    mcp_server_id: Id,
    /// 调用计数与状态。
    state: Mutex<SessionState>,
}

/// 会话内部状态。
#[derive(Debug, Default)]
struct SessionState {
    /// 总调用数。
    calls: u64,
    /// 被拦截数。
    blocked: u64,
    /// 脱敏次数。
    redacted: u64,
    /// 待审批调用数。
    pending_approvals: u64,
    /// 并发是否已登记（用于 [`McpProxySession::finish`] 归还）。
    concurrency_held: bool,
    /// 工具调用分布。
    tool_usage: BTreeMap<String, u64>,
}

/// 会话统计快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStats {
    /// 会话 id。
    pub session_id: String,
    /// 传输方式。
    pub transport: McpTransport,
    /// 总调用数。
    pub calls: u64,
    /// 被拦截数。
    pub blocked: u64,
    /// 脱敏改写次数。
    pub redacted: u64,
    /// 待审批调用数。
    pub pending_approvals: u64,
    /// 是否仍持有并发额度。
    pub concurrency_held: bool,
    /// 工具调用分布。
    pub tool_usage: BTreeMap<String, u64>,
}

/// MCP 代理内核。
///
/// 组合「黑名单 + 策略 + 配额 + 审批 + 审计 + 脱敏」。所有字段均为共享引用，
/// 因此代理本身是轻量可克隆的（`Arc` 语义由上层决定）。
#[derive(Debug)]
pub struct McpProxy {
    /// 策略引擎。
    engine: PolicyEngine,
    /// 黑名单（`Mutex`：求值会累计命中统计）。
    blocklist: Mutex<Blocklist>,
    /// 配额服务。
    quotas: Option<QuotaService>,
    /// 审批服务。
    approvals: Option<std::sync::Arc<dyn crate::approval::ApprovalStore>>,
    /// 拦截审计链。
    audit: std::sync::Arc<InterceptionAuditLog>,
    /// 脱敏模式。
    redaction_mode: RedactionMode,
    /// 帧大小上限。
    max_frame_bytes: usize,
    /// 累计拦截调用数（放行 + 拦截）。
    intercepted_total: AtomicU64,
}

/// 便捷：配额作用域标签（控制台展示）。
#[must_use]
pub const fn scope_label(scope: QuotaScope) -> &'static str {
    scope.as_str()
}

mod impl_json_rpc_parse_error;
mod impl_mcp_proxy;
mod impl_mcp_proxy_2;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_2;
