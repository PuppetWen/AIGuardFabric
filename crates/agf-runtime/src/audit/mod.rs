//! 拦截审计（§4.3 运行时审计 + §4.7 哈希链防篡改）。
//!
//! # 为什么需要独立于 `agf-core::audit` 的链
//!
//! `agf_core::audit::AuditLog` 记录的是**管理面**操作（谁改了策略、谁登录了）。
//! 运行时代理的拦截记录量级完全不同（每秒可能上千条），且必须能在
//! **没有数据库**的场合（离线演示、边车进程）独立产生与校验，
//! 因此本模块用同一套哈希链技术实现了一条**独立的、只追加的拦截链**：
//!
//! ```text
//! entry_hash = SHA256(canonical(record) ‖ prev_hash)
//! ```
//!
//! 与 `agf-core::audit` 的差异：
//!
//! | | `agf_core::audit::AuditLog` | 本模块 `InterceptionAuditLog` |
//! |---|---|---|
//! | 记录对象 | 管理面动作（策略/用户/配置） | 运行时拦截（MCP 调用、策略命中） |
//! | 校验函数 | `verify_chain`（含 sequence 连续性） | [`InterceptionAuditLog::verify`] |
//! | 摘要素材 | 前后快照 | 请求摘要（已脱敏） |
//! | 存储 | `agf-storage::AuditRepo`（Postgres） | 内存环形缓冲（可扩展落库） |
//!
//! # 防篡改能力边界（**诚实声明**）
//!
//! 哈希链能发现"改内容 / 删中间 / 插记录"，但**不能**阻止攻击者删除**整条链并重算**
//! （因为链是自洽的）。生产部署应把链尾哈希定期推送到平台侧（`agf-api`）并对锚点做
//! HMAC 签名——即 `agf-core::audit::AuditChainAnchor` 的做法。
//! 本模块提供 [`InterceptionAuditLog::tail_hash`] 作为锚点素材，
//! 并保留 TODO 锚点 `agf-runtime/interception-anchor-push`。
//!
//! TODO(agf-runtime/interception-anchor-push)：把 `tail_hash` + `len` 定期上报平台并签名。
//! 阻塞原因：需要 `agf-api` 提供上报端点（并发开发中）。影响：当前仅能发现链内篡改，
//! 无法发现"整链替换"。

pub(crate) use std::collections::VecDeque;

pub(crate) use std::sync::Mutex;

pub(crate) use agf_core::enums::PolicyAction;
pub(crate) use agf_core::enums::Severity;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::policy::PolicyDecision;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

#[allow(unused_imports)]
pub(crate) use impl_interception_verdict::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests_2::*;

/// 创世哈希（与 `agf_core::audit::GENESIS_HASH` 保持一致：64 个 0）。
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// 拦截的最终处置结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InterceptionVerdict {
    /// 放行（含脱敏放行）。
    Forwarded,
    /// 放行但改写了载荷（双向脱敏）。
    ForwardedRedacted,
    /// 已阻断。
    Blocked,
    /// 限流（可重试）。
    Throttled,
    /// 降级（转发到本地模型/缓存）。
    Degraded,
    /// 等待人工审批（**期间视为拒绝**）。
    PendingApproval,
    /// 已隔离（挂起 Agent）。
    Isolated,
    /// 已熔断。
    CircuitBroken,
    /// 只审计（dry-run 或 `audit` 动作）。
    Audited,
}

/// 一条拦截审计记录。
///
/// **字段一旦写入即不可变**：`sequence` / `prev_hash` / `entry_hash` 与摘要素材
/// 共同参与哈希计算，任何改动都会被 [`InterceptionAuditLog::verify`] 发现。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptionRecord {
    /// 主键。
    pub id: Id,
    /// 链内序号（从 1 开始，单调递增）。
    pub sequence: i64,
    /// 租户。
    pub tenant_id: TenantId,
    /// 会话 id。
    pub session_id: String,
    /// Agent 资产 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<Id>,
    /// 拦截点。
    pub intercept_point: agf_core::enums::InterceptPoint,
    /// 工具名。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    /// 目标（域名/路径/命令摘要）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// 命中的策略 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<Id>,
    /// 命中的策略名。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<String>,
    /// 命中的黑名单规则 id 列表。
    #[serde(default)]
    pub blocklist_rules: Vec<String>,
    /// 策略动作。
    pub action: PolicyAction,
    /// 最终处置。
    pub verdict: InterceptionVerdict,
    /// 决策原因（人类可读）。
    pub reason: String,
    /// 请求摘要（**已脱敏**；必须本身不含明文凭据）。
    pub request_excerpt: String,
    /// 响应摘要（出站脱敏后）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_excerpt: Option<String>,
    /// 是否实际执行了动作（dry-run 为 `false`）。
    pub enforced: bool,
    /// 严重等级。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    /// 关联审批单 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<Id>,
    /// **进入拦截处理 → 给出决策**的墙钟耗时（微秒，真实测量；见
    /// [`InterceptionRecord::with_latency_micros`]）。
    ///
    /// 精度取微秒而不是毫秒：本机单次判定常在 1ms 以下，毫秒精度会把整个分布压成 0，
    /// 让 `/runtime/intercept-points` 的 `p95_latency_ms` 继续"恒为 0"。
    ///
    /// `0` 只有两种来源，**不得**据此反推"零延迟"：
    /// 1. v0 记录缺该字段（`#[serde(default)]`，向后兼容）——升级前写下的记录；
    /// 2. 埋点未测量（测试/离线手工构造的记录，如 [`InterceptionRecord::new`] 的裸骨架）。
    ///
    /// 真实测量走 [`elapsed_micros`]（纳秒采样**向上取整**），因此"测过就一定 ≥ 1µs"：
    /// `0` 唯一表示"没有测量值"。
    ///
    /// 该字段**仅当 > 0 时**参与 [`Self::compute_hash`]，原因见该方法。
    #[serde(default)]
    pub latency_micros: u64,
    /// 上一条哈希。
    pub prev_hash: String,
    /// 本条哈希。
    pub entry_hash: String,
    /// 发生时间。
    pub at: Timestamp,
}

/// 链校验问题。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterceptionViolation {
    /// 出问题的记录 id。
    pub entry_id: Id,
    /// 序号。
    pub sequence: i64,
    /// 问题类型（`hash_mismatch` / `prev_gap` / `sequence_gap`）。
    pub kind: String,
    /// 说明。
    pub detail: String,
}

/// 链校验报告。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterceptionChainReport {
    /// 校验记录数。
    pub checked: usize,
    /// 是否通过。
    pub passed: bool,
    /// 问题列表。
    pub violations: Vec<InterceptionViolation>,
    /// 链首序号。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_sequence: Option<i64>,
    /// 链尾序号。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sequence: Option<i64>,
    /// 链尾哈希（锚点素材）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tail_hash: Option<String>,
    /// 校验时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<Timestamp>,
}

/// 拦截审计日志（只追加 + 哈希链 + 有界内存缓冲）。
///
/// # 并发模型
///
/// 全部可变状态放在 `Mutex<ChainState>` 内（**不使用 `unsafe`**，符合 workspace 级
/// `unsafe_code = "forbid"`）：写入路径加锁，读取路径克隆快照后释放锁。
/// 因此 [`InterceptionAuditLog::append`] 可以取 `&self`，
/// [`crate::engine::RuntimeEngine`] 的方法得以全部保持 `&self`。
///
/// 内存缓冲只是"最近 N 条"的热视图；生产环境应同时投递到事件总线/数据库
/// （见 TODO 锚点）。
///
/// TODO(agf-runtime/interception-persist)：经由 `agf-storage` 落库到
/// `events` / 专用 `interception_logs` 表，并把 `tail_hash` 上报锚点。
/// 阻塞原因：`agf-storage` 无对应表且正被并发修改；当前内存实现已满足
/// "离线演示 + 篡改可检出"的目标。
#[derive(Debug)]
pub struct InterceptionAuditLog {
    /// 受保护的链状态。
    state: Mutex<ChainState>,
    /// 缓冲上限（不可变）。
    capacity: usize,
}

/// 链状态（全部可变字段）。
#[derive(Debug)]
pub(crate) struct ChainState {
    /// 最近 N 条记录（环形）。
    entries: VecDeque<InterceptionRecord>,
    /// 累计写入条数（含已滚出缓冲的）。
    total: u64,
    /// 最后一条哈希（链尾，锚点素材）。
    tail_hash: String,
    /// 缓冲是否发生过滚出（滚出后 `verify()` 只覆盖当前窗口）。
    truncated: bool,
}

mod impl_interception_audit_log;
mod impl_interception_verdict;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_2;
