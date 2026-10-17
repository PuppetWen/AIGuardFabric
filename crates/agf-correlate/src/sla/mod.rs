//! SLA 计时与升级路由（§4.6「SLA 计时、升级路由」）。
//!
//! 案件/告警闭环里最容易"看起来做了其实没做"的就是 SLA：如果只在告警上记一个
//! `sla_due_at`，那么"响应阶段停了 3 小时等待变更窗口"这件事就无从体现，超时判定必然冤枉人。
//! 本模块把 SLA 建成一个**可暂停的钟**：
//!
//! | 能力 | 说明 |
//! |---|---|
//! | 三类目标 | 首次响应（first-response）/ 遏制（containment）/ 解决（resolution），各自有目标时长 |
//! | 按等级取时长 | [`SlaPolicy::for_severity`]：`critical` 15 分响应、`info` 24 小时解决等 |
//! | 暂停计时 | [`SlaPauseWindow`]（等变更窗口、等业务确认）在计算有效耗时时被扣除 |
//! | 违约判定 | [`SlaStatus`]：`pending` / `at-risk` / `met` / `breached`，含"已达成但当时已超时" |
//! | 升级阶梯 | [`EscalationStep`] + [`SlaClock::due_escalation`]：逾期 15 分升 L1、60 分升 L2 |
//!
//! ## 计时口径（**必须与上层对齐**）
//!
//! - 有效耗时 = `判定时刻 - 起点 - 落在 `[起点, 判定时刻]` 内的暂停时长`；
//! - 超过目标时长即 `breached`；达到 `warning_ratio × 目标` 但未超时即 `at-risk`；
//! - **达成时刻晚于截止** ⇒ `Breached`（`timeout: true`）：既不谎报"达成即合规"，
//!   也不把已发生的事实判成未达成；
//! - 暂停窗口与判定区间无交集（比如窗口完全在未来）时**不扣减**——避免"提前声明暂停"漂白 SLA。
//!
//! ## 降级行为
//!
//! | 能力 | 未实现/不可用时 | 锚点 |
//! |---|---|---|
//! | 工作日历（仅工作时间计时，跳过夜间/周末） | 不做：只支持显式 [`SlaPauseWindow`]；日历需要租户时区与节假日数据 | `TODO(correlate-sla-calendar)` |
//! | 计时状态的持久化与分布式续算 | 内存态：生产由 `agf-storage` 落 `sla_clocks` 表 | `TODO(correlate-sla-persist)` |
//! | 多级 SLA 策略按域/资产分级 | 只按 [`Severity`] 取策略；域/资产维度的差异化需上层给出 `SlaPolicy` | `TODO(correlate-sla-policy-matrix)` |
//! | 升级动作的实际派发（通知/改派） | 本模块只**判定**该升到哪一级；派发由 [`crate::notify`] 与 [`crate::playbook`] 负责 | `TODO(correlate-sla-escalation-dispatch)` |

pub(crate) use agf_core::enums::Severity;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

#[allow(unused_imports)]
pub use impl_sla_clock::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// SLA 目标类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SlaTarget {
    /// 首次响应（人工确认受理）。
    FirstResponse,
    /// 遏制（影响面停止扩大）。
    Containment,
    /// 解决（根因消除 + 复盘归档）。
    Resolution,
}

/// 目标达成记录。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlaMilestone {
    /// 达成时间。
    pub at: Timestamp,
    /// 达成时的操作者（人或系统）。
    pub actor: Option<Id>,
}

/// 暂停计时窗口（等待变更窗口/业务确认等）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlaPauseWindow {
    /// 开始。
    pub from: Timestamp,
    /// 结束（不含）。
    pub to: Timestamp,
    /// 暂停原因（审计必需，不允许空原因静默暂停）。
    pub reason: SlaPauseReason,
}

/// 暂停原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SlaPauseReason {
    /// 等待变更窗口。
    ChangeWindow,
    /// 等待业务方确认。
    BusinessConfirmation,
    /// 等待人工审批。
    AwaitingApproval,
    /// 依赖外部厂商处理。
    VendorPending,
    /// 其它（需在 note 里说明）。
    Other,
}

/// 升级阶梯的一级。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationStep {
    /// 层级（从 1 开始递增）。
    pub level: u8,
    /// 逾期多少秒后触发本级别（`0` = 一到截止就升级）。
    pub overdue_secs: i64,
    /// 升级目标描述（值班组/负责人/渠道名，仅作展示与审计）。
    pub target: EscalationTarget,
}

/// 升级目标（本 crate 只描述"该找谁"，不真正联系）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EscalationTarget {
    /// 一线值班。
    OnCall,
    /// 团队负责人。
    TeamLead,
    /// 安全负责人（CISO 线）。
    SecurityOwner,
    /// 应急指挥（重大事件）。
    IncidentCommander,
}

/// SLA 策略（按严重级取不同目标时长）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlaPolicy {
    /// 策略名。
    pub name: String,
    /// 适用等级。
    pub severity: Severity,
    /// 首次响应目标（秒）。
    pub first_response_secs: i64,
    /// 遏制目标（秒）。
    pub containment_secs: i64,
    /// 解决目标（秒）。
    pub resolution_secs: i64,
    /// 预警比例（`0.0..=1.0`），默认 0.8。
    pub warning_ratio: f64,
    /// 升级阶梯（按 `overdue_secs` 升序）。
    pub escalation: Vec<EscalationStep>,
    /// 暂停窗口。
    pub pause_windows: Vec<SlaPauseWindow>,
}

/// SLA 判定结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SlaStatus {
    /// 进行中且未接近截止。
    Pending,
    /// 进行中但已过预警线。
    AtRisk,
    /// 已在目标时长内达成。
    Met,
    /// 已逾期（或达成时已逾期）。
    Breached,
}

/// 单个目标的判定详情。
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SlaTargetStatus {
    /// 目标。
    pub target: SlaTarget,
    /// 结论。
    pub status: SlaStatus,
    /// 目标时长（秒）。
    pub target_secs: i64,
    /// 有效耗时（秒，已扣除暂停）。
    pub effective_elapsed_secs: i64,
    /// 扣除的暂停时长（秒）。
    pub paused_secs: i64,
    /// 距截止剩余（秒，已逾期为负；已达成则为达成时的剩余）。
    pub remaining_secs: i64,
    /// 是否"达成但已超时"。
    pub timed_out_before_met: bool,
}

/// SLA 时钟（一个案件/告警一个）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlaClock {
    /// 租户（隔离锚点）。
    pub tenant_id: TenantId,
    /// 关联对象 id（案件/告警）。
    pub subject_id: Id,
    /// 时钟起点（案件创建 / 告警首见）。
    pub started_at: Timestamp,
    /// 策略。
    pub policy: SlaPolicy,
    /// 已达成的目标 → 里程碑。
    pub milestones: Vec<(SlaTarget, SlaMilestone)>,
}

/// SLA 相关错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SlaError {
    /// 策略非法。
    #[error("SLA 策略非法: {0}")]
    InvalidPolicy(String),
    /// 时间顺序非法。
    #[error("时间顺序非法: {0}")]
    InvalidTime(String),
    /// 暂停原因不正当。
    #[error("暂停原因不正当: {0}（Other 不能作为暂停理由）")]
    IllegitimatePause(String),
    /// 租户隔离拒绝。
    #[error("租户隔离拒绝: 期望租户 {expected}，实际 {actual}")]
    TenantViolation {
        /// 期望租户。
        expected: String,
        /// 实际租户。
        actual: String,
    },
}

mod impl_sla_clock;
mod impl_sla_target;
#[cfg(test)]
mod tests;
