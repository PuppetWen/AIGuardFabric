//! 案件闭环：由事件簇升级为案件，并管理状态机、时间线、finding 与合并/拆分（§4.6「案件闭环」）。
//!
//! 关联分析的价值最终要落到"有人在处理"：本模块把 [`crate::aggregate::EventCluster`] 升级为
//! [`agf_core::case::Case`]，并给出可运营的案件编排原语：
//!
//! | 能力 | 说明 |
//! |---|---|
//! | 升级为案件 | 事件簇 + 严重级策略 + 影响面 → 案件（含 `CASE-<年>-<序号>` 编号） |
//! | 状态机 | `new → investigating → containing → resolved → closed`，**非法迁移返回错误**，不静默吞掉 |
//! | 时间线 | 有序（按时间升序、同时刻按写入序）事件流，记录操作者与自动化标记 |
//! | finding 关联 | 案件 ↔ 漏洞发现的双向登记（`CaseDetail::findings`） |
//! | 合并 / 拆分 | 合并把源案件要素并入目标并留痕；拆分按子案规格重算 finding 归属，**未分配项显式列出** |
//!
//! ## 状态机语义
//!
//! 与 [`agf_core::case::Case::can_transition_to`] 保持一致（`resolved → investigating` 允许
//! 重新打开调查），额外约束：
//!
//! - **合并关闭源案件是合法流转**：源案件可能处于 `new`/`investigating`/`containing`/`resolved`，
//!   合并时直接落到 `closed`（合并本身就是"已解决并归档"），此路径由 [`CaseManager::merge`]
//!   显式实现，`CaseError::IllegalTransition` 仍会拦截 `closed → *`（归档后不可复活）。
//! - **等级只升不降**：合并取源案件最高等级；拆分不降低父案件等级（父案仍涵盖全部子案）。
//!
//! ## 降级行为
//!
//! | 能力 | 未实现/不可用时 | 锚点 |
//! |---|---|---|
//! | 案件编号持久化序列（`CASE-YYYY-NNNN` 全局唯一） | 内存计数器 + 已有编号扫描推导起点；生产由 DB 序列保证唯一 | `TODO(correlate-case-code-sequence)` |
//! | 案件时间线与案件的同事务落库 | 内存态：生产由 `agf-storage` 在同一事务写 `cases` + `case_events` | `TODO(correlate-case-persist)` |
//! | 跨租户案件合并（集团 SOC 统一处置） | **不做**：合并要求同租户，跨租户一律 [`CaseError::TenantViolation`] | `TODO(correlate-case-cross-tenant-merge)` |
//! | 自动指派（按值班表/负载选人） | 只按显式 `assignee` 或簇影响面推断；不读值班系统 | `TODO(correlate-case-auto-assign)` |

pub(crate) use std::collections::BTreeMap;
pub(crate) use std::collections::BTreeSet;

pub(crate) use agf_core::case::Case;
pub(crate) use agf_core::case::CaseEventKind;

pub(crate) use agf_core::enums::CaseState;
pub(crate) use agf_core::enums::Severity;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use crate::aggregate::EventCluster;

#[cfg(test)]
pub(crate) use crate::aggregate::AggregationConfig;
#[cfg(test)]
pub(crate) use crate::aggregate::AlertAggregator;
#[cfg(test)]
pub(crate) use crate::aggregate::AlertInput;

#[cfg(test)]
pub(crate) use agf_core::enums::RiskDomain;

#[allow(unused_imports)]
pub use impl_case_manager_2::*;
#[allow(unused_imports)]
pub use impl_case_severity_policy::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 严重级策略参数：如何由事件簇推导案件等级。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaseSeverityPolicy {
    /// 影响实体数达到该值时提升一级（默认 3）。
    pub multi_entity_threshold: usize,
    /// 是否允许把簇等级向上提升（默认 true）。关闭则案件等级 = 簇等级。
    pub escalate_on_spread: bool,
    /// 单簇重复次数达到该值时提升一级（默认 50）。
    pub high_repeat_threshold: u64,
}

/// 案件时间线条目类型。
///
/// 与 [`CaseEventKind`] 的区别：本枚举覆盖"案件编排"动作（合并/拆分），
/// [`CaseTimelineEvent::to_core_kind`] 给出落到 `agf-core` 模型时的映射。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimelineKind {
    /// 创建。
    Created,
    /// 状态流转。
    StateChanged,
    /// 指派。
    Assigned,
    /// 评论/备注。
    Comment,
    /// 新增证据。
    EvidenceAdded,
    /// 升级。
    Escalated,
    /// 合并入其它案件。
    Merged,
    /// 从其它案件拆分而来。
    Split,
    /// 关闭。
    Closed,
    /// SLA 期限/违约状态回写（案件状态本身未变）。
    SlaMarked,
}

/// 案件时间线条目。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaseTimelineEvent {
    /// 条目 id。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 案件 id。
    pub case_id: Id,
    /// 类型。
    pub kind: TimelineKind,
    /// 操作者（用户或系统）。
    pub actor: String,
    /// 说明。
    pub note: String,
    /// 结构化详情。
    pub detail: serde_json::Value,
    /// 是否自动化动作。
    pub automated: bool,
    /// 发生时间。
    pub at: Timestamp,
    /// 同刻写入序号（保证时间线稳定有序）。
    pub seq: u64,
}

/// 案件详情：案件 + finding + 时间线 + 派生标记。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseDetail {
    /// 案件本体（`agf-core` 模型）。
    pub case: Case,
    /// 关联 finding id（去重、稳定顺序）。
    pub findings: Vec<Id>,
    /// 时间线（升序）。
    pub timeline: Vec<CaseTimelineEvent>,
}

/// 子案规格（拆分输入）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubCaseSpec {
    /// 标题。
    pub title: String,
    /// 摘要。
    pub summary: String,
    /// 等级。
    pub severity: Severity,
    /// 该子案继承的 finding。
    pub finding_ids: Vec<Id>,
    /// 该子案继承的资产。
    pub asset_ids: Vec<Id>,
    /// 负责人。
    pub owner: Option<String>,
}

/// 拆分结论（**含未分配项，便于上层显式处置**）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseSplitPlan {
    /// 父案件（拆分后仍存在，作为"总案"，等级不降低）。
    pub parent: Case,
    /// 新建的子案件。
    pub children: Vec<Case>,
    /// 已分配到子案的 finding。
    pub assigned_findings: Vec<Id>,
    /// 未分配到任何子案的 finding（**不会丢失，仍留在父案件上**）。
    pub unassigned_findings: Vec<Id>,
}

/// 合并结论（**含未分配项**）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseMergePlan {
    /// 合并后的目标案件。
    pub target: Case,
    /// 被合并关闭的源案件。
    pub sources: Vec<Case>,
    /// 未从源案件迁出的 finding（目标已有同 id，或源案件本来就没有）。
    pub unmoved_findings: Vec<Id>,
}

/// 案件编排错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CaseError {
    /// 非法状态迁移。
    #[error("非法状态迁移: {from} → {to}（允许的目标: {allowed}）")]
    IllegalTransition {
        /// 当前状态。
        from: &'static str,
        /// 目标状态。
        to: &'static str,
        /// 允许的目标状态（逗号分隔）。
        allowed: String,
    },
    /// 案件不存在。
    #[error("案件不存在: {0}")]
    NotFound(Id),
    /// 已存在的案件 id 重复登记。
    #[error("案件已存在: {0}")]
    Duplicate(Id),
    /// 跨租户访问/合并被拒绝。
    #[error("租户隔离拒绝: 期望租户 {expected}，实际 {actual}")]
    TenantViolation {
        /// 期望租户。
        expected: String,
        /// 实际租户。
        actual: String,
    },
    /// 输入非法（空标题、空子案集等）。
    #[error("输入非法: {0}")]
    InvalidInput(String),
    /// 状态不允许该操作。
    #[error("状态不允许该操作: {state} 下不可 {action}")]
    StateConflict {
        /// 当前状态。
        state: &'static str,
        /// 被拒绝的动作。
        action: &'static str,
    },
}

/// 案件管理器：登记案件（含外部回填）、状态机、时间线、finding 与合并/拆分。
///
/// ## 租户隔离
///
/// 每个公开方法都要求显式传入 `tenant` 并逐条校验；跨租户访问返回
/// [`CaseError::TenantViolation`]，**不返回空结果**（避免调用方把"越权被拒"误读为"没有数据"）。
#[derive(Debug, Clone)]
pub struct CaseManager {
    /// 严重级策略。
    pub severity_policy: CaseSeverityPolicy,
    /// 默认负责人（升级为案件时的兜底指派；`None` 表示不自动指派）。
    pub default_owner: Option<String>,
    cases: BTreeMap<Id, CaseDetail>,
    /// 租户 → 已用最大案件序号（内存态，见模块级降级表）。
    code_seq: BTreeMap<TenantId, u32>,
}

mod impl_case_manager;
mod impl_case_manager_2;
mod impl_case_severity_policy;
#[cfg(test)]
mod tests;
