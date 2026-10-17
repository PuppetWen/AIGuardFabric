//! SOAR-lite 剧本：声明式 YAML 剧本 + 确定性执行器（§4.6「SOAR-lite 剧本」）。
//!
//! 剧本本身是数据（[`agf_core::case::Playbook`]，YAML 可读可审），执行是**纯编排**：
//! 每一步要么求值、要么把动作交给注入的实现（[`ActionExecutor`] / [`NotifySink`] /
//! [`ApprovalGate`]）。因此本模块**绝不调用任何外部系统**，离线即可完整回放与断言。
//!
//! ## 步骤形态（由 `agf-core` 模型派生）
//!
//! | 形态 | 来源字段 | 语义 |
//! |---|---|---|
//! | [`StepKind::Condition`] | `params.condition`（CEL 表达式） | 为假 → 本步跳过（不算失败） |
//! | [`StepKind::Notify`] | `notify_channel` | 经 [`NotifySink`] 发送 |
//! | [`StepKind::Action`] | `action`（处置动作） | 经 [`ActionExecutor`] 执行（阻断/隔离/吊销…） |
//! | [`StepKind::Wait`] | `params.wait_secs` | 挂起等待（经 [`ActionExecutor::wait`]，可被审批否决中止） |
//! | [`StepKind::Approval`] | `params.require_approval` | 人工审批门（无注入 → **拒绝并留痕**，绝不自动放行） |
//!
//! ## 确定性保证
//!
//! - 步骤**严格按声明顺序**执行，无并行、无重排；
//! - 条件用 CEL 求值，未声明引用/缺键归一为"条件为假"（该步跳过），其它求值错误 → 步骤失败；
//! - 每步最多尝试 `step_max_attempts` 次（默认 1，即不重试），失败是否继续由 `continue_on_error` 决定；
//! - 超时同时检查声明时长，并使用单调时钟限制每步和整体执行；超时中止后不撤销已完成动作；
//! - 全流程产出 [`PlaybookRun`] 轨迹（含每步结论、尝试次数、错误与可读笔记）。
//!
//! ## 降级行为
//!
//! | 能力 | 未实现/不可用时 | 锚点 |
//! |---|---|---|
//! | 真实动作执行（EDR 隔离、IAM 吊销、WAF 封禁…） | **不做**：一切外部系统经 [`ActionExecutor`] 注入；本 crate 只提供 [`MockActionExecutor`] | `TODO(correlate-playbook-actions)` |
//! | 真实通知发送 | 经 [`NotifySink`] 注入（可用 [`crate::notify::NotificationDispatcher`] 实现） | `TODO(correlate-playbook-notify)` |
//! | 主动挂起与跨请求恢复（持久化等待状态机） | 执行器同步返回 [`WaitOutcome`]；真正长时间挂起需 `agf-runtime` 落库并用调度器恢复 | `TODO(correlate-playbook-durable-wait)` |
//! | 执行超时 | 每步使用 tokio deadline，中止后保留已完成轨迹 | `PlaybookEngine::run` |
//! | 并行步骤 / 循环 / 子剧本调用 | 不支持：保持"线性确定性"以便审计与重放 | `TODO(correlate-playbook-dag)` |

pub(crate) use std::collections::BTreeMap;

pub(crate) use agf_core::case::ContainmentAction;
pub(crate) use agf_core::case::Playbook;
pub(crate) use agf_core::case::PlaybookStep;

pub(crate) use agf_core::enums::AssetKind;
pub(crate) use agf_core::enums::RiskDomain;
pub(crate) use agf_core::enums::Severity;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::notify as core_notify;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use async_trait::async_trait;

pub(crate) use cel_interpreter::Context;
pub(crate) use cel_interpreter::Program;
pub(crate) use cel_interpreter::Value;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

#[cfg(test)]
pub(crate) use agf_core::case::PlaybookTrigger;

#[allow(unused_imports)]
pub use impl_trigger_input::*;
#[allow(unused_imports)]
pub use retry::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

#[cfg(test)]
mod execution_tests;

/// 剧本触发判定输入（把 `agf-core` 的扁平参数收成一个可读结构）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriggerInput {
    /// 安全域。
    pub domain: Option<RiskDomain>,
    /// 严重等级。
    pub severity: Severity,
    /// 命中规则键。
    pub rule_keys: Vec<String>,
    /// 资产类型。
    pub asset_kind: Option<AssetKind>,
}

/// 剧本执行上下文（CEL 变量与动作参数的来源）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunContext {
    /// 租户（隔离锚点）。
    pub tenant_id: TenantId,
    /// 关联案件 id。
    pub case_id: Option<Id>,
    /// 关联告警 id。
    pub alert_id: Option<Id>,
    /// 严重等级。
    pub severity: Severity,
    /// 安全域文本。
    pub domain: String,
    /// 命中规则键。
    pub rule_keys: Vec<String>,
    /// 涉及资产 id。
    pub asset_ids: Vec<Id>,
    /// 关联 finding id。
    pub finding_ids: Vec<Id>,
    /// 附加变量（同时供 CEL 与动作参数使用，字符串化的值）。
    pub params: BTreeMap<String, String>,
}

/// 等待类步骤的结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WaitOutcome {
    /// 等待结束，继续执行。
    Completed,
    /// 等待期间被中止（例如人工否决/取消），剧本中止。
    Aborted,
    /// 等待超时，剧本中止。
    TimedOut,
}

/// 步骤执行结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StepOutcome {
    /// 执行成功。
    Succeeded,
    /// 因条件为假而跳过（**不是失败**）。
    Skipped,
    /// 执行失败。
    Failed,
}

/// 整次运行结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunOutcome {
    /// 全部步骤执行完毕（允许有失败步骤，只要 `continue_on_error` 允许）。
    Completed,
    /// 中止（步骤失败且不允许继续 / 等待被中止 / 审批被拒）。
    Aborted,
    /// 未启动（剧本关闭 / 触发不匹配 / 审批被拒于启动前）。
    NotStarted,
}

/// 步骤形态（由 `agf-core` 步骤字段派生）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum StepKind {
    /// 条件判断（CEL 表达式）。
    Condition {
        /// CEL 表达式。
        expression: String,
    },
    /// 通知。
    Notify {
        /// 渠道键。
        channel: String,
    },
    /// 处置动作（阻断/隔离/吊销…）。
    Action {
        /// 动作。
        action: ContainmentAction,
    },
    /// 挂起等待。
    Wait {
        /// 等待秒数。
        secs: i64,
    },
    /// 人工审批门。
    Approval,
    /// 空步骤（配置错误）。
    Empty,
}

/// 单步执行记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepTrace {
    /// 步骤序号（从 0 开始）。
    pub index: usize,
    /// 步骤名。
    pub name: String,
    /// 形态。
    pub kind: String,
    /// 结论。
    pub outcome: StepOutcome,
    /// 实际尝试次数。
    pub attempts: u32,
    /// 错误原因（失败时）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// 可读笔记（跳过原因、执行结果）。
    pub note: String,
    /// 是否自动化产生（剧本执行恒为 true）。
    pub automated: bool,
}

/// 整次剧本运行的轨迹与结论。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaybookRun {
    /// 剧本键。
    pub playbook_key: String,
    /// 剧本版本。
    pub playbook_version: u32,
    /// 租户。
    pub tenant_id: TenantId,
    /// 关联案件。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_id: Option<Id>,
    /// 结论。
    pub outcome: RunOutcome,
    /// 逐步轨迹（严格按执行顺序）。
    pub trace: Vec<StepTrace>,
    /// 中止/未启动原因。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// 是否空转（演练）执行。
    pub dry_run: bool,
    /// 结束时间。
    pub finished_at: Timestamp,
}

/// 动作执行器抽象：**一切外部系统都必须经此注入**（离线可测的关键）。
#[async_trait]
pub trait ActionExecutor: Send + Sync + std::fmt::Debug {
    /// 执行一个处置动作，返回可读结果。
    ///
    /// # Errors
    /// 动作执行失败（外部系统不可用/被策略拒绝）时返回原因。
    async fn execute(&self, action: ContainmentAction, ctx: &RunContext) -> Result<String, String>;

    /// 挂起等待，返回等待结论。
    ///
    /// # Errors
    /// 等待无法建立（依赖不可用）时返回原因。
    async fn wait(&self, secs: i64, ctx: &RunContext) -> Result<WaitOutcome, String>;
}

/// 通知注入点（由 [`crate::notify`] 的实现满足）。
#[async_trait]
pub trait NotifySink: Send + Sync + std::fmt::Debug {
    /// 发送通知。
    ///
    /// # Errors
    /// 渠道不可用/失败时返回原因。
    async fn notify(&self, channel: &str, ctx: &RunContext, note: &str) -> Result<String, String>;
}

/// 人工审批门。
///
/// **未注入时的默认行为是拒绝**（[`PlaybookEngine::approval`] 返回 `None`）：
/// 无人审批时自动放行不可逆动作是安全事故，不是"便利"。
#[async_trait]
pub trait ApprovalGate: Send + Sync + std::fmt::Debug {
    /// 请求审批，返回是否批准。
    ///
    /// # Errors
    /// 审批系统不可用时返回原因（此时执行器视为**未批准**）。
    async fn approve(&self, ctx: &RunContext, reason: &str) -> Result<bool, String>;
}

/// Mock 动作执行器：记录全部调用，可编程失败。
#[derive(Debug)]
pub struct MockActionExecutor {
    /// 前 N 次动作调用失败。
    fail_first: u32,
    /// 等待结论。
    wait_outcome: WaitOutcome,
    state: std::sync::Mutex<MockActionState>,
}

#[derive(Debug, Default)]
struct MockActionState {
    calls: Vec<(String, String)>,
    waits: Vec<i64>,
    failures: u32,
}

/// Mock 通知点：记录全部通知。
#[derive(Debug, Default)]
pub struct MockNotifySink {
    state: std::sync::Mutex<Vec<(String, String)>>,
}

/// Mock 审批门（固定结论）。
#[derive(Debug, Clone, Copy)]
pub struct MockApprovalGate {
    /// 是否批准。
    pub approved: bool,
    /// 审批系统是否不可用。
    pub unavailable: bool,
}

/// 剧本相关错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlaybookError {
    /// 剧本定义非法。
    #[error("剧本非法: {0}")]
    Invalid(String),
    /// CEL 条件编译/求值失败。
    #[error("剧本条件求值失败: {0}")]
    Condition(String),
    /// 缺少必要的注入实现。
    #[error("缺少注入实现: {0}")]
    MissingDependency(String),
}

/// 已编译条件的缓存（`Program` 不是 `Clone`，因此单独持有）。
#[derive(Debug, Default)]
struct CompiledConditions {
    programs: BTreeMap<String, Program>,
}

/// 剧本执行器（确定性；所有外部副作用经 trait 注入）。
#[derive(Debug)]
pub struct PlaybookEngine {
    /// 单步最大尝试次数（默认 1：**默认不重试**，避免不可逆动作被重复执行）。
    pub step_max_attempts: u32,
    /// 空转模式：不真正调用执行器/通知点，只走轨迹（演练用）。
    pub dry_run: bool,
    /// 无 CEL 条件时的默认结论（默认 false：条件缺失即不执行）。
    pub default_condition: bool,
    action_executor: Option<Box<dyn ActionExecutor>>,
    notifier: Option<Box<dyn NotifySink>>,
    approval: Option<Box<dyn ApprovalGate>>,
    compiled: CompiledConditions,
}

/// 单步执行结果（内部用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StepExecution {
    Succeeded { attempts: u32, note: String },
    Skipped { attempts: u32, note: String },
    Failed { attempts: u32, error: String },
    Aborted { attempts: u32, reason: String },
}

mod impl_mock_action_executor;
mod impl_playbook_engine;
mod impl_trigger_input;
mod retry;
#[cfg(test)]
mod tests;
