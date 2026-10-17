//! 策略引擎（§4.3 策略引擎：Rego/CEL DSL，动作 `allow/deny/audit/quota/redact`）。
//!
//! # 评估与组合规则（**契约，测试逐条覆盖**）
//!
//! 1. **排序**：启用策略按 `priority` **升序**；`priority` 相同时按 `policy.id` 升序
//!    （保证"同优先级"下结果**确定**、与装载顺序无关，避免同一策略集在不同节点上给出不同结论）。
//! 2. **适用性**：`Policy::applies_to(agent_id, department)` 为真才参与评估；
//!    不适用（含 `enabled=false`、作用域不符）的策略被完全跳过。
//! 3. **命中**：
//!    - `Structured`：`StructuredCondition` 中**声明过的条件全部命中**（AND 语义）才算命中；
//!      未声明（空）的条件不参与判定。因此**条件全空的策略是"作用域内全量命中"**——这既符合
//!      "空条件集在逻辑上恒真"的常规策略语义，也是"我就是要拦这个作用域的全部流量"的自然写法。
//!      ⚠️ 这是把双刃剑：一条条件全空、`action=deny`、`priority` 很小的策略会拦下全部流量，
//!      因此下发前请用 `dry_run=true` 试跑（见第 6 条），并在控制台查看"策略命中量"。
//!    - `Rego` / `CEL`：见 [`crate::rego`] / [`crate::cel`] 的契约（规则给出 `action` 或非空 `reason`）；
//!      黑名单命中可通过 `input.hit` / `hit` 变量引用。
//!    - 上下文中**缺少**某条件所需的字段（如策略要求匹配 `domain` 但请求没有域名）⇒
//!      该条件不成立 ⇒ 策略不命中（不会因为"没数据"而误拦）。
//! 4. **胜出**：按 (1) 的顺序取**第一条**命中策略；`Deny` / `Isolate` **短路**——
//!    立即定案，不再评估后续策略。
//! 5. **无命中**：默认 `Allow`，原因固定为 [`NO_POLICY_MATCHED_REASON`]（`无策略命中`）。
//! 6. **dry-run**：`dry_run=true` 的策略照常产出决策（含动作与原因），但
//!    [`agf_core::policy::PolicyDecision::is_blocking`] 为 `false`——只记录不拦截。
//!    若一条 dry-run 的 `Deny` 命中，评估**就此打住**（不会继续找下一条真正拦截的策略）：
//!    dry-run 的语义是"如果启用会怎样"，继续评估会让原因与 `policy_id` 指向别的策略，反而误导排障。
//! 7. **签名**：`SignatureMode::Enforce`（生产默认）下签名缺失/非法的策略**不装载**；
//!    `SignatureMode::Warn`（开发）下装载但在 [`crate::guard::SelfCheck`] 记 FAIL。
//! 8. **后端错误**：见 [`EvalErrorMode`]（默认 fail-closed）。

pub(crate) use std::time::Instant;

pub(crate) use agf_core::enums::InterceptPoint;
pub(crate) use agf_core::enums::PolicyAction;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::policy::Policy;
pub(crate) use agf_core::policy::PolicyContext;
pub(crate) use agf_core::policy::PolicyDecision;
pub(crate) use agf_core::policy::PolicyLanguage;
pub(crate) use agf_core::policy::StructuredCondition;
pub(crate) use agf_core::policy::command_matches_deny;
pub(crate) use agf_core::policy::domain_matches;
pub(crate) use agf_core::policy::path_matches_prefix;

pub(crate) use tracing::debug;
pub(crate) use tracing::warn;

pub(crate) use crate::cel::CelBackend;

pub(crate) use crate::rego::RegoBackend;

pub(crate) use crate::signature::PolicySignatureState;
pub(crate) use crate::signature::PolicySigner;

#[allow(unused_imports)]
pub use pattern_matches::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests_2::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests_3::*;

/// 策略签名校验模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignatureMode {
    /// 强制校验（**生产默认**）：签名缺失/非法 ⇒ 拒绝装载该策略。
    #[default]
    Enforce,
    /// 告警模式（开发/灰度）：签名缺失/非法 ⇒ 装载但记警告，自检记 FAIL。
    Warn,
    /// 跳过校验（**仅限离线演示**；自检记 FAIL）。
    Disabled,
}

/// 后端求值失败时的策略（Rego/CEL 运行时错误）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EvalErrorMode {
    /// 失败即**拒绝**（**默认**）：策略引擎不可判定时，宁可少服务不可放过。
    #[default]
    FailClosed,
    /// 失败即放行并记录（用于灰度期"只看不拦"）。
    FailOpen,
}

/// 黑名单命中如何参与策略判定。
///
/// ⚠️ 除 [`Self::Off`] 外，**黑名单的 `Deny` 命中都不会在降级方向被"洗白"**：
/// 当策略结论为 `Allow`/`Audit` 而黑名单为 `Deny` 时，引擎强制升级为 `Deny`
/// （见 [`PolicyEngine::evaluate`] 的"黑名单否决权"）。否则一条过宽的白名单策略
/// 就能整体绕过平台级最低防线。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HitSource {
    /// 只由策略决定**原因与动作强度**，黑名单命中仍保留 `Deny` 否决权（**默认，生产建议**）。
    ///
    /// 即：策略命中 ⇒ 用策略的动作/原因；策略未命中但黑名单命中 ⇒ 用黑名单原因拒绝。
    #[default]
    PolicyFirst,
    /// **兜底拒绝**：语义同 [`Self::PolicyFirst`]，但把"黑名单命中即拒绝"写成显式配置意图
    /// （便于控制台展示"已启用黑名单兜底拦截"）。
    FallbackDeny,
    /// **额外命中条件**：仅当策略本身也命中时，把黑名单原因追加到决策原因里。
    /// 同样保留 `Deny` 否决权。
    Annotate,
    /// **完全不参与判定**（黑名单命中既不影响动作也不影响原因）。
    ///
    /// ⚠️ 这等于**拆掉平台级最低防线**，只允许用于排障/对照实验：
    /// [`crate::guard::SelfCheck`] 会记 **FAIL** 并在控制台标红，生产环境禁止使用。
    Off,
}

/// 单条策略的命中详情（审计与排障用）。
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyMatch {
    /// 命中的策略（`None` = 无策略命中）。
    pub policy_id: Option<Id>,
    /// 策略名。
    pub policy_name: Option<String>,
    /// 后端给出的原因（`None` = 后端未给出，使用策略描述）。
    pub backend_reason: Option<String>,
    /// 后端给出的动作（`None` = 使用策略行配置）。
    pub backend_action: Option<PolicyAction>,
    /// 后端给出的脱敏要求。
    pub backend_redact: bool,
    /// 黑名单是否命中。
    pub blocklist_hit: bool,
    /// 评估过的策略条数（性能观测）。
    pub evaluated: usize,
}

/// 策略引擎。
///
/// 与 [`agf_storage::PolicyRepo`] 的关系：引擎只负责"装载 + 求值"，
/// 数据库读写由调用方（`agf-api` / [`crate::engine::RuntimeEngine`]）完成，
/// 因此引擎可以在**完全没有数据库**的离线环境下完整工作。
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    /// 已装载策略（按 priority 升序保持）。
    policies: Vec<Policy>,
    /// 签名器（`None` = 未配置密钥；此时 `Enforce` 模式下所有策略都会被拒绝装载）。
    signer: Option<PolicySigner>,
    /// 签名校验模式。
    signature_mode: SignatureMode,
    /// 后端错误处理模式。
    eval_error_mode: EvalErrorMode,
    /// 黑名单命中的参与方式。
    hit_source: HitSource,
    /// 装载期被拒绝的策略及原因（控制台"策略装载失败"面板）。
    rejected: Vec<(String, String)>,
    /// 装载期签名告警（`Warn` 模式下收集）。
    signature_warnings: Vec<String>,
}

/// 结构化求值的中间形态（与 Rego/CEL 结论统一）。
struct StructuredOutcome {
    hit: bool,
    action: Option<PolicyAction>,
    reason: Option<String>,
    redact: bool,
}

mod impl_policy_engine;
mod impl_signature_mode;
mod pattern_matches;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_2;
#[cfg(test)]
mod tests_3;
