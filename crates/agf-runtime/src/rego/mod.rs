//! Rego 策略后端（`regorus`，§4.3 策略引擎）。
//!
//! # 策略契约（**对外发布，作者与平台共同遵守**）
//!
//! 策略源码必须满足：
//!
//! 1. **包名固定为 `agf`**：`package agf`
//! 2. 必须定义以下规则（三者都可缺省，缺省按"未定义"处理）：
//!
//! | 规则 | 路径 | 类型 | 语义 | 缺省行为 |
//! |---|---|---|---|---|
//! | `action` | `data.agf.action` | string | 命中时采取的 [`PolicyAction`]（`allow`/`deny`/`audit`/`quota`/`redact`/`throttle`/`degrade`/`circuit-break`/`isolate`/`approval`） | 取策略行的 `action` 字段 |
//! | `reason` | `data.agf.reason` | string | 命中原因（写入拦截提示与审计） | 取 [`agf_core::policy::Policy::description`] |
//! | `redact` | `data.agf.redact` | bool | 是否要求脱敏（与 `action` 取或） | `false` |
//!
//! 3. **「命中」的判定**：`data.agf.action` 求值成功且不为 `undefined`，或
//!    `data.agf.reason` 为**非空字符串**。二者皆不成立即视为该策略不命中。
//!    （因此"只审计不拦截"的策略可以只写 `reason`。）
//! 4. 规则返回 `undefined`（Rego 中规则体全部为假）等价于"未定义"，**不是错误**。
//!
//! ## 输入 schema（`input`）
//!
//! 输入即 [`PolicyContext`] 的 JSON 序列化（`serde_json::to_value`），字段与
//! `PolicyContext` 一一对应；**同时**在 `input` 下额外注入一个便捷子对象 `input.hit`，
//! 值为 [`crate::blocklist::Blocklist::evaluate`] 的黑名单命中结果（无命中时为 `null`），
//! 使 Rego 作者无需自己写正则即可引用平台黑名单：
//!
//! ```rego
//! package agf
//!
//! default action := "allow"
//!
//! # 命中平台内置黑名单即阻断，并采用黑名单给出的原因
//! action := "deny" if {
//!     input.hit != null
//! }
//!
//! reason := sprintf("命中黑名单规则 %v：%v", [input.hit.rule_id, input.hit.reason]) if {
//!     input.hit != null
//! }
//!
//! redact := true if {
//!     input.data_class == "confidential"
//! }
//! ```
//!
//! ## 编译错误
//!
//! [`RegoBackend::compile`] 在**装载期**执行（[`crate::policy::PolicyEngine::from_policies`] 会
//! 对全部 Rego 策略调用 [`crate::policy::PolicyEngine::validate_source`]），
//! 编译失败返回 [`DomainError::Parse`]，错误信息包含策略名与 `regorus` 给出的源码行，
//! 保证坏策略永远不会进入拦截热路径。
//!
//! ## 线程安全
//!
//! `regorus::Engine` 为 `Clone` 且求值需要 `&mut self`，故每次求值克隆一份引擎
//! （模块 AST 以 `Rc` 共享，克隆开销为浅拷贝），使 [`RegoBackend`] 可安全共享于 `Arc` 中。

pub(crate) use agf_core::enums::PolicyAction;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::policy::Policy;
pub(crate) use agf_core::policy::PolicyContext;

pub(crate) use regorus::Engine;
pub(crate) use regorus::Value;

#[allow(unused_imports)]
pub(crate) use impl_rego_outcome::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// Rego 策略包名（契约）。
pub const PACKAGE: &str = "agf";

/// `action` 规则全路径。
pub const RULE_ACTION: &str = "data.agf.action";

/// `reason` 规则全路径。
pub const RULE_REASON: &str = "data.agf.reason";

/// `redact` 规则全路径。
pub const RULE_REDACT: &str = "data.agf.redact";

/// 编译好的 Rego 策略。
#[derive(Debug, Clone)]
pub struct RegoBackend {
    /// 策略名（错误信息与审计用）。
    policy_name: String,
    /// 已编译引擎（含策略 AST 与 data 文档）。
    engine: Engine,
    /// 策略里是否定义了 `action` 规则（**由 AST 判定**，见 [`probe_rules`]）。
    has_action: bool,
    /// 策略里是否定义了 `reason` 规则。
    has_reason: bool,
    /// 策略里是否定义了 `redact` 规则。
    has_redact: bool,
}

/// Rego 求值结论。
#[derive(Debug, Clone, PartialEq)]
pub struct RegoOutcome {
    /// 是否命中该策略。
    pub hit: bool,
    /// `action` 规则给出的动作（`None` = 未定义，调用方回退到策略行配置）。
    pub action: Option<PolicyAction>,
    /// `reason` 规则给出的原因。
    pub reason: Option<String>,
    /// `redact` 规则给出的脱敏要求。
    pub redact: bool,
}

mod impl_rego_outcome;
#[cfg(test)]
mod tests;
