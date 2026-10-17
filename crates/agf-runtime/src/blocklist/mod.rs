//! 分级黑名单（§4.3 分级：命令级黑名单 / 工具白名单 / 域名出网管控）。
//!
//! # 与策略引擎的分工
//!
//! 黑名单是**平台级、不依赖租户配置**的第一道闸门（内置危险命令、高危外联域名、
//! 机密文件路径），其命中结果会：
//!
//! 1. 直接产出 [`RuleHit`]，被 [`crate::mcp_proxy::McpProxy`] 当作硬拦截依据；
//! 2. 作为变量 `hit` / `input.hit` 注入 Rego / CEL（见 [`crate::rego`]、[`crate::cel`]），
//!    使策略作者无需重写正则即可引用平台黑名单。
//!
//! 策略引擎是**租户可编排**的第二道闸门。二者顺序为「黑名单 → 策略」，互不替代：
//! 黑名单保证"最低防线在任何租户配置下都存在"。
//!
//! # 规则类型与匹配语义
//!
//! | [`RuleKind`] | 匹配对象 | 模式语义 |
//! |---|---|---|
//! | `Command` | [`Blocklist::extract_command`] 提取出的命令文本 | 子串（大小写不敏感）或 `re:` 前缀正则 |
//! | `Domain` | 目标域名 | 精确 / `*.example.com` 通配 / `re:` 正则 |
//! | `Path` | 目标路径 | 前缀（`path_matches_prefix`，反斜杠归一化）或 `re:` 正则 |
//! | `Tool` | 工具名 | 子串（大小写不敏感）或 `re:` 前缀正则 |
//! | `Hash` | 载荷中出现的 hex 摘要（MD5/SHA1/SHA256） | 大小写不敏感子串，或 `re:` 正则 |
//!
//! # 命中优先级与「允许覆盖拒绝」
//!
//! 1. 先求值 [`RuleAction::Allow`] 规则（**白名单**）：一旦命中，直接返回"放行"结论，
//!    **不再**求值任何 `Deny` 规则——即**白名单覆盖黑名单**；
//! 2. 再按 工具 → 域名 → 路径 → 哈希 → 命令 的顺序求值 `Deny` 规则；
//!    最先命中者胜出（**只报告首条命中**，避免一个载荷刷出十几条噪音）；
//! 3. 命令类最后求值，因为域名/路径/工具是更精确的"意图"信号，可给出更有解释力的原因。
//!
//! > ⚠️ 白名单覆盖是**双刃剑**：一条过宽的白名单（如 `re:.*`）会整体关闭内置黑名单。
//! > [`Blocklist::validate`] 会在热重载时对"覆盖内置拒绝规则的白名单"给出告警列表。

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::sync::LazyLock;

pub(crate) use agf_core::enums::RiskDomain;
pub(crate) use agf_core::enums::Severity;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::policy::PolicyContext;
pub(crate) use agf_core::policy::command_matches_deny;
pub(crate) use agf_core::policy::domain_matches;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use regex::Regex;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

#[allow(unused_imports)]
pub use impl_rule_kind::*;
#[allow(unused_imports)]
pub use make_hit::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests_2::*;

/// 规则类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleKind {
    /// 命令级黑名单（`rm -rf`、`curl | sh` …）。
    Command,
    /// 域名出网管控。
    Domain,
    /// 敏感文件路径。
    Path,
    /// 工具（能力）级规则。
    Tool,
    /// 载荷哈希（已知恶意样本）。
    Hash,
}

/// 规则动作。
///
/// **不是** [`agf_core::enums::PolicyAction`] 的子集：黑名单只做"拦/放/记"三态，
/// 限流/降级/审批由策略引擎与配额服务承担。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    /// 拦截。
    Deny,
    /// 放行（白名单；覆盖同载荷的 Deny 规则）。
    Allow,
    /// 放行但记录。
    Audit,
}

/// 黑名单规则。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleRule {
    /// 规则 id（稳定标识，审计与统计的键；同一黑名单内应唯一）。
    pub id: String,
    /// 类别。
    pub kind: RuleKind,
    /// 匹配模式（`re:` 前缀表示正则）。
    pub pattern: String,
    /// 动作。
    pub action: RuleAction,
    /// 命中原因（写入拦截提示与审计；应解释"为什么危险"）。
    pub reason: String,
    /// 归属风险域（控制台按域聚合）。
    pub domain: RiskDomain,
    /// 严重等级。
    pub severity: Severity,
}

/// 规则命中结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleHit {
    /// 命中规则 id。
    pub rule_id: String,
    /// 类别。
    pub kind: RuleKind,
    /// 实际参与匹配的文本（命令/域名/路径/工具名/哈希）。
    pub matched_text: String,
    /// 命中模式。
    pub pattern: String,
    /// 动作。
    pub action: RuleAction,
    /// 原因。
    pub reason: String,
    /// 风险域。
    pub domain: RiskDomain,
    /// 严重等级。
    pub severity: Severity,
}

/// 黑名单变更统计（控制台展示"最近是否被改过"）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlocklistStats {
    /// 当前生效规则数。
    pub rule_count: usize,
    /// 按类别统计的规则数。
    pub by_kind: BTreeMap<String, usize>,
    /// 热重载次数。
    pub reload_count: u64,
    /// 最近一次重载时间。
    pub last_reload_at: Option<Timestamp>,
    /// 累计命中次数（按规则 id）。
    pub hits: BTreeMap<String, u64>,
    /// 累计求值次数。
    pub evaluations: u64,
    /// 最近一次变更说明。
    pub last_change: String,
}

/// 编译后的规则（正则预编译，热路径零分配解析）。
#[derive(Debug, Clone)]
pub(crate) struct CompiledRule {
    rule: RuleRule,
    regex: Option<Regex>,
}

/// 分级黑名单。
///
/// 内部结构：一段预编译规则 + 统计数据。热重载（[`Blocklist::reload`]）在**不中断服务**的前提下
/// 整体替换规则集（编译失败即整体回滚，旧规则集继续生效）。
#[derive(Debug, Clone)]
pub struct Blocklist {
    rules: Vec<CompiledRule>,
    stats: BlocklistStats,
    allowlist: Vec<CompiledRule>,
}

/// 已知恶意样本哈希规则（惰性编译，避免每次构造都编译正则）。
static KNOWN_BAD_HASHES: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    vec![
        // EICAR 反病毒测试文件哈希（用于验证黑名单链路，非真实恶意样本）
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    ]
});

mod impl_blocklist;
mod impl_rule_kind;
mod make_hit;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_2;
