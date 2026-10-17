//! 检测原语：把 [`Detection`] 编译成可复用的匹配器，并对文本执行匹配。
//!
//! ## 设计要点
//!
//! - **编译一次、匹配多次**：正则/关键字在 [`CompiledDetection`] 构造时预编译，
//!   热路径上不再做解析（规则热更新时整体重建）；
//! - **纯函数**：`match_text` 不依赖任何 I/O，规则正确性可以完全离线验证；
//! - **可解释**：每个命中都带 `matched_excerpt`（截断 + 脱敏）与字符区间 `spans`，
//!   供控制台高亮与证据链使用；
//! - **降级明确**：`Semantic` 在离线时退化为 `fallback_keywords`（并标记降级），
//!   `Yara` 需要 `yara-x` 编译，编译失败时记录警告而不是让整包加载失败。

pub(crate) use agf_core::enums::Severity;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::rule::Detection;
pub(crate) use agf_core::rule::RuleDefinition;

pub(crate) use agf_core::secret::content_hash;
pub(crate) use agf_core::secret::mask_default;

pub(crate) use regex::Regex;

pub(crate) use tracing::warn;

#[cfg(test)]
pub(crate) use agf_core::enums::PolicyAction;
#[cfg(test)]
pub(crate) use agf_core::enums::RiskDomain;
#[cfg(test)]
pub(crate) use agf_core::enums::RuleKind;

#[cfg(test)]
pub(crate) use agf_core::rule::RuleSamples;
#[cfg(test)]
pub(crate) use agf_core::rule::RuleTarget;

#[allow(unused_imports)]
pub use extract_encoded_tokens::*;
#[allow(unused_imports)]
pub use impl_match_result::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 一个规则的编译结果。
#[derive(Debug, Clone)]
pub struct CompiledDetection {
    /// 编译后的匹配器。
    node: CompiledNode,
    /// 语义检测是否已降级为关键词近似（控制台需要提示）。
    degraded_semantic: bool,
}

#[derive(Debug, Clone)]
pub(crate) enum CompiledNode {
    Regex { re: Regex, min_matches: usize },
    Keyword { any: Vec<String> },
    KeywordAll { all: Vec<String> },
    Entropy { min_length: usize, min_entropy: f32 },
    EncodingBypass { trigger: Vec<String>, decoded_contains: Vec<String> },
    Ast { dangerous: Vec<String>, context: Vec<String> },
    Yara { rule_name: String, source: String },
    Semantic { intent: String, fallback_keywords: Vec<String>, threshold: f32 },
    All(Vec<Self>),
    Any(Vec<Self>),
    Not(Box<Self>),
    Threshold { of: Vec<Self>, min_hits: usize },
}

/// 匹配片段（用于证据与高亮）。
#[derive(Debug, Clone, PartialEq)]
pub struct MatchSpan {
    /// 起始字符偏移。
    pub start: usize,
    /// 结束字符偏移。
    pub end: usize,
    /// 命中文本（已截断）。
    pub excerpt: String,
}

/// 单次匹配结果。
#[derive(Debug, Clone, PartialEq)]
pub struct MatchResult {
    /// 是否命中。
    pub hit: bool,
    /// 命中的片段。
    pub spans: Vec<MatchSpan>,
    /// 说明（未命中时为原因，命中时为摘要）。
    pub note: String,
    /// 该规则是否以降级方式判定（如语义 → 关键词）。
    pub degraded: bool,
}

/// 命中摘要中单个片段的最大字符数（防止超长载荷把日志撑爆）。
pub const MAX_EXCERPT_CHARS: usize = 240;

/// 规则匹配的最终结果（含规则元数据，供 finding 生成）。
#[derive(Debug, Clone, PartialEq)]
pub struct RuleHit {
    /// 规则稳定键。
    pub rule_key: String,
    /// 规则名。
    pub rule_name: String,
    /// 严重等级。
    pub severity: Severity,
    /// 安全域。
    pub domain: agf_core::enums::RiskDomain,
    /// 建议动作。
    pub action: agf_core::enums::PolicyAction,
    /// 置信度（规则命中基础置信度 × 命中强度）。
    pub confidence: f32,
    /// 命中片段。
    pub spans: Vec<MatchSpan>,
    /// 说明。
    pub note: String,
    /// 标签。
    pub tags: Vec<String>,
    /// 修复建议。
    pub remediation: String,
    /// 是否降级判定。
    pub degraded: bool,
}

/// 规则的默认基础置信度（按类型）。
#[must_use]
pub const fn base_confidence(kind: agf_core::enums::RuleKind) -> f32 {
    use agf_core::enums::RuleKind as K;
    match kind {
        K::Regex => 0.80,
        K::Keyword => 0.65,

        K::Semantic => 0.60,
        K::Ast => 0.70,
        K::Yara => 0.85,
        K::Entropy => 0.55,
        K::Composite => 0.75,
    }
}

mod extract_encoded_tokens;
mod impl_match_result;
#[cfg(test)]
mod tests;
