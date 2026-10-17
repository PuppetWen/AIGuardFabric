//! 规则包加载与治理（§4.2：规则以 YAML 存放于 `<项目>/rules/`，与代码解耦，支持热更新/版本化/灰度）。
//!
//! ## 加载流程
//!
//! 1. **递归发现**：扫描 `<rules_dir>/<domain>/**.yaml|yml`（目录名即安全域）；
//! 2. **解析与校验**：反序列化为 [`RuleDefinition`] 并调用 `validate()`
//!    （含正则预编译，坏规则在加载期就暴露）；
//! 3. **去重与冲突**：同 `key` 出现两次视为冲突（显式报错，避免"改了一份没生效"）；
//! 4. **产出版本清单**：每条规则一个 `content_hash` + 聚合包指纹，用于灰度与回滚对比。
//!
//! 加载**不因单条规则错误而整体失败**：坏规则进入 `invalid` 列表，
//! 好规则照常生效——这是"平台降级但可用"原则在规则层的体现；CI 门禁则要求 `invalid` 必须为空。

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::path::Path;
pub(crate) use std::path::PathBuf;

pub(crate) use agf_core::enums::RiskDomain;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::rule::RuleDefinition;
pub(crate) use agf_core::rule::RulePackSummary;

pub(crate) use agf_core::secret::content_hash;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use tracing::debug;
pub(crate) use tracing::info;
pub(crate) use tracing::warn;

pub(crate) use crate::detector::CompiledDetection;

#[cfg(test)]
pub(crate) use agf_core::enums::PolicyAction;
#[cfg(test)]
pub(crate) use agf_core::enums::RuleKind;
#[cfg(test)]
pub(crate) use agf_core::enums::Severity;

#[cfg(test)]
pub(crate) use agf_core::rule::Detection;
#[cfg(test)]
pub(crate) use agf_core::rule::RuleSamples;
#[cfg(test)]
pub(crate) use agf_core::rule::RuleTarget;

#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 规则目录描述。
#[derive(Debug, Clone)]
pub struct RulesDir {
    /// 根目录。
    pub root: PathBuf,
}

/// 加载报告。
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct LoadReport {
    /// 成功加载的规则数。
    pub loaded: usize,
    /// 校验失败/解析失败的规则（键或文件路径 → 问题列表）。
    pub invalid: BTreeMap<String, Vec<String>>,
    /// 重复键冲突。
    pub duplicates: Vec<String>,
    /// 按安全域统计。
    pub by_domain: BTreeMap<String, usize>,
    /// 按严重等级统计。
    pub by_severity: BTreeMap<String, usize>,
    /// 含降级语义检测的规则键。
    pub degraded_semantic: Vec<String>,
    /// 缺少正负样本的规则键（CI 必拒）。
    pub missing_samples: Vec<String>,
    /// 扫描到的文件数。
    pub files_scanned: usize,
    /// 聚合包指纹（所有规则内容哈希排序后再哈希）。
    pub pack_fingerprint: String,
    /// 生成时间。
    pub generated_at: Option<Timestamp>,
}

/// 规则包（加载结果）。
#[derive(Debug, Clone)]
pub struct RulePack {
    /// 规则定义（按域分组保持稳定顺序）。
    pub rules: Vec<RuleDefinition>,
    /// 编译后的匹配器（与 `rules` 同序）。
    compiled: Vec<CompiledDetection>,
    /// 加载报告。
    pub report: LoadReport,
}

/// 规则包加载器。
#[derive(Debug, Clone, Default)]
pub struct RulePackLoader {
    /// 是否严格模式（严格模式下遇到非法规则立即失败；CI 用）。
    strict: bool,
}

mod impl_rules_dir;
#[cfg(test)]
mod tests;
