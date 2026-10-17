//! # agf-scan — 风险引擎与 AI 红队
//!
//! 覆盖 §4.2 风险治理与 AI 红队。
//!
//! ## 模块与职责
//!
//! | 模块 | 职责 | 离线可用 |
//! |---|---|---|
//! | [`detector`] | 检测原语：把 YAML 规则编译成匹配器并执行（正则/关键字/熵/编码绕过/AST/YARA/语义/组合） | ✅ 纯函数 |
//! | [`loader`] | 规则包加载：从 `<项目>/rules/` 递归读 YAML、校验正负样本、灰度、版本化 | ✅ |
//! | [`samples`] | 正负样本自动回归（CI 门禁的判定核心） | ✅ 纯函数 |
//! | [`domains`] | 五大安全域的专项检测器（提示词攻击/凭证泄露/RAG 投毒/工具滥用/模型与数据） | ✅ 纯函数 |
//! | [`redteam`] | 红队用例库加载、战役编排、成功率统计、报告生成 | 需要模型（离线走 Mock） |
//! | [`engine`] | 扫描引擎：对目标（提示词/日志/资产画像）批量执行规则并产出 finding | 需要存储 |
//!
//! ## 与 AI 网关的关系
//!
//! [`engine::ScanEngine`] 通过 `agf-aigw` 的模型能力做**二次研判**，
//! 在 `AGF_MOCK_MODE=1` 或无 API Key 时自动使用 Mock 模型（离线可用），
//! 因此本地离线环境可以完整跑通"规则命中 → 模型研判 → finding"链路。
//!
//! ## 降级行为
//!
//! | 依赖 | 未配置时 |
//! |---|---|
//! | 大模型（研判/报告） | 走 Mock 模型；`LlmJudgement.mocked = true`，控制台显著标注 |
//! | 语义规则 | 退化为 `fallback_keywords` 关键词近似，`MatchResult.degraded = true` |
//! | YARA | 规则编译失败时该条规则不命中并记录警告，不影响其它规则 |
//! | 红队执行环境（真实 Agent/MCP） | 使用本地模拟实例（见 `redteam::simulator`） |

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![cfg_attr(test, allow(clippy::panic))]

pub mod detector;
pub mod domains;
pub mod engine;
pub mod loader;
pub mod redteam;
pub mod samples;

pub use detector::{CompiledDetection, MatchResult, MatchSpan, RuleHit, evaluate_rule, rule_matches};
pub use domains::{DomainDetector, DomainReport, DomainVerdict};
pub use engine::{ScanEngine, ScanRequest, ScanResult, ScanTarget};
pub use loader::{LoadReport, RulePack, RulePackLoader, RulesDir};
pub use redteam::{
    AgentHttpTarget, CampaignRunner, CaseLibrary, CaseLibraryStats, RedteamOutcome, RedteamSimulator, TargetUnderTest,
};
pub use samples::{SampleRegression, SampleRunReport};

/// 平台版本。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// §11 阶段一验收要求：提示词注入 / 凭证泄露 / RAG 投毒 各 ≥10 条规则。
pub const MIN_RULES_PER_CORE_DOMAIN: usize = 10;
