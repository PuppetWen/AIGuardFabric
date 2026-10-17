//! 注册表对外类型：匹配趟次 `MatchMode`、注册表统计、非法模板记录与 `ParserRegistry` 本体。

use super::*;

/// 匹配趟次（决定 `matched_by` 取值，也是统计里的分项口径）。
///
/// 取值文本（`as_str()`，同时也是 serde 序列化取值）：
/// `explicit` / `protocol` / `protocol-relaxed` / `sample-score` / `ai-inferred`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatchMode {
    /// 显式 `parser_key` 命中（调用方指定，不受协议白名单约束）。
    Explicit,
    /// **严格趟**命中：模板声明的 `protocols` 包含当前协议（行为与修复前完全一致）。
    Protocol,
    /// **放宽趟**命中：严格趟零命中后忽略协议白名单命中（新协议缺模板声明时的兜底）。
    ProtocolRelaxed,
    /// 样本打分命中（本就不做协议过滤）。
    SampleScore,
    /// AI 推断兜底命中。
    AiInferred,
}

impl MatchMode {
    /// 文本形式（写进结果与统计的 `matched_by`）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::Protocol => "protocol",
            Self::ProtocolRelaxed => "protocol-relaxed",
            Self::SampleScore => "sample-score",
            Self::AiInferred => "ai-inferred",
        }
    }

    /// 是否为"放宽趟"命中（放宽协议白名单换来的命中）。
    #[must_use]
    pub const fn is_relaxed(&self) -> bool {
        matches!(self, Self::ProtocolRelaxed)
    }

    /// 全部趟次（统计初始化与展示用）。
    #[must_use]
    pub const fn all() -> [Self; 5] {
        [Self::Explicit, Self::Protocol, Self::ProtocolRelaxed, Self::SampleScore, Self::AiInferred]
    }
}

/// 注册表统计（看板与运维页直接展示）。
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RegistryStats {
    /// 从 YAML 目录加载成功的模板数。
    pub loaded: usize,
    /// 内置模板数。
    pub builtin: usize,
    /// 加载失败的模板数（校验/编译不过）。
    pub invalid: usize,
    /// AI 推断注册的模板数。
    pub ai_inferred: usize,
    /// 各模板命中次数。
    pub matched_counts: BTreeMap<String, u64>,
    /// **按匹配趟次分解**的命中数（键为 [`MatchMode::as_str`]）。
    pub matched_by_mode: BTreeMap<String, u64>,
    /// **放宽趟命中数**（= `matched_by_mode["protocol-relaxed"]`，单列出来便于看板直读与告警）。
    pub matched_relaxed: u64,
    /// 放宽趟命中**按模板**分解（key → 次数）：解释"命中率为什么变高"。
    pub relaxed_hits: BTreeMap<String, u64>,
    /// 未命中任何模板的报文数。
    pub unmatched: u64,
    /// 匹配总耗时（微秒，便于发现慢模板）。
    pub match_micros_total: u64,
}

impl RegistryStats {
    /// 某个趟次的命中数（缺失为 0）。
    #[must_use]
    pub fn mode_count(&self, mode: MatchMode) -> u64 {
        self.matched_by_mode.get(mode.as_str()).copied().unwrap_or(0)
    }

    /// 命中总数（严格趟 + 放宽趟 + 样本打分 + AI + 显式）。
    #[must_use]
    pub fn matched_total(&self) -> u64 {
        self.matched_by_mode.values().copied().sum()
    }
}

/// 加载失败的模板记录。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InvalidTemplate {
    /// 来源（文件路径或 `<builtin>`）。
    pub origin: String,
    /// 模板 key（可能取不到）。
    pub key: String,
    /// 失败原因。
    pub reason: String,
}

/// 解析器注册表。
#[derive(Debug, Clone)]
pub struct ParserRegistry {
    pub(super) entries: Vec<Parser>,
    pub(super) invalid: Vec<InvalidTemplate>,
    pub(super) stats: RegistryStats,
    /// 是否在匹配失败时尝试 AI 推断（默认关闭，需显式开启）。
    pub(super) ai_fallback: bool,
}
