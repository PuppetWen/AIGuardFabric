//! 检测规则模型（§4.2 规则引擎）。
//!
//! 规则以 YAML 存放于 `<项目>/rules/<domain>/`，与代码解耦，支持热更新/版本化/灰度。
//! **每条规则必须带正负样本**（[`RuleSamples`]），CI 门禁会校验样本齐全且全部通过，
//! 这是"规则可信"的硬约束。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::enums::{RiskDomain, RuleKind, Severity};

use crate::ids::{Id, TenantId};

use crate::time::Timestamp;

#[allow(unused_imports)]
pub(crate) use default_semantic_threshold::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 检测条件（规则的核心判定部分）。
///
/// 采用"可序列化的小型 DSL"，避免引入通用脚本引擎带来的沙箱风险；
/// 复杂逻辑通过 [`Detection::All`] / [`Detection::Any`] / [`Detection::Not`] 组合表达。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Detection {
    /// 正则匹配（对 target 字段全文）。
    Regex {
        /// 正则表达式。
        pattern: String,
        /// 是否忽略大小写。
        #[serde(default = "default_true")]
        case_insensitive: bool,
        /// 需要命中的最小组数（默认 1）。
        #[serde(default = "default_one")]
        min_matches: usize,
    },
    /// 关键字匹配（任一命中即算）。
    Keyword {
        /// 关键字列表。
        any: Vec<String>,
    },
    /// 全部关键字都要出现。
    KeywordAll {
        /// 关键字列表。
        all: Vec<String>,
    },
    /// 熵检测（识别高熵字符串，如密钥/编码载荷）。
    Entropy {
        /// 最小长度。
        min_length: usize,
        /// 熵阈值（bits/char），典型 4.0 以上为可疑。
        min_entropy: f32,
    },
    /// 编码绕过检测：文本中同时出现"编码指令"与"解码后敏感词"。
    EncodingBypass {
        /// 触发词（如 `base64`、`解码`）。
        trigger: Vec<String>,
        /// 需要解码后命中的敏感词。
        decoded_contains: Vec<String>,
    },
    /// AST 结构匹配（用于命令注入/危险调用识别）。
    #[serde(rename = "ast")]
    Ast {
        /// 危险符号/函数名。
        dangerous_symbols: Vec<String>,
        /// 必须同时出现的伴随符号（可选）。
        #[serde(default)]
        context_symbols: Vec<String>,
    },
    /// YARA 规则内联（`rule` 为 yara-x 语法）。
    Yara {
        /// 规则名。
        rule_name: String,
        /// 规则体。
        source: String,
    },
    /// 语义相似（需要向量/模型支持；离线时由词表近似替代并标注降级）。
    Semantic {
        /// 语义意图描述（送模型判定）。
        intent: String,
        /// 离线降级时使用的关键词近似集合。
        #[serde(default)]
        fallback_keywords: Vec<String>,
        /// 相似度阈值。
        #[serde(default = "default_semantic_threshold")]
        threshold: f32,
    },
    /// 组合：全部满足。
    All {
        /// 子条件。
        of: Vec<Self>,
    },
    /// 组合：任一满足。
    Any {
        /// 子条件。
        of: Vec<Self>,
    },
    /// 取反。
    Not {
        /// 子条件。
        of: Box<Self>,
    },
    /// 阈值聚合：命中的子条件数达到 `min_hits`。
    Threshold {
        /// 子条件。
        of: Vec<Self>,
        /// 最少命中数。
        min_hits: usize,
    },
}

const fn default_true() -> bool {
    true
}

const fn default_one() -> usize {
    1
}

/// 规则的检测目标字段。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleTarget {
    /// 用户/Agent 提示词输入。
    Prompt,
    /// 模型输出。
    ModelOutput,
    /// 工具调用参数。
    ToolArguments,
    /// 工具返回结果。
    ToolResult,
    /// MCP 请求。
    McpRequest,
    /// MCP 响应。
    McpResponse,
    /// 日志/事件载荷。
    EventPayload,
    /// 知识库文档内容。
    Document,
    /// 配置内容（MCP 配置/环境变量）。
    Config,
    /// 代码/文本文件。
    FileContent,
    /// 工具描述与 schema（间接注入面）。
    ToolDefinition,
}

/// 规则样本（正/负样本，CI 强制）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleSamples {
    /// 正样本（必须命中）。
    #[serde(default)]
    pub positive: Vec<String>,
    /// 负样本（必须不命中）。
    #[serde(default)]
    pub negative: Vec<String>,
}

/// 规则定义（YAML 反序列化的主体）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDefinition {
    /// 稳定键（形如 `PA-INJ-001`，跨版本不变）。
    pub key: String,
    /// 名称。
    pub name: String,
    /// 描述。
    #[serde(default)]
    pub description: String,
    /// 所属安全域。
    pub domain: RiskDomain,
    /// 严重等级。
    pub severity: Severity,
    /// 规则类型（用于统计与 UI 分组）。
    pub kind: RuleKind,
    /// 检测目标。
    pub target: RuleTarget,
    /// 触发后的建议动作。
    pub action: crate::enums::PolicyAction,
    /// 是否启用。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 灰度比例（0-100，按资产 id 哈希取模；100 = 全量）。
    #[serde(default = "default_hundred")]
    pub rollout_percent: u8,
    /// 标签（MITRE / Agentic ATT&CK 技术编号、OWASP LLM Top10 等）。
    #[serde(default)]
    pub tags: Vec<String>,
    /// 引用来源（公开 PoC / 论文 / 厂商公告 URL），便于溯源。
    #[serde(default)]
    pub references: Vec<String>,
    /// 检测条件。
    pub detection: Detection,
    /// 正负样本。
    #[serde(default)]
    pub samples: RuleSamples,
    /// 修复建议模板。
    #[serde(default)]
    pub remediation: String,
    /// 作者。
    #[serde(default)]
    pub author: String,
    /// 版本（YAML 内声明，与 DB 版本号互补）。
    #[serde(default = "default_one_u32")]
    pub version: u32,
}

const fn default_hundred() -> u8 {
    100
}

const fn default_one_u32() -> u32 {
    1
}

/// 规则版本（DB 实体，支持热更新与回滚）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleVersion {
    /// 主键。
    pub id: Id,
    /// 租户（平台内置规则属于默认租户）。
    pub tenant_id: TenantId,
    /// 规则稳定键。
    pub rule_key: String,
    /// 版本号（单调递增）。
    pub version: u32,
    /// 规则定义快照。
    pub definition: RuleDefinition,
    /// 内容哈希。
    pub content_hash: String,
    /// 状态。
    pub state: RuleVersionState,
    /// 正样本通过数。
    pub positive_passed: u32,
    /// 负样本通过数。
    pub negative_passed: u32,
    /// 样本总数。
    pub sample_total: u32,
    /// 发布人。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_by: Option<Id>,
    /// 发布时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_at: Option<Timestamp>,
    /// 创建时间。
    pub created_at: Timestamp,
}

/// 规则版本状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleVersionState {
    /// 草稿。
    Draft,
    /// 灰度中。
    Canary,
    /// 已发布（生效）。
    Published,
    /// 已下线。
    Retired,
}

/// 单条样本的测试结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleResult {
    /// 样本内容。
    pub sample: String,
    /// 期望是否命中。
    pub expected_hit: bool,
    /// 实际是否命中。
    pub actual_hit: bool,
    /// 是否通过。
    pub passed: bool,
}

/// 规则包的加载汇总（`agf-scan` 启动时输出，便于排障与 CI 断言）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RulePackSummary {
    /// 按域统计的规则数。
    pub by_domain: BTreeMap<String, usize>,
    /// 按严重等级统计。
    pub by_severity: BTreeMap<String, usize>,
    /// 规则总数。
    pub total: usize,
    /// 校验失败的规则（key → 错误列表）。
    pub invalid: BTreeMap<String, Vec<String>>,
    /// 加载来源目录。
    pub sources: Vec<String>,
    /// 生成时间。
    pub generated_at: Option<Timestamp>,
}

/// 规则匹配结果（规则引擎输出）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    /// 规则稳定键。
    pub rule_key: String,
    /// 规则名。
    pub rule_name: String,
    /// 安全域。
    pub domain: RiskDomain,
    /// 严重等级。
    pub severity: Severity,
    /// 建议动作。
    pub action: crate::enums::PolicyAction,
    /// 置信度。
    pub confidence: f32,
    /// 命中片段（已脱敏，截断）。
    pub matched_excerpt: String,
    /// 命中位置（字符偏移）。
    #[serde(default)]
    pub spans: Vec<(usize, usize)>,
    /// 标签。
    #[serde(default)]
    pub tags: Vec<String>,
    /// 修复建议。
    #[serde(default)]
    pub remediation: String,
}

mod default_semantic_threshold;
#[cfg(test)]
mod tests;
