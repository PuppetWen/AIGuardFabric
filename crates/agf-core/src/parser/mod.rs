//! 日志解析框架模型（§4.5 解析：内置模板 + Grok/JSONPath/JQ + 自定义插件 + AI 推断）。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::enums::{IngestProtocol, Severity};

use crate::ids::{Id, TenantId};

use crate::time::Timestamp;

#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 解析引擎类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParserEngine {
    /// Grok（基于正则的命名捕获，兼容 Logstash 语法子集）。
    Grok,
    /// JSONPath（结构化 JSON 提取）。
    JsonPath,
    /// JQ（复杂 JSON 变换）。
    Jq,
    /// 正则 + 命名组。
    Regex,
    /// Syslog RFC3164 / RFC5424 头解析。
    Syslog,
    /// CEF（Common Event Format）。
    Cef,
    /// LEEF（Log Event Extended Format）。
    Leef,
    /// GELF（Graylog Extended Log Format）。
    Gelf,
    /// CSV / TSV 分列。
    Csv,
    /// KV 键值对。
    Kv,
    /// CEL 表达式（计算派生字段）。
    Cel,
    /// 自定义 Rust 插件（动态库；企业定制）。
    Plugin,
    /// AI 推断（LLM 生成解析器，需人工确认后固化）。
    AiInferred,
}

/// 字段映射（把解析出的字段名映射到 AGF-ECS 路径）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FieldMapping {
    /// 源字段名 → ECS 路径（如 `src_ip` → `network.source_ip`）。
    #[serde(default)]
    pub map: BTreeMap<String, String>,
    /// 时间字段（用于填充 `event.time`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_field: Option<String>,
    /// 时间格式（strftime 风格）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_format: Option<String>,
    /// 严重等级字段。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity_field: Option<String>,
    /// 严重等级取值映射（厂商值 → 平台等级）。
    #[serde(default)]
    pub severity_map: BTreeMap<String, Severity>,
    /// 事件类别取值映射。
    #[serde(default)]
    pub category_map: BTreeMap<String, String>,
    /// 动作字段。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_field: Option<String>,
    /// 默认值（源字段缺失时填充）。
    #[serde(default)]
    pub defaults: BTreeMap<String, serde_json::Value>,
}

/// 解析器定义（YAML 存储，可版本化）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParserDefinition {
    /// 稳定键（形如 `qingteng-hive-syslog`）。
    pub key: String,
    /// 名称。
    pub name: String,
    /// 厂商。
    #[serde(default)]
    pub vendor: String,
    /// 产品。
    #[serde(default)]
    pub product: String,
    /// 适用协议。
    #[serde(default)]
    pub protocols: Vec<IngestProtocol>,
    /// 引擎。
    pub engine: ParserEngine,
    /// 主模式（Grok 表达式 / JSONPath / 正则 / JQ 程序）。
    #[serde(default)]
    pub pattern: String,
    /// 辅助模式列表（多段解析，按顺序尝试，首个命中即用）。
    #[serde(default)]
    pub fallback_patterns: Vec<String>,
    /// 字段映射。
    #[serde(default)]
    pub mapping: FieldMapping,
    /// CEL 派生字段表达式（键 = 目标 ECS 路径）。
    #[serde(default)]
    pub derived: BTreeMap<String, String>,
    /// 必须存在的字段（缺失则该模板不匹配，用于消歧）。
    #[serde(default)]
    pub required_fields: Vec<String>,
    /// 版本。
    #[serde(default = "default_version")]
    pub version: u32,
    /// 是否内置（内置模板不可删除）。
    #[serde(default)]
    pub builtin: bool,
    /// 是否由 AI 推断生成（需人工确认）。
    #[serde(default)]
    pub ai_inferred: bool,
    /// 描述。
    #[serde(default)]
    pub description: String,
    /// 样例文件（`tests/fixtures/` 相对路径）。
    #[serde(default)]
    pub sample_fixture: String,
}

const fn default_version() -> u32 {
    1
}

/// 解析器实体（DB）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parser {
    /// 主键。
    pub id: Id,
    /// 租户（内置解析器属默认租户）。
    pub tenant_id: TenantId,
    /// 定义。
    pub definition: ParserDefinition,
    /// 是否启用。
    pub enabled: bool,
    /// 优先级（数值小者先匹配）。
    pub priority: u32,
    /// 内容哈希。
    pub content_hash: String,
    /// 统计：成功解析次数。
    #[serde(default)]
    pub success_count: u64,
    /// 统计：失败次数。
    #[serde(default)]
    pub failure_count: u64,
    /// 最近使用时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<Timestamp>,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 更新时间。
    pub updated_at: Timestamp,
}

/// 解析结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseOutcome {
    /// 是否匹配成功。
    pub matched: bool,
    /// 使用的解析器键。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parser_key: Option<String>,
    /// 提取出的字段（ECS 路径 → 值）。
    #[serde(default)]
    pub fields: BTreeMap<String, serde_json::Value>,
    /// 未映射的剩余字段。
    #[serde(default)]
    pub extra: BTreeMap<String, serde_json::Value>,
    /// 派生字段计算失败项（不影响主流程，但记录以便修规则）。
    #[serde(default)]
    pub derived_errors: Vec<String>,
    /// 失败原因。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// **命中趟次**（`explicit` / `protocol` / `protocol-relaxed` / `sample-score` / `ai-inferred`）。
    ///
    /// 由解析器注册表在**命中时**逐条写入（取值文本 = `agf_ingest::registry::MatchMode::as_str`），
    /// 未命中或缺省调用方不写时为 `None`——`#[serde(default)]` + 不序列化 `None`
    /// 保证老调用方与老 JSON 双向兼容。
    /// 存在的理由：只暴露 `parser_key` 时"命中了，但凭什么命中"不可观测
    /// （严格趟 / 放宽趟 / 样本打分 / AI 兜底必须能区分）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_by: Option<String>,
    /// 耗时（微秒）。
    pub elapsed_micros: u64,
}

/// AI 推断解析器的请求（无模板时）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiParserRequest {
    /// 样例原始日志（若干行）。
    pub samples: Vec<String>,
    /// 已知厂商（可选提示）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_hint: Option<String>,
    /// 已知协议。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<IngestProtocol>,
    /// 期望输出的 ECS 路径列表（引导模型）。
    #[serde(default)]
    pub target_paths: Vec<String>,
}

/// AI 推断解析器的结果（需人工确认后才固化）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiParserSuggestion {
    /// 推断出的解析器定义。
    pub definition: ParserDefinition,
    /// 置信度。
    pub confidence: f32,
    /// 模型说明。
    pub rationale: String,
    /// 使用的模型。
    pub model: String,
    /// 是否 Mock。
    pub mocked: bool,
    /// 生成时间。
    pub generated_at: Timestamp,
}

mod impl_parser_engine;
#[cfg(test)]
mod tests;
