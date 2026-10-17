//! 由 `parser.rs` 拆分：`ParseOutcome`/`Parser`/`ParserDefinition`/`ParserEngine` 的实现（纯搬移，逻辑不变）。
use super::*;

use crate::ids::{TenantId, TenantScoped};
use std::collections::BTreeMap;

impl ParserEngine {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Grok => "grok",
            Self::JsonPath => "jsonpath",
            Self::Jq => "jq",
            Self::Regex => "regex",
            Self::Syslog => "syslog",
            Self::Cef => "cef",
            Self::Leef => "leef",
            Self::Gelf => "gelf",
            Self::Csv => "csv",
            Self::Kv => "kv",
            Self::Cel => "cel",
            Self::Plugin => "plugin",
            Self::AiInferred => "ai-inferred",
        }
    }

    /// 全部引擎。
    #[must_use]
    pub const fn all() -> [Self; 13] {
        [
            Self::Grok,
            Self::JsonPath,
            Self::Jq,
            Self::Regex,
            Self::Syslog,
            Self::Cef,
            Self::Leef,
            Self::Gelf,
            Self::Csv,
            Self::Kv,
            Self::Cel,
            Self::Plugin,
            Self::AiInferred,
        ]
    }
}

impl ParserDefinition {
    /// 校验解析器定义（加载期）。
    ///
    /// # Errors
    /// 返回问题列表。
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errs = Vec::new();
        if self.key.trim().is_empty() {
            errs.push("key 不能为空".to_string());
        }
        if self.pattern.trim().is_empty() && self.engine != ParserEngine::Syslog {
            errs.push(format!("解析器 {} 缺少 pattern", self.key));
        }
        if matches!(self.engine, ParserEngine::Regex | ParserEngine::Grok) && !self.pattern.is_empty() {
            // Grok 语法在编译为正则后校验由 agf-ingest 完成；此处只校验纯正则引擎
            if self.engine == ParserEngine::Regex {
                if let Err(e) = regex::Regex::new(&self.pattern) {
                    errs.push(format!("解析器 {} 正则非法: {e}", self.key));
                }
            }
        }
        for (target, expr) in &self.derived {
            if expr.trim().is_empty() {
                errs.push(format!("解析器 {} 派生字段 {target} 表达式为空", self.key));
            }
        }
        if errs.is_empty() { Ok(()) } else { Err(errs) }
    }

    /// 是否需要样例（内置模板必须有真实/合成样例）。
    #[must_use]
    pub fn requires_sample(&self) -> bool {
        self.builtin
    }
}

impl TenantScoped for Parser {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl Parser {
    /// 成功率（0.0-1.0）。
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn success_rate(&self) -> f32 {
        let total = self.success_count + self.failure_count;
        if total == 0 {
            return 0.0;
        }
        self.success_count as f32 / total as f32
    }

    /// 是否需要人工关注（成功率低于阈值且样本足够）。
    #[must_use]
    pub fn needs_attention(&self, min_rate: f32, min_samples: u64) -> bool {
        let total = self.success_count + self.failure_count;
        total >= min_samples && self.success_rate() < min_rate
    }
}

impl ParseOutcome {
    /// 失败结果。
    #[must_use]
    pub fn miss(reason: impl Into<String>) -> Self {
        Self {
            matched: false,
            parser_key: None,
            fields: BTreeMap::new(),
            extra: BTreeMap::new(),
            derived_errors: Vec::new(),
            error: Some(reason.into()),
            matched_by: None,
            elapsed_micros: 0,
        }
    }

    /// 匹配结果。
    #[must_use]
    pub fn hit(parser_key: impl Into<String>, fields: BTreeMap<String, serde_json::Value>) -> Self {
        Self {
            matched: true,
            parser_key: Some(parser_key.into()),
            fields,
            extra: BTreeMap::new(),
            derived_errors: Vec::new(),
            error: None,
            matched_by: None,
            elapsed_micros: 0,
        }
    }

    /// 取某字段的字符串值。
    #[must_use]
    pub fn get_str(&self, path: &str) -> Option<&str> {
        self.fields.get(path).and_then(serde_json::Value::as_str)
    }
}
