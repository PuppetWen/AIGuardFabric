//! 由 `rule.rs` 拆分：`default_semantic_threshold`/`impl_RuleTarget` 等 11 项（纯搬移，逻辑不变）。
use super::*;

use crate::enums::RiskDomain;
use crate::ids::{Id, TenantId, TenantScoped};
use std::fmt;

pub(crate) fn default_semantic_threshold() -> f32 {
    0.75
}

impl RuleTarget {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Prompt => "prompt",
            Self::ModelOutput => "model-output",
            Self::ToolArguments => "tool-arguments",
            Self::ToolResult => "tool-result",
            Self::McpRequest => "mcp-request",
            Self::McpResponse => "mcp-response",
            Self::EventPayload => "event-payload",
            Self::Document => "document",
            Self::Config => "config",
            Self::FileContent => "file-content",
            Self::ToolDefinition => "tool-definition",
        }
    }

    /// 全部目标。
    #[must_use]
    pub const fn all() -> [Self; 11] {
        [
            Self::Prompt,
            Self::ModelOutput,
            Self::ToolArguments,
            Self::ToolResult,
            Self::McpRequest,
            Self::McpResponse,
            Self::EventPayload,
            Self::Document,
            Self::Config,
            Self::FileContent,
            Self::ToolDefinition,
        ]
    }
}

impl RuleSamples {
    /// 样本是否齐全（至少 1 正 1 负）。
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.positive.is_empty() && !self.negative.is_empty()
    }

    /// 样本总数。
    #[must_use]
    pub fn total(&self) -> usize {
        self.positive.len() + self.negative.len()
    }
}

impl RuleDefinition {
    /// 规则内容哈希（用于变更检测与灰度比对）。
    #[must_use]
    pub fn content_hash(&self) -> String {
        let canonical = serde_json::json!({
            "key": self.key,
            "name": self.name,
            "domain": self.domain.as_str(),
            "severity": self.severity.as_str(),
            "kind": self.kind.as_str(),
            "target": self.target.as_str(),
            "action": self.action.as_str(),
            "detection": self.detection,
        });
        crate::secret::content_hash(&serde_json::to_string(&canonical).unwrap_or_default())
    }

    /// 校验规则自身的完整性（加载期调用）。
    ///
    /// # Errors
    /// 返回全部校验失败的说明（聚合，便于一次性修完）。
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errs = Vec::new();
        if self.key.trim().is_empty() {
            errs.push("key 不能为空".to_string());
        }
        if self.name.trim().is_empty() {
            errs.push("name 不能为空".to_string());
        }
        if !self.samples.is_complete() {
            errs.push(format!("规则 {} 缺少正负样本（须至少 1 正 1 负）", self.key));
        }
        if self.rollout_percent > 100 {
            errs.push(format!("规则 {} rollout_percent 必须在 0-100", self.key));
        }
        // 正则预编译，避免运行时才发现写错
        collect_regexes(&self.detection, &mut |pattern| {
            if let Err(e) = regex::Regex::new(pattern) {
                errs.push(format!("规则 {} 正则非法: {pattern} ({e})", self.key));
            }
        });
        if errs.is_empty() { Ok(()) } else { Err(errs) }
    }

    /// 该规则是否对指定资产生效（灰度判定）。
    ///
    /// 灰度用确定性哈希，保证同一资产在灰度期内行为稳定（不会忽左忽右）。
    #[must_use]
    pub fn applies_to_asset(&self, asset_id: &Id) -> bool {
        if !self.enabled {
            return false;
        }
        if self.rollout_percent >= 100 {
            return true;
        }
        if self.rollout_percent == 0 {
            return false;
        }
        let h = crate::secret::content_hash(&asset_id.to_string());
        let bucket = u8::from_str_radix(&h[..2], 16).unwrap_or(0);
        bucket % 100 < self.rollout_percent
    }
}

/// 递归收集 detection 中的所有正则模式。
pub(crate) fn collect_regexes(det: &Detection, f: &mut impl FnMut(&str)) {
    match det {
        Detection::Regex { pattern, .. } => f(pattern),
        Detection::All { of } | Detection::Any { of } | Detection::Threshold { of, .. } => {
            for d in of {
                collect_regexes(d, f);
            }
        }
        Detection::Not { of } => collect_regexes(of, f),
        _ => {}
    }
}

impl TenantScoped for RuleVersion {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl RuleVersion {
    /// 样本测试是否全绿（发布前置条件）。
    #[must_use]
    pub fn samples_green(&self) -> bool {
        self.sample_total > 0 && self.positive_passed + self.negative_passed == self.sample_total
    }
}

impl RuleVersionState {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Canary => "canary",
            Self::Published => "published",
            Self::Retired => "retired",
        }
    }
}

impl SampleResult {
    /// 构造并自动判定。
    #[must_use]
    pub fn new(sample: impl Into<String>, expected_hit: bool, actual_hit: bool) -> Self {
        Self { sample: sample.into(), expected_hit, actual_hit, passed: expected_hit == actual_hit }
    }
}

impl RulePackSummary {
    /// 是否全部规则合法。
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.invalid.is_empty() && self.total > 0
    }

    /// 某域的规则数。
    #[must_use]
    pub fn count_domain(&self, domain: RiskDomain) -> usize {
        self.by_domain.get(domain.as_str()).copied().unwrap_or(0)
    }
}

impl fmt::Display for RuleMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} ({})", self.rule_key, self.rule_name, self.severity)
    }
}
