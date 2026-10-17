//! 由 `engine.rs` 拆分：`RuleBasedJudge`/`ScanEngine`/`ScanRequest`/`ScanResult`/`ScanTarget`/`ScanTargetKind` 的实现（纯搬移，逻辑不变）。
use super::*;

impl ScanTargetKind {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Prompt => "prompt",
            Self::LogPayload => "log-payload",
            Self::Document => "document",
            Self::ToolArguments => "tool-arguments",
            Self::ToolResult => "tool-result",
            Self::McpRequest => "mcp-request",
            Self::ModelOutput => "model-output",
            Self::McpResponse => "mcp-response",
            Self::Config => "config",
            Self::FileContent => "file-content",
            Self::ToolDefinition => "tool-definition",
        }
    }

    /// 默认适用哪些域（用于裁剪扫描范围，降低噪声）。
    #[must_use]
    pub const fn default_domains(&self) -> &'static [RiskDomain] {
        match self {
            Self::Prompt => &[RiskDomain::PromptAttack, RiskDomain::CredentialLeak],
            Self::LogPayload => &[RiskDomain::CredentialLeak, RiskDomain::ModelData],
            Self::Document => &[RiskDomain::RagPoison, RiskDomain::CredentialLeak],
            Self::ToolArguments | Self::McpRequest => &[RiskDomain::ToolAbuse, RiskDomain::CredentialLeak],
            Self::ToolResult => &[RiskDomain::ModelData, RiskDomain::CredentialLeak, RiskDomain::PromptAttack],
            Self::ModelOutput => &[RiskDomain::ModelData, RiskDomain::CredentialLeak],
            Self::McpResponse => &[RiskDomain::ModelData, RiskDomain::ToolAbuse],
            Self::Config => &[RiskDomain::CredentialLeak, RiskDomain::ToolAbuse],
            Self::FileContent => &[RiskDomain::CredentialLeak, RiskDomain::RagPoison],
            Self::ToolDefinition => &[RiskDomain::PromptAttack, RiskDomain::ToolAbuse],
        }
    }

    /// 对应规则编辑器里的检测目标，避免将工具规则用于提示词等其他输入。
    #[must_use]
    pub const fn rule_target(self) -> RuleTarget {
        match self {
            Self::Prompt => RuleTarget::Prompt,
            Self::LogPayload => RuleTarget::EventPayload,
            Self::Document => RuleTarget::Document,
            Self::ToolArguments => RuleTarget::ToolArguments,
            Self::ToolResult => RuleTarget::ToolResult,
            Self::McpRequest => RuleTarget::McpRequest,
            Self::ModelOutput => RuleTarget::ModelOutput,
            Self::McpResponse => RuleTarget::McpResponse,
            Self::Config => RuleTarget::Config,
            Self::FileContent => RuleTarget::FileContent,
            Self::ToolDefinition => RuleTarget::ToolDefinition,
        }
    }
}

impl ScanTarget {
    /// 构造。
    #[must_use]
    pub fn new(label: impl Into<String>, kind: ScanTargetKind, text: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            kind,
            text: text.into(),
            asset_id: None,
            data_class: DataClass::Internal,
            tool_name: None,
            tool_traits: None,
        }
    }

    /// 指定数据分级。
    #[must_use]
    pub const fn with_data_class(mut self, class: DataClass) -> Self {
        self.data_class = class;
        self
    }

    /// 指定工具信息。
    #[must_use]
    pub fn with_tool(mut self, name: impl Into<String>, traits: ToolTraits) -> Self {
        self.tool_name = Some(name.into());
        self.tool_traits = Some(traits);
        self
    }

    /// 指定资产。
    #[must_use]
    pub const fn with_asset(mut self, asset_id: Id) -> Self {
        self.asset_id = Some(asset_id);
        self
    }
}

impl Default for ScanRequest {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            use_llm_judge: false,
            domains: Vec::new(),
            report_suspicious: true,
            job_name: "adhoc-scan".to_string(),
        }
    }
}

impl ScanRequest {
    /// 构造。
    #[must_use]
    pub fn new(job_name: impl Into<String>) -> Self {
        Self { job_name: job_name.into(), ..Self::default() }
    }

    /// 追加目标。
    #[must_use]
    pub fn with_target(mut self, target: ScanTarget) -> Self {
        self.targets.push(target);
        self
    }

    /// 启用模型研判。
    #[must_use]
    pub const fn with_llm_judge(mut self, enabled: bool) -> Self {
        self.use_llm_judge = enabled;
        self
    }
}

impl ScanResult {
    /// 是否有任何命中。
    #[must_use]
    pub fn has_hits(&self) -> bool {
        !self.findings.is_empty() || !self.rule_hits.is_empty()
    }

    /// 规则命中总数。
    #[must_use]
    pub fn total_rule_hits(&self) -> usize {
        self.rule_hits.values().sum()
    }

    /// 摘要行（日志与 CI 输出）。
    #[must_use]
    pub fn summary_line(&self) -> String {
        format!(
            "扫描 {}：目标 {} 个，规则命中 {} 次，finding {} 条，最高等级 {}，风险分 {}，耗时 {}ms",
            self.job_name,
            self.targets_scanned,
            self.total_rule_hits(),
            self.findings.len(),
            self.max_severity,
            self.risk_score,
            self.elapsed_ms
        )
    }

    /// 按安全域统计 finding 数。
    #[must_use]
    pub fn findings_by_domain(&self) -> BTreeMap<String, usize> {
        let mut map = BTreeMap::new();
        for f in &self.findings {
            *map.entry(f.domain.as_str().to_string()).or_insert(0) += 1;
        }
        map
    }
}

#[async_trait]
impl LlmJudge for RuleBasedJudge {
    async fn judge(&self, domain: RiskDomain, _text: &str, hits: &[DomainHit]) -> DomainResult<LlmJudgement> {
        let max_sev = hits.iter().map(|h| h.severity).max();
        let (verdict, confidence, rationale) = if hits.is_empty() {
            (Verdict::Benign, 0.9, "规则未命中，判定为良性")
        } else {
            match max_sev {
                Some(Severity::Critical | Severity::High) => (Verdict::Malicious, 0.8, "命中高危规则，判定为恶意"),
                Some(Severity::Medium) => (Verdict::Suspicious, 0.65, "命中中危规则，判定为疑似"),
                _ => (Verdict::Suspicious, 0.5, "命中低危规则，需人工确认"),
            }
        };
        Ok(LlmJudgement {
            verdict,
            confidence,
            rationale: format!("[离线规则研判 · {}] {rationale}", domain.as_str()),
            cited_evidence: hits.iter().map(|h| h.key.clone()).collect(),
            model: "rule-based-judge".to_string(),
            mocked: true,
            judged_at: Timestamp::now(),
            raw_excerpt: None,
        })
    }

    fn is_mocked(&self) -> bool {
        true
    }

    fn model_name(&self) -> String {
        "rule-based-judge".to_string()
    }
}

impl std::fmt::Debug for ScanEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanEngine")
            .field("detector", &self.detector)
            .field("judge", &self.judge.as_ref().map(|j| j.model_name()))
            .finish()
    }
}

impl Default for ScanEngine {
    fn default() -> Self {
        Self::new()
    }
}
