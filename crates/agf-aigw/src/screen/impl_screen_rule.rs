//! 由 `screen.rs` 拆分：`KeywordCategory`/`KeywordScreen`/`NoopScreen`/`ScreenOutcome`/`ScreenRule`/`ScreenVerdict` 的实现（纯搬移，逻辑不变）。
use super::*;

impl ScreenRule {
    /// 构造。
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        domain: RiskDomain,
        description: impl Into<String>,
        masked_hit: impl Into<String>,
    ) -> Self {
        Self { id: id.into(), domain, description: description.into(), masked_hit: masked_hit.into() }
    }

    /// 审计文本。
    #[must_use]
    pub fn audit_note(&self) -> String {
        format!("规则 {}（{}）：{}", self.id, self.domain.as_str(), self.description)
    }
}

impl ScreenVerdict {
    /// 是否放行（含脱敏放行）。
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        matches!(self, Self::Allow | Self::Redact(_))
    }

    /// 是否阻断。
    #[must_use]
    pub const fn is_block(&self) -> bool {
        matches!(self, Self::Block { .. })
    }

    /// 脱敏条目数。
    #[must_use]
    pub fn redaction_count(&self) -> usize {
        match self {
            Self::Redact(items) => items.len(),
            _ => 0,
        }
    }

    /// 命中的规则 id（无命中返回 `None`）。
    #[must_use]
    pub fn rule_id(&self) -> Option<&str> {
        match self {
            Self::Block { rule, .. } => Some(rule.id.as_str()),
            _ => None,
        }
    }

    /// 阻断原因。
    #[must_use]
    pub fn block_reason(&self) -> Option<&str> {
        match self {
            Self::Block { reason, .. } => Some(reason.as_str()),
            _ => None,
        }
    }
}

impl Default for ScreenVerdict {
    /// 默认裁决：放行。
    fn default() -> Self {
        Self::Allow
    }
}

impl ScreenOutcome {
    /// 放行结果（无改写）。
    #[must_use]
    pub fn allow() -> Self {
        Self { verdict: ScreenVerdict::Allow, request: None, response: None, redaction_map: RedactionMap::new() }
    }

    /// 阻断结果。
    #[must_use]
    pub fn block(rule: ScreenRule, reason: impl Into<String>) -> Self {
        Self {
            verdict: ScreenVerdict::Block { reason: reason.into(), rule: Box::new(rule) },
            request: None,
            response: None,
            redaction_map: RedactionMap::new(),
        }
    }

    /// 脱敏结果。
    #[must_use]
    pub fn redact(request: Option<ChatRequest>, response: Option<ChatResponse>, map: RedactionMap) -> Self {
        Self { verdict: ScreenVerdict::Redact(map.entries().to_vec()), request, response, redaction_map: map }
    }
}

impl NoopScreen {
    /// 新建。
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ContentScreen for NoopScreen {
    fn screen_request(&self, _req: &ChatRequest) -> ScreenOutcome {
        ScreenOutcome::allow()
    }

    fn screen_response(&self, _resp: &ChatResponse) -> ScreenOutcome {
        ScreenOutcome::allow()
    }

    fn name(&self) -> &'static str {
        "noop"
    }

    fn is_noop(&self) -> bool {
        true
    }
}

impl KeywordCategory {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Jailbreak => "jailbreak",
            Self::SystemPromptLeak => "system-prompt-leak",
            Self::CredentialExfiltration => "credential-exfiltration",
        }
    }

    /// 归属安全域。
    #[must_use]
    pub const fn domain(&self) -> RiskDomain {
        match self {
            Self::Jailbreak | Self::SystemPromptLeak => RiskDomain::PromptAttack,
            Self::CredentialExfiltration => RiskDomain::CredentialLeak,
        }
    }

    /// 中文说明。
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Jailbreak => "越狱/角色劫持指令：试图让模型脱离既定安全约束",
            Self::SystemPromptLeak => "系统提示词泄露探测：试图套取平台提示词与内部配置",
            Self::CredentialExfiltration => "凭证外传：提示词中出现明文密钥或要求把密钥发送到外部",
        }
    }

    /// 全部类别。
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Jailbreak, Self::SystemPromptLeak, Self::CredentialExfiltration]
    }
}

impl Default for KeywordScreen {
    fn default() -> Self {
        Self {
            filter_responses: true,
            enable_jailbreak: true,
            enable_system_prompt_leak: true,
            enable_credential_exfiltration: true,
            credential_action: KeywordAction::Redact,
            block_categories: vec![KeywordCategory::Jailbreak, KeywordCategory::SystemPromptLeak],
        }
    }
}

impl KeywordScreen {
    /// 新建默认配置。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 仅审计（不阻断），用于试运行阶段。
    #[must_use]
    pub fn audit_only() -> Self {
        Self { block_categories: Vec::new(), credential_action: KeywordAction::Audit, ..Self::default() }
    }

    /// 设置凭证处置方式。
    #[must_use]
    pub fn with_credential_action(mut self, action: KeywordAction) -> Self {
        self.credential_action = action;
        self
    }

    /// 设置阻断类别。
    #[must_use]
    pub fn with_block_categories(mut self, categories: Vec<KeywordCategory>) -> Self {
        self.block_categories = categories;
        self
    }

    pub(crate) fn category_enabled(&self, category: KeywordCategory) -> bool {
        match category {
            KeywordCategory::Jailbreak => self.enable_jailbreak,
            KeywordCategory::SystemPromptLeak => self.enable_system_prompt_leak,
            KeywordCategory::CredentialExfiltration => self.enable_credential_exfiltration,
        }
    }

    pub(crate) fn category_from_str(value: &str) -> Option<KeywordCategory> {
        KeywordCategory::all().into_iter().find(|c| c.as_str() == value)
    }

    /// 在文本中查关键词，返回命中（`(category, masked_hit)`）。
    #[must_use]
    pub fn keyword_hits(&self, text: &str) -> Vec<(KeywordCategory, String)> {
        let lower = text.to_lowercase();
        let mut out: Vec<(KeywordCategory, String)> = Vec::new();
        for (category, pattern, _) in KEYWORD_PATTERNS {
            let Some(cat) = Self::category_from_str(category) else { continue };
            if !self.category_enabled(cat) {
                continue;
            }
            if lower.contains(pattern) {
                if !out.iter().any(|(c, _)| *c == cat) {
                    out.push((cat, mask_fragment(pattern)));
                }
            }
        }
        out
    }

    /// 用于检测的文本：所有消息内容 + 工具描述（工具描述也可能被注入）。
    pub(crate) fn request_text(req: &ChatRequest) -> String {
        let mut text = String::new();
        for m in &req.messages {
            text.push_str(&m.content.as_plain_text());
            for tc in &m.tool_calls {
                text.push_str(&tc.name);
                text.push_str(&tc.arguments.to_string());
            }
            text.push('\n');
        }
        for tool in &req.tools {
            text.push_str(&tool.name);
            text.push_str(&tool.description);
            text.push('\n');
        }
        text
    }

    pub(crate) fn block_reason(category: KeywordCategory) -> String {
        match category {
            KeywordCategory::Jailbreak => {
                "提示词含越狱/角色劫持指令，已被内容安全前置过滤阻断（未触达任何模型厂商）".to_string()
            }
            KeywordCategory::SystemPromptLeak => {
                "提示词试图套取系统提示词/平台内部配置，已被内容安全前置过滤阻断".to_string()
            }
            KeywordCategory::CredentialExfiltration => "提示词含凭证外传意图，已被内容安全前置过滤阻断".to_string(),
        }
    }

    /// 对文本做凭据脱敏（返回改写文本与替换记录）。
    pub(crate) fn redact_credentials(text: &str, map: &mut RedactionMap) -> (String, Vec<Redaction>) {
        let outcome = redact_text(text, RedactionMode::CredentialsAndPii, map);
        (outcome.text, outcome.redactions)
    }
}
