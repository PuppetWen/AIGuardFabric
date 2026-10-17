//! 由 `screen.rs` 拆分：`mask_fragment`/`impl_KeywordScreen` 等 6 项（纯搬移，逻辑不变）。
use super::*;

/// 片段掩码（只保留长度信息，绝不回显原文）。
pub(crate) fn mask_fragment(fragment: &str) -> String {
    format!("<{} 字符的模式片段，已掩码>", fragment.chars().count())
}

impl ContentScreen for KeywordScreen {
    fn screen_request(&self, req: &ChatRequest) -> ScreenOutcome {
        let text = Self::request_text(req);
        if text.is_empty() {
            return ScreenOutcome::allow();
        }

        // 1) 凭证外传：默认脱敏（把明文密钥替换为占位符），可配置为阻断/仅记录
        if self.enable_credential_exfiltration {
            let has_exfil_intent =
                self.keyword_hits(&text).iter().any(|(c, _)| *c == KeywordCategory::CredentialExfiltration);
            let credentials = scan_credentials(&text, &[]);
            if has_exfil_intent || !credentials.is_empty() {
                match self.credential_action {
                    KeywordAction::Block => {
                        let rule = ScreenRule::new(
                            "kw.credential-exfiltration",
                            KeywordCategory::CredentialExfiltration.domain(),
                            KeywordCategory::CredentialExfiltration.description(),
                            mask_fragment("credential"),
                        );
                        return ScreenOutcome::block(rule, Self::block_reason(KeywordCategory::CredentialExfiltration));
                    }
                    KeywordAction::Redact => {
                        let mut map = RedactionMap::new();
                        let mut rewritten = req.clone();
                        let mut any = false;
                        for m in &mut rewritten.messages {
                            match &mut m.content {
                                MessageContent::Text(t) => {
                                    let (new_text, redactions) = Self::redact_credentials(t, &mut map);
                                    if !redactions.is_empty() {
                                        *t = new_text;
                                        any = true;
                                    }
                                }
                                MessageContent::Parts(parts) => {
                                    for part in parts.iter_mut() {
                                        if let crate::wire::ContentPart::Text { text } = part {
                                            let (new_text, redactions) = Self::redact_credentials(text, &mut map);
                                            if !redactions.is_empty() {
                                                *text = new_text;
                                                any = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if any {
                            return ScreenOutcome::redact(Some(rewritten), None, map);
                        }
                    }
                    KeywordAction::Audit => {}
                }
            }
        }

        // 2) 阻断类关键词（越狱 / 系统提示词泄露）
        for (category, masked) in self.keyword_hits(&text) {
            if self.block_categories.contains(&category) {
                let rule = ScreenRule::new(
                    format!("kw.{}", category.as_str()),
                    category.domain(),
                    category.description(),
                    masked,
                );
                return ScreenOutcome::block(rule, Self::block_reason(category));
            }
        }

        ScreenOutcome::allow()
    }

    fn screen_response(&self, resp: &ChatResponse) -> ScreenOutcome {
        if !self.filter_responses {
            return ScreenOutcome::allow();
        }
        let content = resp.text_content();
        if content.is_empty() {
            return ScreenOutcome::allow();
        }
        // 出站：模型把密钥/系统提示词原样吐回来时必须打码
        let mut map = RedactionMap::new();
        let (new_text, redactions) = Self::redact_credentials(&content, &mut map);
        if redactions.is_empty() {
            return ScreenOutcome::allow();
        }
        let mut rewritten = resp.clone();
        rewritten.message.content = MessageContent::text(new_text);
        ScreenOutcome::redact(None, Some(rewritten), map)
    }

    fn name(&self) -> &'static str {
        "keyword"
    }
}

impl CompositeScreen {
    /// 新建。
    #[must_use]
    pub fn new(screens: Vec<Arc<dyn ContentScreen>>) -> Self {
        Self { screens }
    }

    /// 过滤器数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.screens.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.screens.is_empty()
    }
}

impl ContentScreen for CompositeScreen {
    fn screen_request(&self, req: &ChatRequest) -> ScreenOutcome {
        let mut current = req.clone();
        let mut map = RedactionMap::new();
        let mut redacted = false;
        for screen in &self.screens {
            let outcome = screen.screen_request(&current);
            match outcome.verdict {
                ScreenVerdict::Block { .. } => return outcome,
                ScreenVerdict::Redact(_) => {
                    if let Some(next) = outcome.request {
                        current = next;
                    }
                    redacted = true;
                    for entry in outcome.redaction_map.entries() {
                        let placeholder = map.record(&entry.masked, &entry.category);
                        let _ = placeholder;
                    }
                }
                ScreenVerdict::Allow => {}
            }
        }
        if redacted { ScreenOutcome::redact(Some(current), None, map) } else { ScreenOutcome::allow() }
    }

    fn screen_response(&self, resp: &ChatResponse) -> ScreenOutcome {
        let mut current = resp.clone();
        let map = RedactionMap::new();
        let mut redacted = false;
        for screen in &self.screens {
            let outcome = screen.screen_response(&current);
            match outcome.verdict {
                ScreenVerdict::Block { .. } => return outcome,
                ScreenVerdict::Redact(_) => {
                    if let Some(next) = outcome.response {
                        current = next;
                    }
                    redacted = true;
                }
                ScreenVerdict::Allow => {}
            }
        }
        if redacted { ScreenOutcome::redact(None, Some(current), map) } else { ScreenOutcome::allow() }
    }

    fn name(&self) -> &'static str {
        "composite"
    }
}

/// 判断消息是否来自系统角色（供上层决定是否对系统提示词做特殊处理）。
#[must_use]
pub fn is_system_message(role: Role) -> bool {
    role == Role::System
}

/// 安全话术：响应被后置过滤判定为泄露时替换的文本。
#[must_use]
pub fn safe_response_text(rule_id: &str) -> String {
    format!("[内容安全] 该回复命中规则 {rule_id}，已按策略屏蔽原始内容。如需查看请联系安全管理员。")
}
