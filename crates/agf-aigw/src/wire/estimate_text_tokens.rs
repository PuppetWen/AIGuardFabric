//! 由 `wire.rs` 拆分：`estimate_text_tokens`/`is_cjk` 等 9 项（纯搬移，逻辑不变）。
use super::*;

/// 估算一段文本的 token 数（见 [`ChatRequest::estimate_prompt_tokens`] 的规则说明）。
#[must_use]
pub fn estimate_text_tokens(text: &str) -> f64 {
    let mut latin = 0_usize;
    let mut cjk = 0_usize;
    let mut other = 0_usize;
    for ch in text.chars() {
        if ch.is_ascii() {
            latin += 1;
        } else if is_cjk(ch) {
            cjk += 1;
        } else {
            other += 1;
        }
    }
    latin as f64 / 4.0 + cjk as f64 / 1.5 + other as f64 / 2.0
}

/// 是否为 CJK 字符（中日韩统一表意文字、扩展 A、假名、谚文、CJK 标点与全角形式）。
#[must_use]
pub fn is_cjk(ch: char) -> bool {
    matches!(ch as u32,
        0x1100..=0x11FF        // 谚文字母
        | 0x2E80..=0x2EFF      // CJK 部首补充
        | 0x3000..=0x303F      // CJK 标点
        | 0x3040..=0x30FF      // 平假名 / 片假名
        | 0x3130..=0x318F      // 谚文兼容字母
        | 0x3400..=0x4DBF      // CJK 扩展 A
        | 0x4E00..=0x9FFF      // CJK 统一表意
        | 0xA960..=0xA97F      // 谚文字母扩展 A
        | 0xAC00..=0xD7FF      // 谚文音节
        | 0xF900..=0xFAFF      // CJK 兼容表意
        | 0xFE30..=0xFE4F      // CJK 兼容形式
        | 0xFF00..=0xFFEF      // 全角形式
        | 0x20000..=0x2FA1F    // CJK 扩展 B~F
    )
}

impl Usage {
    /// 构造。
    #[must_use]
    pub const fn new(prompt_tokens: u64, completion_tokens: u64, cached_tokens: u64) -> Self {
        Self { prompt_tokens, completion_tokens, cached_tokens, cache_write_tokens: 0, cache_write_1h_tokens: 0 }
    }

    /// 总 token。
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.prompt_tokens + self.completion_tokens
    }

    /// 累加（流式分片汇总、多段调用合并）。
    #[must_use]
    pub const fn saturating_add(self, other: Self) -> Self {
        Self {
            prompt_tokens: self.prompt_tokens.saturating_add(other.prompt_tokens),
            completion_tokens: self.completion_tokens.saturating_add(other.completion_tokens),
            cached_tokens: self.cached_tokens.saturating_add(other.cached_tokens),
            cache_write_tokens: self.cache_write_tokens.saturating_add(other.cache_write_tokens),
            cache_write_1h_tokens: self.cache_write_1h_tokens.saturating_add(other.cache_write_1h_tokens),
        }
    }

    /// 累加（原地）。
    pub const fn accumulate(&mut self, other: Self) {
        *self = self.saturating_add(other);
    }

    /// 是否为空（流式仅末尾分片带 usage，其余分片为空）。
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.prompt_tokens == 0
            && self.completion_tokens == 0
            && self.cached_tokens == 0
            && self.cache_write_tokens == 0
            && self.cache_write_1h_tokens == 0
    }
}

impl FinishReason {
    /// 文本形式（OpenAI 风格，便于直接回包给 OpenAI 兼容客户端）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::Length => "length",
            Self::ToolCalls => "tool_calls",
            Self::ContentFilter => "content_filter",
            Self::Other => "other",
        }
    }

    /// 从 OpenAI 风格字符串解析。
    #[must_use]
    pub fn from_openai(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "stop" | "end_turn" => Self::Stop,
            "length" | "max_tokens" => Self::Length,
            "tool_calls" | "function_call" | "tool_use" => Self::ToolCalls,
            "content_filter" | "safety" | "recitation" | "blocklist" | "prohibited_content" => Self::ContentFilter,
            _ => Self::Other,
        }
    }
}

impl ChatResponse {
    /// 组装一次纯文本回复。
    #[must_use]
    pub fn text(model: impl Into<String>, text: impl Into<String>, usage: Usage) -> Self {
        Self {
            id: format!("agf-{}", agf_core::secret::generate_token()),
            model: model.into(),
            message: ChatMessage::assistant(text),
            finish_reason: FinishReason::Stop,
            usage,
            raw: None,
        }
    }

    /// 回复的纯文本形态。
    #[must_use]
    pub fn text_content(&self) -> String {
        self.message.content.as_plain_text()
    }

    /// 回复中的工具调用。
    #[must_use]
    pub fn tool_calls(&self) -> &[ToolCall] {
        &self.message.tool_calls
    }
}

impl ChatDelta {
    /// 文本增量。
    #[must_use]
    pub fn text(content: impl Into<String>) -> Self {
        Self { role: None, content: content.into(), tool_calls: Vec::new() }
    }

    /// 是否为空增量（心跳分片）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.content.is_empty() && self.tool_calls.is_empty() && self.role.is_none()
    }
}

impl StreamChunk {
    /// 文本增量分片。
    #[must_use]
    pub fn text(content: impl Into<String>) -> Self {
        Self { delta: ChatDelta::text(content), ..Self::default() }
    }

    /// 结束分片（携带 usage）。
    #[must_use]
    pub fn finished(reason: FinishReason, usage: Option<Usage>) -> Self {
        Self { finish_reason: Some(reason), usage, ..Self::default() }
    }

    /// 是否是结束分片。
    #[must_use]
    pub const fn is_final(&self) -> bool {
        self.finish_reason.is_some()
    }
}

impl StreamAccumulator {
    /// 新建。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 吸收一个分片。
    pub fn push(&mut self, chunk: &StreamChunk) {
        self.content.push_str(&chunk.delta.content);
        for d in &chunk.delta.tool_calls {
            self.merge_tool_call(d);
        }
        if let Some(r) = chunk.finish_reason {
            self.finish_reason = Some(r);
        }
        if let Some(u) = chunk.usage {
            self.usage.accumulate(u);
        }
    }

    /// 合并工具调用增量（同一 `index` 的分片拼接 id/name/参数片段）。
    pub fn merge_tool_call(&mut self, delta: &ToolCallDelta) {
        let idx = usize::try_from(delta.index).unwrap_or(usize::MAX);
        while self.calls.len() <= idx {
            self.calls.push(ToolCall::new(String::new(), String::new(), serde_json::Value::Null));
        }
        if let Some(slot) = self.calls.get_mut(idx) {
            if let Some(id) = &delta.id {
                slot.id.clone_from(id);
            }
            if let Some(name) = &delta.name {
                slot.name.clone_from(name);
            }
            if !delta.arguments_fragment.is_empty() {
                let mut buf = match &slot.arguments {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Null => String::new(),
                    other => other.to_string(),
                };
                buf.push_str(&delta.arguments_fragment);
                slot.arguments = parse_arguments(&buf);
            }
        }
    }

    /// 当前累积的文本。
    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }

    /// 当前累积的用量。
    #[must_use]
    pub const fn usage(&self) -> Usage {
        self.usage
    }

    /// 结束原因。
    #[must_use]
    pub const fn finish_reason(&self) -> Option<FinishReason> {
        self.finish_reason
    }

    /// 应收敛为完整回复（消费累积器）。
    #[must_use]
    pub fn finish(self, model: &str) -> ChatResponse {
        self.snapshot(model)
    }

    /// 应收敛为完整回复（**不消费**累积器，供流式收尾时"既要回复也要保留累积器"的场景）。
    #[must_use]
    pub fn snapshot(&self, model: &str) -> ChatResponse {
        let mut message = ChatMessage::assistant(self.content.clone());
        message.tool_calls = self.calls.clone();
        ChatResponse {
            id: format!("agf-{}", agf_core::secret::generate_token()),
            model: model.to_string(),
            message,
            finish_reason: self.finish_reason.unwrap_or(FinishReason::Stop),
            usage: self.usage,
            raw: None,
        }
    }
}

/// 把工具参数片段解析为 JSON；无法解析时**保留原始字符串**（不丢数据）。
#[must_use]
pub fn parse_arguments(raw: &str) -> serde_json::Value {
    if raw.trim().is_empty() {
        return serde_json::Value::Null;
    }
    serde_json::from_str(raw).unwrap_or_else(|_| serde_json::Value::String(raw.to_string()))
}
