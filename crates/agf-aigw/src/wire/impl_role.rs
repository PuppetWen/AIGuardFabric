//! 由 `wire.rs` 拆分：`ChatMessage`/`ChatRequest`/`ContentPart`/`ImageDetail`/`MessageContent`/`ResponseFormat`/`Role`/`ToolCall`/`ToolDefinition` 的实现（纯搬移，逻辑不变）。
use super::*;

impl Role {
    /// 文本形式（与厂商侧字符串一致的部分直接复用）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::Tool => "tool",
        }
    }

    /// 解析文本。
    ///
    /// # Errors
    /// 未知角色返回错误描述。
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "system" | "developer" => Ok(Self::System),
            "user" | "human" => Ok(Self::User),
            "assistant" | "model" | "ai" => Ok(Self::Assistant),
            "tool" | "function" | "tool_result" => Ok(Self::Tool),
            other => Err(format!("未知会话角色: {other}")),
        }
    }
}

impl ImageDetail {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Low => "low",
            Self::High => "high",
        }
    }
}

impl ContentPart {
    /// 纯文本部件。
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text { text: text.into() }
    }

    /// 图片部件。
    #[must_use]
    pub fn image(url: impl Into<String>) -> Self {
        Self::Image { url: url.into(), detail: None }
    }

    /// 该部件占用的"文本当量"字符数（图片按固定 256 字符估算）。
    #[must_use]
    pub fn text_len(&self) -> usize {
        match self {
            Self::Text { text } => text.chars().count(),
            Self::Image { .. } => 256,
            Self::ToolCall { name, arguments, .. } => name.chars().count() + arguments.to_string().chars().count(),
        }
    }
}

impl Default for MessageContent {
    fn default() -> Self {
        Self::Text(String::new())
    }
}

impl MessageContent {
    /// 纯文本构造。
    #[must_use]
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text(value.into())
    }

    /// 多部件构造。
    #[must_use]
    pub fn parts(parts: Vec<ContentPart>) -> Self {
        Self::Parts(parts)
    }

    /// 取拼接后的纯文本（多部件时按顺序拼接文本片段，忽略图片）。
    #[must_use]
    pub fn as_plain_text(&self) -> String {
        match self {
            Self::Text(t) => t.clone(),
            Self::Parts(parts) => parts
                .iter()
                .filter_map(|p| match p {
                    ContentPart::Text { text } => Some(text.clone()),
                    ContentPart::ToolCall { arguments, .. } => Some(arguments.to_string()),
                    ContentPart::Image { .. } => None,
                })
                .collect::<String>(),
        }
    }

    /// 是否为空内容。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Text(t) => t.is_empty(),
            Self::Parts(p) => p.is_empty(),
        }
    }

    /// 是否含图片部件（用于路由的 Vision 模态筛选）。
    #[must_use]
    pub fn has_image(&self) -> bool {
        match self {
            Self::Text(_) => false,
            Self::Parts(parts) => parts.iter().any(|p| matches!(p, ContentPart::Image { .. })),
        }
    }

    /// "文本当量"字符数（估算 token 用）。
    #[must_use]
    pub fn approx_chars(&self) -> usize {
        match self {
            Self::Text(t) => t.chars().count(),
            Self::Parts(parts) => parts.iter().map(ContentPart::text_len).sum(),
        }
    }
}

impl ChatMessage {
    /// 系统消息。
    #[must_use]
    pub fn system(text: impl Into<String>) -> Self {
        Self::plain(Role::System, text)
    }

    /// 用户消息。
    #[must_use]
    pub fn user(text: impl Into<String>) -> Self {
        Self::plain(Role::User, text)
    }

    /// 助手消息。
    #[must_use]
    pub fn assistant(text: impl Into<String>) -> Self {
        Self::plain(Role::Assistant, text)
    }

    /// 工具结果消息。
    #[must_use]
    pub fn tool_result(tool_call_id: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            role: Role::Tool,
            content: MessageContent::text(text),
            tool_calls: Vec::new(),
            tool_call_id: Some(tool_call_id.into()),
            name: None,
        }
    }

    /// 指定角色 + 纯文本。
    #[must_use]
    pub fn plain(role: Role, text: impl Into<String>) -> Self {
        Self { role, content: MessageContent::text(text), tool_calls: Vec::new(), tool_call_id: None, name: None }
    }

    /// 多模态消息。
    #[must_use]
    pub fn multi(role: Role, parts: Vec<ContentPart>) -> Self {
        Self { role, content: MessageContent::parts(parts), tool_calls: Vec::new(), tool_call_id: None, name: None }
    }
}

impl ToolDefinition {
    /// 无副作用查询工具。
    #[must_use]
    pub fn query(name: impl Into<String>, description: impl Into<String>, parameters: serde_json::Value) -> Self {
        Self { name: name.into(), description: description.into(), parameters, side_effecting: false }
    }

    /// 有副作用工具。
    #[must_use]
    pub fn mutating(name: impl Into<String>, description: impl Into<String>, parameters: serde_json::Value) -> Self {
        Self { name: name.into(), description: description.into(), parameters, side_effecting: true }
    }
}

impl ToolCall {
    /// 构造。
    #[must_use]
    pub fn new(id: impl Into<String>, name: impl Into<String>, arguments: serde_json::Value) -> Self {
        Self { id: id.into(), name: name.into(), arguments }
    }
}

impl ResponseFormat {
    /// 是否要求 JSON 输出。
    #[must_use]
    pub const fn requires_json(&self) -> bool {
        !matches!(self, Self::Text)
    }
}

impl Default for ChatRequest {
    /// 默认空请求（`metadata` 需要显式构造，故不能 `derive`）。
    fn default() -> Self {
        Self {
            model: String::new(),
            messages: Vec::new(),
            temperature: None,
            max_tokens: None,
            top_p: None,
            stop: Vec::new(),
            tool_choice: None,
            stream: false,
            tools: Vec::new(),
            response_format: None,
            user: None,
            metadata: BTreeMap::new(),
            anthropic_native: None,
        }
    }
}

impl ChatRequest {
    /// A policy rewrite must never leave the original native payload eligible for forwarding.
    pub fn ensure_anthropic_native_unchanged(&self) -> agf_core::error::DomainResult<()> {
        if self.anthropic_native.as_ref().is_some_and(|native| native.messages != self.messages) {
            return Err(agf_core::error::DomainError::PolicyDenied {
                policy: "anthropic-native-request".into(),
                action: "deny".into(),
                reason: "策略或内容检查改写了消息；无法安全保留原生思考签名，请调整策略或关闭扩展思考".into(),
            });
        }
        Ok(())
    }

    /// 单轮用户提问。
    #[must_use]
    pub fn simple(model: impl Into<String>, prompt: impl Into<String>) -> Self {
        Self { model: model.into(), messages: vec![ChatMessage::user(prompt)], ..Self::default() }
    }

    /// 追加一条消息。
    pub fn push(&mut self, message: ChatMessage) -> &mut Self {
        self.messages.push(message);
        self
    }

    /// 取系统提示词（可能有多条，拼接为一段）。
    #[must_use]
    pub fn system_prompt(&self) -> Option<String> {
        let texts: Vec<String> = self
            .messages
            .iter()
            .filter(|m| m.role == Role::System)
            .map(|m| m.content.as_plain_text())
            .filter(|t| !t.is_empty())
            .collect();
        if texts.is_empty() { None } else { Some(texts.join("\n")) }
    }

    /// 非系统消息。
    #[must_use]
    pub fn conversation(&self) -> Vec<&ChatMessage> {
        self.messages.iter().filter(|m| m.role != Role::System).collect()
    }

    /// 请求是否携带图片（路由需要 Vision 端点）。
    #[must_use]
    pub fn has_image(&self) -> bool {
        self.messages.iter().any(|m| m.content.has_image())
    }

    /// 是否要求工具调用能力。
    #[must_use]
    pub fn needs_tools(&self) -> bool {
        !self.tools.is_empty() || self.messages.iter().any(|m| !m.tool_calls.is_empty())
    }

    /// 请求中是否出现有副作用的工具。
    #[must_use]
    pub fn has_side_effecting_tools(&self) -> bool {
        self.tools.iter().any(|t| t.side_effecting)
    }

    /// 估算输入 token。
    ///
    /// ## 启发式规则（刻意保守，宁可高估）
    ///
    /// - 拉丁字母/数字/ASCII 标点：**4 字符 ≈ 1 token**（BPE 经验值，英文技术文本 3.6~4.2）；
    /// - CJK（中日韩统一表意文字、假名、全角标点）：**1.5 字符 ≈ 1 token**
    ///   （现代 BPE 词表对中文约 1.2~1.8 字符/token，取中位数 1.5）；
    /// - 其余 Unicode（emoji、其它文字）：按 **2 字符 ≈ 1 token**；
    /// - 每条消息固定开销 **4 token**（role 标记 + 分隔符），末尾追加 **3 token**（回复引导符）；
    /// - 图片按每张 4,784 token 预留（当前高分辨率 Claude 图像的上限）；
    ///   未知尺寸/厂商时可能高估，但不能把截图算作零 token；
    /// - 每个工具定义按其 JSON 序列化长度的 1/4 计。
    ///
    /// 结果向上取整。真实值以厂商返回的 `usage` 为准，本函数只用于
    /// 预算前置拒绝与路由成本排序。
    #[must_use]
    pub fn estimate_prompt_tokens(&self) -> u64 {
        let mut tokens: f64 = 3.0;
        for m in &self.messages {
            tokens += 4.0;
            match &m.content {
                MessageContent::Text(text) => tokens += estimate_text_tokens(text),
                MessageContent::Parts(parts) => {
                    for part in parts {
                        tokens += match part {
                            ContentPart::Text { text } => estimate_text_tokens(text),
                            ContentPart::Image { .. } => 4_784.0,
                            ContentPart::ToolCall { name, arguments, .. } => {
                                estimate_text_tokens(name) + estimate_text_tokens(&arguments.to_string())
                            }
                        };
                    }
                }
            }
            for tc in &m.tool_calls {
                tokens += 4.0;
                tokens += estimate_text_tokens(&tc.name);
                tokens += estimate_text_tokens(&tc.arguments.to_string());
            }
        }
        for tool in &self.tools {
            tokens += 8.0;
            tokens += estimate_text_tokens(&tool.name);
            tokens += estimate_text_tokens(&tool.description);
            if !tool.parameters.is_null() {
                tokens += estimate_text_tokens(&tool.parameters.to_string());
            }
        }
        tokens.ceil().max(0.0) as u64
    }

    /// 请求指纹：`model + messages + tools + temperature` 的 SHA-256 十六进制。
    ///
    /// **刻意排除** `metadata` / `user` / `stream`：
    /// - `metadata` 只是审计标注，改变它不应导致缓存击穿；
    /// - `stream` 只是传输方式，非流式与流式的"内容"完全一致，
    ///   但流式请求默认不写缓存（见 [`crate::cache::is_cacheable`]）；
    ///
    /// 输出上限和采样/停止/工具选择参数参与指纹，避免错误复用不同请求的结果。
    ///
    /// 指纹稳定：同一进程、跨进程、跨平台均一致（纯 SHA-256，无随机盐）。
    /// 敏感性：任一消息文本、角色顺序、工具定义或温度变化都会改变指纹。
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"agf-aigw/v1\n");
        hasher.update(self.model.as_bytes());
        hasher.update(b"\n--messages--\n");
        for m in &self.messages {
            hasher.update(m.role.as_str().as_bytes());
            hasher.update(b"\x1f");
            if let Some(name) = &m.name {
                hasher.update(name.as_bytes());
            }
            hasher.update(b"\x1f");
            hasher.update(m.content.as_plain_text().as_bytes());
            hasher.update(b"\x1f");
            if let MessageContent::Parts(parts) = &m.content {
                for p in parts {
                    // 图片 URL 原样参与哈希（同一张图不同 URL 视为不同请求）
                    hasher.update(format!("{p:?}").as_bytes());
                }
            }
            for tc in &m.tool_calls {
                hasher.update(tc.id.as_bytes());
                hasher.update(tc.name.as_bytes());
                hasher.update(tc.arguments.to_string().as_bytes());
            }
            hasher.update(b"\x1e");
        }
        hasher.update(b"\n--tools--\n");
        for t in &self.tools {
            hasher.update(t.name.as_bytes());
            hasher.update(t.description.as_bytes());
            hasher.update(t.parameters.to_string().as_bytes());
            hasher.update([u8::from(t.side_effecting)]);
            hasher.update(b"\x1e");
        }
        hasher.update(b"\n--params--\n");
        hasher.update(format!("{:?}", self.temperature).as_bytes());
        hasher.update(format!("{:?}{:?}{:?}{:?}", self.max_tokens, self.top_p, self.stop, self.tool_choice).as_bytes());
        hasher.update(format!("{:?}", self.response_format).as_bytes());
        hex::encode(hasher.finalize())
    }

    /// 请求的数据分级（默认取自 metadata 的 `data_class`，缺省为 `Internal`）。
    ///
    /// 网关允许调用方通过 metadata 标注数据分级（`public`/`internal`/`confidential`/`restricted`），
    /// 路由据此执行"数据不出域"约束。
    #[must_use]
    pub fn data_class_hint(&self) -> Option<DataClass> {
        self.metadata.get("data_class").and_then(|v| match v.to_ascii_lowercase().as_str() {
            "public" => Some(DataClass::Public),
            "internal" => Some(DataClass::Internal),
            "confidential" => Some(DataClass::Confidential),
            "restricted" => Some(DataClass::Restricted),
            _ => None,
        })
    }
}
