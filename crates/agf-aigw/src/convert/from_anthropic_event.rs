//! 由 `convert.rs` 拆分：`from_anthropic_event`/`to_gemini_body` 等 8 项（纯搬移，逻辑不变）。
use super::*;

/// Anthropic 流式事件 → canonical [`StreamChunk`]。
///
/// 支持的事件：`message_start`（首个 usage）、`content_block_start`（tool_use 开始）、
/// `content_block_delta`（`text_delta` / `input_json_delta`）、`message_delta`（stop_reason + usage）。
/// 其余事件（`ping`、`message_stop`…）返回空分片。
#[must_use]
pub fn from_anthropic_event(raw: &Value) -> StreamChunk {
    let mut chunk = StreamChunk::default();
    if matches!(
        raw.get("type").and_then(Value::as_str),
        Some(
            "message_start"
                | "content_block_start"
                | "content_block_delta"
                | "content_block_stop"
                | "message_delta"
                | "message_stop"
                | "ping"
        )
    ) {
        chunk.anthropic_event = Some(raw.clone());
    }
    match raw.get("type").and_then(Value::as_str) {
        Some("message_start") => {
            if let Some(u) = raw.get("message").and_then(|m| m.get("usage")) {
                let mut usage = anthropic_usage(u);
                // message_delta carries the final cumulative output count.
                usage.completion_tokens = 0;
                chunk.usage = Some(usage);
            }
        }
        Some("content_block_start") => {
            if let Some(block) = raw.get("content_block") {
                if block.get("type").and_then(Value::as_str) == Some("tool_use") {
                    chunk.delta.tool_calls.push(ToolCallDelta {
                        index: u32::try_from(raw.get("index").and_then(Value::as_u64).unwrap_or(0)).unwrap_or(0),
                        id: block.get("id").and_then(Value::as_str).map(ToString::to_string),
                        name: block.get("name").and_then(Value::as_str).map(ToString::to_string),
                        arguments_fragment: String::new(),
                    });
                }
            }
        }
        Some("content_block_delta") => {
            if let Some(delta) = raw.get("delta") {
                match delta.get("type").and_then(Value::as_str) {
                    Some("text_delta") => {
                        if let Some(t) = delta.get("text").and_then(Value::as_str) {
                            chunk.delta.content = t.to_string();
                        }
                    }
                    Some("input_json_delta") => {
                        chunk.delta.tool_calls.push(ToolCallDelta {
                            index: u32::try_from(raw.get("index").and_then(Value::as_u64).unwrap_or(0)).unwrap_or(0),
                            id: None,
                            name: None,
                            arguments_fragment: delta
                                .get("partial_json")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                        });
                    }
                    _ => {}
                }
            }
        }
        Some("message_delta") => {
            if let Some(reason) = raw.get("delta").and_then(|d| d.get("stop_reason")).and_then(Value::as_str) {
                chunk.finish_reason = Some(FinishReason::from_openai(reason));
            }
            if let Some(u) = raw.get("usage") {
                chunk.usage = Some(Usage {
                    prompt_tokens: 0,
                    completion_tokens: u.get("output_tokens").and_then(Value::as_u64).unwrap_or(0),
                    cached_tokens: 0,
                    ..Usage::default()
                });
            }
        }
        _ => {}
    }
    chunk
}

// ---------------------------------------------------------------------------
// Google Gemini
// ---------------------------------------------------------------------------

/// canonical → Gemini `POST /v1beta/models/{model}:generateContent` 请求体。
#[must_use]
pub fn to_gemini_body(req: &ChatRequest) -> Value {
    let mut body = Map::new();
    let contents: Vec<Value> = req.conversation().iter().map(|m| gemini_content(m)).collect();
    body.insert("contents".into(), Value::Array(contents));
    if let Some(system) = req.system_prompt() {
        body.insert("systemInstruction".into(), json!({"parts": [{"text": system}]}));
    }
    let mut generation = Map::new();
    if let Some(t) = req.temperature {
        generation.insert("temperature".into(), json!(t));
    }
    if let Some(top_p) = req.top_p {
        generation.insert("topP".into(), json!(top_p));
    }
    if !req.stop.is_empty() {
        generation.insert("stopSequences".into(), json!(req.stop));
    }
    generation.insert("maxOutputTokens".into(), json!(req.max_tokens.unwrap_or(GEMINI_DEFAULT_MAX_TOKENS)));
    if let Some(rf) = &req.response_format {
        if rf.requires_json() {
            generation.insert("responseMimeType".into(), Value::String("application/json".into()));
        }
    }
    body.insert("generationConfig".into(), Value::Object(generation));
    if !req.tools.is_empty() {
        body.insert(
            "tools".into(),
            json!([{"functionDeclarations": req.tools.iter().map(gemini_tool).collect::<Vec<_>>()}]),
        );
    }
    Value::Object(body)
}

pub(crate) fn gemini_tool(tool: &ToolDefinition) -> Value {
    json!({
        "name": tool.name,
        "description": tool.description,
        "parameters": if tool.parameters.is_null() { json!({"type": "object"}) } else { tool.parameters.clone() },
    })
}

pub(crate) fn gemini_content(msg: &ChatMessage) -> Value {
    let role = if msg.role == Role::Assistant { "model" } else { "user" };
    let mut parts: Vec<Value> = Vec::new();
    match msg.role {
        Role::Tool => {
            // Gemini 的 functionResponse 以"函数名"寻址（无独立 id 字段），
            // 网关用 tool_call_id 兜底（Mock/本地模型场景下即为函数名）。
            let name = msg.name.clone().unwrap_or_else(|| msg.tool_call_id.clone().unwrap_or_default());
            parts.push(json!({
                "functionResponse": {"name": name, "response": {"content": msg.content.as_plain_text()}}
            }));
        }
        _ => {
            match &msg.content {
                MessageContent::Text(t) if !t.is_empty() => parts.push(json!({"text": t})),
                MessageContent::Parts(content_parts) => {
                    for p in content_parts {
                        match p {
                            ContentPart::Text { text } => parts.push(json!({"text": text})),
                            ContentPart::Image { url, .. } => {
                                if let Some(part) = gemini_image_part(url) {
                                    parts.push(part);
                                }
                            }
                            ContentPart::ToolCall { name, arguments, .. } => {
                                parts.push(json!({"functionCall": {"name": name, "args": arguments}}));
                            }
                        }
                    }
                }
                MessageContent::Text(_) => {}
            }
            for call in &msg.tool_calls {
                parts.push(json!({"functionCall": {"name": call.name, "args": call.arguments}}));
            }
        }
    }
    if parts.is_empty() {
        parts.push(json!({"text": ""}));
    }
    json!({"role": role, "parts": parts})
}

pub(crate) fn gemini_image_part(url: &str) -> Option<Value> {
    let trimmed = url.trim();
    let rest = trimmed.strip_prefix("data:")?;
    let mut it = rest.splitn(2, ',');
    let meta = it.next().unwrap_or_default();
    let data = it.next().unwrap_or_default();
    if data.is_empty() {
        return None;
    }
    let mime_type = meta.split(';').next().unwrap_or("image/png");
    Some(json!({"inlineData": {"mimeType": mime_type, "data": data}}))
}

/// Gemini `generateContent` 响应 → canonical。
///
/// # Errors
/// 响应缺少 `candidates` 数组时返回 `DomainError::Parse`。
pub fn from_gemini_response(raw: &Value) -> agf_core::error::DomainResult<ChatResponse> {
    let candidates = raw
        .get("candidates")
        .and_then(Value::as_array)
        .ok_or_else(|| agf_core::error::DomainError::Parse("Gemini 响应缺少 candidates 数组".to_string()))?;
    let first = candidates.first();
    let parts = first.and_then(|c| c.get("content")).and_then(|c| c.get("parts")).and_then(Value::as_array);
    let mut text = String::new();
    let mut tool_calls: Vec<ToolCall> = Vec::new();
    for p in parts.into_iter().flatten() {
        if let Some(t) = p.get("text").and_then(Value::as_str) {
            text.push_str(t);
        }
        if let Some(fc) = p.get("functionCall") {
            tool_calls.push(ToolCall {
                id: format!("call_{}", tool_calls.len()),
                name: fc.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
                arguments: fc.get("args").cloned().unwrap_or(Value::Null),
            });
        }
    }
    let finish_reason = first
        .and_then(|c| c.get("finishReason"))
        .and_then(Value::as_str)
        .map_or(FinishReason::Stop, FinishReason::from_openai);
    let usage = raw.get("usageMetadata").map_or_else(Usage::default, |u| Usage {
        prompt_tokens: u.get("promptTokenCount").and_then(Value::as_u64).unwrap_or(0),
        completion_tokens: u.get("candidatesTokenCount").and_then(Value::as_u64).unwrap_or(0),
        cached_tokens: u.get("cachedContentTokenCount").and_then(Value::as_u64).unwrap_or(0),
        ..Usage::default()
    });
    let mut message = ChatMessage::assistant(text);
    message.tool_calls = tool_calls;
    Ok(ChatResponse {
        id: format!("agf-{}", agf_core::secret::generate_token()),
        model: raw.get("modelVersion").and_then(Value::as_str).unwrap_or_default().to_string(),
        message,
        finish_reason,
        usage,
        raw: Some(raw.clone()),
    })
}

/// Gemini 流式响应体（`alt=sse` 的每个 `data:` JSON）→ canonical [`StreamChunk`]。
#[must_use]
pub fn from_gemini_chunk(raw: &Value) -> StreamChunk {
    let mut chunk = StreamChunk::default();
    if let Some(u) = raw.get("usageMetadata") {
        chunk.usage = Some(Usage {
            prompt_tokens: u.get("promptTokenCount").and_then(Value::as_u64).unwrap_or(0),
            completion_tokens: u.get("candidatesTokenCount").and_then(Value::as_u64).unwrap_or(0),
            cached_tokens: u.get("cachedContentTokenCount").and_then(Value::as_u64).unwrap_or(0),
            ..Usage::default()
        });
    }
    let Some(candidate) = raw.get("candidates").and_then(Value::as_array).and_then(|a| a.first()) else {
        return chunk;
    };
    if let Some(parts) = candidate.get("content").and_then(|c| c.get("parts")).and_then(Value::as_array) {
        for p in parts {
            if let Some(t) = p.get("text").and_then(Value::as_str) {
                chunk.delta.content.push_str(t);
            }
            if let Some(fc) = p.get("functionCall") {
                let index = u32::try_from(chunk.delta.tool_calls.len()).unwrap_or(0);
                chunk.delta.tool_calls.push(ToolCallDelta {
                    index,
                    id: Some(format!("call_{index}")),
                    name: fc.get("name").and_then(Value::as_str).map(ToString::to_string),
                    arguments_fragment: fc.get("args").map_or_else(String::new, ToString::to_string),
                });
            }
        }
    }
    if let Some(reason) = candidate.get("finishReason").and_then(Value::as_str) {
        chunk.finish_reason = Some(FinishReason::from_openai(reason));
    }
    chunk
}

impl SseEvent {
    /// 是否是流结束标记 `data: [DONE]`。
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.data.trim() == "[DONE]"
    }

    /// 把 `data` 解析为 JSON。
    ///
    /// # Errors
    /// `data` 不是合法 JSON。
    pub fn json(&self) -> agf_core::error::DomainResult<Value> {
        serde_json::from_str(&self.data).map_err(|e| {
            agf_core::error::DomainError::Parse(format!("SSE data 不是合法 JSON: {e}; 原始内容: {}", self.data))
        })
    }
}
