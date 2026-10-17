//! 由 `convert.rs` 拆分：`to_openai_body` 等 15 个函数（纯搬移，逻辑不变）。
use super::*;

// ---------------------------------------------------------------------------
// OpenAI 兼容
// ---------------------------------------------------------------------------

/// canonical → OpenAI Chat Completions 请求体。
///
/// Azure OpenAI / 阿里云百炼(DashScope) / 火山方舟(Ark) / 腾讯混元 / 百度文心(Qianfan)
/// / Kimi(Moonshot) / DeepSeek / 智谱 GLM / MiniMax / Ollama / vLLM / 自定义端点
/// 均使用该请求体（差异只在 `base_url`、鉴权头与 `extra_headers`）。
#[must_use]
pub fn to_openai_body(req: &ChatRequest, stream: bool) -> Value {
    let mut body = Map::new();
    body.insert("model".into(), Value::String(req.model.clone()));
    body.insert("messages".into(), Value::Array(req.messages.iter().map(openai_message).collect()));
    if let Some(t) = req.temperature {
        body.insert("temperature".into(), json!(t));
    }
    if let Some(m) = req.max_tokens {
        body.insert("max_tokens".into(), json!(m));
    }
    body.insert("stream".into(), Value::Bool(stream));
    if stream {
        // 让上游在最后一个分片返回 usage，网关据此计量（OpenAI 兼容族普遍支持）。
        body.insert("stream_options".into(), json!({"include_usage": true}));
    }
    if !req.tools.is_empty() {
        body.insert("tools".into(), Value::Array(req.tools.iter().map(openai_tool).collect()));
        body.insert("tool_choice".into(), Value::String("auto".into()));
    }
    if let Some(rf) = &req.response_format {
        body.insert("response_format".into(), openai_response_format(rf));
    }
    if let Some(value) = req.top_p {
        body.insert("top_p".into(), json!(value));
    }
    if !req.stop.is_empty() {
        body.insert("stop".into(), json!(req.stop));
    }
    if let Some(choice) = &req.tool_choice {
        body.insert("tool_choice".into(), choice.clone());
    }
    if let Some(u) = &req.user {
        body.insert("user".into(), Value::String(u.clone()));
    }
    Value::Object(body)
}

pub(crate) fn openai_response_format(rf: &ResponseFormat) -> Value {
    match rf {
        ResponseFormat::Text => json!({"type": "text"}),
        ResponseFormat::JsonObject => json!({"type": "json_object"}),
        ResponseFormat::JsonSchema { name, schema, strict } => json!({
            "type": "json_schema",
            "json_schema": {"name": name, "schema": schema, "strict": strict},
        }),
    }
}

pub(crate) fn openai_tool(tool: &ToolDefinition) -> Value {
    json!({
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": if tool.parameters.is_null() { json!({"type": "object"}) } else { tool.parameters.clone() },
        }
    })
}

pub(crate) fn openai_message(msg: &ChatMessage) -> Value {
    let mut out = Map::new();
    out.insert("role".into(), Value::String(msg.role.as_str().to_string()));
    if let Some(name) = &msg.name {
        out.insert("name".into(), Value::String(name.clone()));
    }
    match msg.role {
        Role::Tool => {
            if let Some(id) = &msg.tool_call_id {
                out.insert("tool_call_id".into(), Value::String(id.clone()));
            }
            out.insert("content".into(), Value::String(msg.content.as_plain_text()));
        }
        _ => {
            // 助手消息带工具调用时，OpenAI 要求 content 可为 null
            if !msg.tool_calls.is_empty() || !msg.content.is_empty() {
                out.insert("content".into(), openai_content(&msg.content));
            } else {
                out.insert("content".into(), Value::Null);
            }
            if !msg.tool_calls.is_empty() {
                out.insert("tool_calls".into(), Value::Array(msg.tool_calls.iter().map(openai_tool_call).collect()));
            }
        }
    }
    Value::Object(out)
}

pub(crate) fn openai_tool_call(call: &ToolCall) -> Value {
    json!({
        "id": call.id,
        "type": "function",
        "function": {
            "name": call.name,
            // OpenAI 侧参数是 JSON **字符串**
            "arguments": call.arguments.to_string(),
        }
    })
}

pub(crate) fn openai_content(content: &MessageContent) -> Value {
    match content {
        MessageContent::Text(t) => Value::String(t.clone()),
        MessageContent::Parts(parts) => Value::Array(
            parts
                .iter()
                .map(|p| match p {
                    ContentPart::Text { text } => json!({"type": "text", "text": text}),
                    ContentPart::Image { url, detail } => match detail {
                        Some(d) => json!({"type": "image_url", "image_url": {"url": url, "detail": d.as_str()}}),
                        None => json!({"type": "image_url", "image_url": {"url": url}}),
                    },
                    ContentPart::ToolCall { id, name, arguments } => json!({
                        "type": "function",
                        "id": id,
                        "function": {"name": name, "arguments": arguments.to_string()},
                    }),
                })
                .collect(),
        ),
    }
}

/// OpenAI Chat Completions 响应 → canonical。
///
/// # Errors
/// 响应体不是 JSON 或缺少 `choices` 数组时返回 `DomainError::Parse`。
pub fn from_openai_response(raw: &Value) -> agf_core::error::DomainResult<ChatResponse> {
    let choices = raw
        .get("choices")
        .and_then(Value::as_array)
        .ok_or_else(|| agf_core::error::DomainError::Parse("OpenAI 响应缺少 choices 数组".to_string()))?;
    let first = choices.first();
    let message = first.and_then(|c| c.get("message"));
    let role = message
        .and_then(|m| m.get("role"))
        .and_then(Value::as_str)
        .and_then(|r| Role::parse(r).ok())
        .unwrap_or(Role::Assistant);
    let content = message.and_then(|m| m.get("content"));
    let content = match content {
        Some(Value::String(s)) => MessageContent::text(s.clone()),
        Some(Value::Array(parts)) => MessageContent::parts(
            parts
                .iter()
                .filter_map(|p| {
                    let text = p.get("text").and_then(Value::as_str)?;
                    Some(ContentPart::text(text))
                })
                .collect(),
        ),
        _ => MessageContent::text(String::new()),
    };
    let tool_calls = message
        .and_then(|m| m.get("tool_calls"))
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(parse_openai_tool_call).collect())
        .unwrap_or_default();
    let finish_reason = first
        .and_then(|c| c.get("finish_reason"))
        .and_then(Value::as_str)
        .map_or(FinishReason::Stop, FinishReason::from_openai);
    Ok(ChatResponse {
        id: raw
            .get("id")
            .and_then(Value::as_str)
            .map_or_else(|| format!("agf-{}", agf_core::secret::generate_token()), ToString::to_string),
        model: raw.get("model").and_then(Value::as_str).unwrap_or_default().to_string(),
        message: ChatMessage { role, content, tool_calls, tool_call_id: None, name: None },
        finish_reason,
        usage: raw.get("usage").map_or_else(Usage::default, parse_openai_usage),
        raw: Some(raw.clone()),
    })
}

pub(crate) fn parse_openai_usage(usage: &Value) -> Usage {
    Usage {
        prompt_tokens: usage.get("prompt_tokens").and_then(Value::as_u64).unwrap_or(0),
        completion_tokens: usage.get("completion_tokens").and_then(Value::as_u64).unwrap_or(0),
        cached_tokens: usage
            .get("prompt_tokens_details")
            .and_then(|d| d.get("cached_tokens"))
            .and_then(Value::as_u64)
            .or_else(|| usage.get("cached_tokens").and_then(Value::as_u64))
            .unwrap_or(0),
        ..Usage::default()
    }
}

pub(crate) fn parse_openai_tool_call(value: &Value) -> Option<ToolCall> {
    let function = value.get("function")?;
    let name = function.get("name").and_then(Value::as_str)?.to_string();
    let arguments = match function.get("arguments") {
        Some(Value::String(s)) => parse_arguments(s),
        Some(other) => other.clone(),
        None => Value::Null,
    };
    let id = value.get("id").and_then(Value::as_str).map_or_else(|| format!("call_{name}"), ToString::to_string);
    Some(ToolCall { id, name, arguments })
}

/// OpenAI 流式分片（已解析的 `data:` JSON）→ canonical [`StreamChunk`]。
///
/// `choices` 为空（例如 `stream_options.include_usage` 的末尾分片）时只回传 usage。
#[must_use]
pub fn from_openai_chunk(raw: &Value) -> StreamChunk {
    let mut chunk = StreamChunk::default();
    if let Some(usage) = raw.get("usage") {
        if !usage.is_null() {
            chunk.usage = Some(parse_openai_usage(usage));
        }
    }
    let Some(choice) = raw.get("choices").and_then(Value::as_array).and_then(|a| a.first()) else {
        return chunk;
    };
    if let Some(delta) = choice.get("delta") {
        if let Some(role) = delta.get("role").and_then(Value::as_str).and_then(|r| Role::parse(r).ok()) {
            chunk.delta.role = Some(role);
        }
        if let Some(text) = delta.get("content").and_then(Value::as_str) {
            chunk.delta.content = text.to_string();
        }
        if let Some(calls) = delta.get("tool_calls").and_then(Value::as_array) {
            for c in calls {
                chunk.delta.tool_calls.push(ToolCallDelta {
                    index: u32::try_from(c.get("index").and_then(Value::as_u64).unwrap_or(0)).unwrap_or(0),
                    id: c.get("id").and_then(Value::as_str).map(ToString::to_string),
                    name: c
                        .get("function")
                        .and_then(|f| f.get("name"))
                        .and_then(Value::as_str)
                        .map(ToString::to_string),
                    arguments_fragment: c
                        .get("function")
                        .and_then(|f| f.get("arguments"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                });
            }
        }
    }
    if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
        chunk.finish_reason = Some(FinishReason::from_openai(reason));
    }
    chunk
}

// ---------------------------------------------------------------------------
// Anthropic Messages API
// ---------------------------------------------------------------------------

/// canonical → Anthropic `POST /v1/messages` 请求体。
#[must_use]
pub fn to_anthropic_body(req: &ChatRequest, stream: bool) -> Value {
    if let Some(native) = &req.anthropic_native {
        // Provider callers reject a changed canonical snapshot before reaching this function.
        if native.messages == req.messages {
            let mut body = native.body.clone();
            body["model"] = json!(req.model);
            body["max_tokens"] = json!(req.max_tokens.unwrap_or(ANTHROPIC_DEFAULT_MAX_TOKENS));
            body["stream"] = json!(stream);
            return body;
        }
    }
    let mut body = Map::new();
    body.insert("model".into(), Value::String(req.model.clone()));
    body.insert("max_tokens".into(), json!(req.max_tokens.unwrap_or(ANTHROPIC_DEFAULT_MAX_TOKENS)));
    if let Some(system) = req.system_prompt() {
        body.insert("system".into(), Value::String(system));
    }
    body.insert("messages".into(), Value::Array(anthropic_conversation(req)));
    if let Some(t) = req.temperature {
        body.insert("temperature".into(), json!(t));
    }
    body.insert("stream".into(), Value::Bool(stream));
    if !req.tools.is_empty() {
        body.insert("tools".into(), Value::Array(req.tools.iter().map(anthropic_tool).collect()));
    }
    if let Some(value) = req.top_p {
        body.insert("top_p".into(), json!(value));
    }
    if !req.stop.is_empty() {
        body.insert("stop_sequences".into(), json!(req.stop));
    }
    if let Some(choice) = &req.tool_choice {
        body.insert(
            "tool_choice".into(),
            match choice.as_str() {
                Some("required") => json!({"type":"any"}),
                Some("none") => json!({"type":"none"}),
                Some(_) => json!({"type":"auto"}),
                None => json!({"type":"tool","name":choice["function"]["name"]}),
            },
        );
    }
    Value::Object(body)
}

pub(crate) fn anthropic_tool(tool: &ToolDefinition) -> Value {
    json!({
        "name": tool.name,
        "description": tool.description,
        "input_schema": if tool.parameters.is_null() { json!({"type": "object"}) } else { tool.parameters.clone() },
    })
}

fn anthropic_conversation(req: &ChatRequest) -> Vec<Value> {
    let mut messages = Vec::new();
    let mut pending_tool_results = false;
    for message in req.conversation() {
        let native = anthropic_message(message);
        if pending_tool_results && matches!(message.role, Role::Tool | Role::User) {
            if let (Some(target), Some(blocks)) = (
                messages.last_mut().and_then(|last: &mut Value| last.get_mut("content")).and_then(Value::as_array_mut),
                native.get("content").and_then(Value::as_array),
            ) {
                target.extend(blocks.iter().cloned());
            } else {
                messages.push(native);
            }
        } else {
            messages.push(native);
        }
        pending_tool_results = message.role == Role::Tool;
    }
    messages
}

fn anthropic_content_blocks(content: &MessageContent) -> Vec<Value> {
    match content {
        MessageContent::Text(text) if !text.is_empty() => vec![json!({"type":"text","text":text})],
        MessageContent::Text(_) => Vec::new(),
        MessageContent::Parts(parts) => parts
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(json!({"type":"text","text":text})),
                ContentPart::Image { url, .. } => anthropic_image_block(url),
                ContentPart::ToolCall { id, name, arguments } => {
                    Some(json!({"type":"tool_use","id":id,"name":name,"input":arguments}))
                }
            })
            .collect(),
    }
}

pub(crate) fn anthropic_message(msg: &ChatMessage) -> Value {
    let role = if msg.role == Role::Assistant { "assistant" } else { "user" };
    let mut blocks: Vec<Value> = Vec::new();
    match msg.role {
        Role::Tool => {
            blocks.push(json!({
                "type": "tool_result",
                "tool_use_id": msg.tool_call_id.clone().unwrap_or_default(),
                "content": match &msg.content {
                    MessageContent::Text(text) => json!(text),
                    MessageContent::Parts(_) => json!(anthropic_content_blocks(&msg.content)),
                },
            }));
        }
        _ => {
            blocks.extend(anthropic_content_blocks(&msg.content));
            for call in &msg.tool_calls {
                blocks.push(json!({
                    "type": "tool_use", "id": call.id, "name": call.name, "input": call.arguments,
                }));
            }
        }
    }
    json!({"role": role, "content": blocks})
}

/// `data:image/png;base64,xxx` / 纯 base64 → Anthropic `image` 块。
///
/// HTTP(S) URL 无法直接内联到 Anthropic（其 API 只接受 base64 或 file_id），
/// 因此这里把非 data URI 的地址原样放进 `source.url`（Anthropic 新版支持 URL 源），
/// 由上游决定接受与否——**网关不做图片下载**（避免 SSRF 面）。
pub(crate) fn anthropic_image_block(url: &str) -> Option<Value> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix("data:") {
        let mut it = rest.splitn(2, ',');
        let meta = it.next().unwrap_or_default();
        let data = it.next().unwrap_or_default();
        let media_type = meta.split(';').next().unwrap_or("image/png");
        return Some(json!({
            "type": "image",
            "source": {"type": "base64", "media_type": media_type, "data": data},
        }));
    }
    Some(json!({"type": "image", "source": {"type": "url", "url": trimmed}}))
}

/// Anthropic Messages 响应 → canonical。
///
/// # Errors
/// 响应缺少 `content` 数组时返回 `DomainError::Parse`。
pub fn from_anthropic_response(raw: &Value) -> agf_core::error::DomainResult<ChatResponse> {
    let blocks = raw
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| agf_core::error::DomainError::Parse("Anthropic 响应缺少 content 数组".to_string()))?;
    let mut text = String::new();
    let mut tool_calls: Vec<ToolCall> = Vec::new();
    for b in blocks {
        match b.get("type").and_then(Value::as_str) {
            Some("text") => {
                if let Some(t) = b.get("text").and_then(Value::as_str) {
                    text.push_str(t);
                }
            }
            Some("tool_use") => {
                tool_calls.push(ToolCall {
                    id: b
                        .get("id")
                        .and_then(Value::as_str)
                        .map_or_else(|| format!("call_{}", tool_calls.len()), ToString::to_string),
                    name: b.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
                    arguments: b.get("input").cloned().unwrap_or(Value::Null),
                });
            }
            _ => {}
        }
    }
    let finish_reason =
        raw.get("stop_reason").and_then(Value::as_str).map_or(FinishReason::Stop, FinishReason::from_openai);
    let mut message = ChatMessage::assistant(text);
    message.tool_calls = tool_calls;
    Ok(ChatResponse {
        id: raw
            .get("id")
            .and_then(Value::as_str)
            .map_or_else(|| format!("agf-{}", agf_core::secret::generate_token()), ToString::to_string),
        model: raw.get("model").and_then(Value::as_str).unwrap_or_default().to_string(),
        message,
        finish_reason,
        usage: raw.get("usage").map_or_else(Usage::default, anthropic_usage),
        raw: Some(raw.clone()),
    })
}
