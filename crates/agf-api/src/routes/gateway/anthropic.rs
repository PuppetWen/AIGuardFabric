//! Anthropic Messages boundary; shares policy, quota, routing and metering with chat.
use super::*;
use agf_aigw::wire::{AnthropicNativeRequest, ChatRequest, ChatResponse, FinishReason};
use axum::{
    http::HeaderMap,
    response::{IntoResponse, Response},
};

pub(super) async fn messages(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Value>,
) -> ApiResult<Response> {
    let request = request(body, false)?;
    chat::execute(state, principal, headers, request, protocol::Protocol::Anthropic).await
}

pub(super) async fn count_tokens(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<Value>,
) -> ApiResult<Response> {
    principal.require(&state, "models", "read")?;
    let request = request(body, true)?;
    // This is deliberately marked as an estimate; billing always uses actual upstream usage.
    Ok(([("x-agf-token-count", "estimated")], Json(json!({"input_tokens":request.estimate_prompt_tokens()})))
        .into_response())
}

fn invalid(message: &str) -> crate::error::ApiError {
    DomainError::Validation(message.into()).into()
}

fn string(value: &Value, key: &str) -> ApiResult<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid(&format!("Messages: {key} 必须是非空字符串")))
}

fn parts(content: &Value) -> ApiResult<Vec<Value>> {
    if let Some(text) = content.as_str() {
        return Ok(vec![json!({"type":"text","text":text})]);
    }
    let rows = content.as_array().ok_or_else(|| invalid("Messages content 须为字符串或内容块数组"))?;
    let mut result = Vec::new();
    for block in rows {
        match block["type"].as_str() {
            Some("text") => result.push(json!({"type":"text","text":string(block,"text")?})),
            Some("image") => {
                let source = &block["source"];
                let url = match source["type"].as_str() {
                    Some("url") => string(source, "url")?,
                    Some("base64") => {
                        let mime = string(source, "media_type")?;
                        if !["image/png", "image/jpeg", "image/gif", "image/webp"].contains(&mime.as_str()) {
                            return Err(invalid("不支持此图片类型"));
                        }
                        format!("data:{mime};base64,{}", string(source, "data")?)
                    }
                    _ => return Err(invalid("图片须为 URL 或 base64 源")),
                };
                result.push(json!({"type":"image_url","image_url":{"url":url}}));
            }
            _ => return Err(invalid("该内容块尚不支持跨协议转换；支持 text、image、tool_use 与 tool_result")),
        }
    }
    Ok(result)
}

pub(super) fn request(body: Value, counting: bool) -> ApiResult<ChatRequest> {
    let model = string(&body, "model")?;
    if !counting && body["max_tokens"].as_u64().is_none_or(|v| v == 0 || v > u64::from(u32::MAX)) {
        return Err(invalid("Messages max_tokens 必须是正整数"));
    }
    if body.get("container").is_some_and(|v| !v.is_null()) {
        return Err(invalid("container 尚未接入模型网关"));
    }
    for field in ["thinking", "output_config", "context_management", "cache_control"] {
        if body.get(field).is_some_and(|value| !value.is_null() && !value.is_object()) {
            return Err(invalid(&format!("{field} 必须是对象")));
        }
    }
    let source = body["messages"]
        .as_array()
        .filter(|m| !m.is_empty() && m.len() <= 512)
        .ok_or_else(|| invalid("Messages 消息数量必须为 1–512"))?;
    let mut messages = Vec::new();
    if let Some(system) = body.get("system") {
        let system = parts(system)?;
        if system.iter().any(|b| b["type"] != "text") {
            return Err(invalid("system 只支持文本"));
        }
        messages.push(json!({"role":"system","content":system}));
    }
    let mut needs_native = ["thinking", "output_config", "context_management", "cache_control", "top_k"]
        .iter()
        .any(|field| body.get(*field).is_some_and(|value| !value.is_null()))
        || body.pointer("/tool_choice/disable_parallel_tool_use").is_some()
        || has_cache_control(&body);
    for message in source {
        let role = string(message, "role")?;
        if role != "user" && role != "assistant" {
            return Err(invalid("Messages role 必须为 user 或 assistant"));
        }
        let blocks = if let Some(text) = message["content"].as_str() {
            vec![json!({"type":"text","text":text})]
        } else {
            message["content"].as_array().cloned().ok_or_else(|| invalid("消息缺少 content"))?
        };
        let mut content = Vec::new();
        let mut calls = Vec::new();
        let mut results = Vec::new();
        for block in blocks {
            match block["type"].as_str() {
                Some("thinking") if role == "assistant" => {
                    let text = string(&block, "thinking")?;
                    let _signature = string(&block, "signature")?;
                    content.push(json!({"type":"text","text":text}));
                    needs_native = true;
                }
                Some("redacted_thinking") if role == "assistant" => {
                    let _data = string(&block, "data")?;
                    content.push(json!({"type":"text","text":"[redacted_thinking]"}));
                    needs_native = true;
                }
                Some("tool_use") if role == "assistant" => {
                    if !block["input"].is_object() {
                        return Err(invalid("tool_use input 须为 JSON 对象"));
                    }
                    calls.push(json!({"id":string(&block,"id")?,"type":"function","function":{
                        "name":string(&block,"name")?,"arguments":block["input"].to_string()}}));
                }
                Some("tool_result") if role == "user" => {
                    let mut value = parts(block.get("content").unwrap_or(&json!("")))?;
                    if block["is_error"] == true {
                        value.insert(0, json!({"type":"text","text":"Tool execution failed: "}));
                    }
                    results.push(json!({"role":"tool","tool_call_id":string(&block,"tool_use_id")?,"content":value}));
                }
                _ => content.extend(parts(&json!([block]))?),
            }
        }
        // OpenAI requires tool results immediately after the assistant tool calls.
        messages.extend(results);
        if !content.is_empty() || !calls.is_empty() {
            messages.push(json!({"role":role,"content":content,"tool_calls":calls}));
        }
    }
    let mut tools = Vec::new();
    if let Some(source) = body.get("tools") {
        for tool in source.as_array().ok_or_else(|| invalid("tools 必须是数组"))? {
            if tool.get("type").is_some_and(|v| v != "custom") {
                return Err(invalid("只支持客户端自定义工具；服务端工具须直连其原生端点"));
            }
            if !tool["input_schema"].is_object() {
                return Err(invalid("工具须提供 input_schema"));
            }
            tools.push(json!({"type":"function","function":{"name":string(tool,"name")?,
                "description":tool["description"].as_str().unwrap_or(""),"parameters":tool["input_schema"]}}));
        }
    }
    let choice = match body.get("tool_choice") {
        None => Value::Null,
        Some(value) => match value["type"].as_str() {
            Some("auto") => json!("auto"),
            Some("any") => json!("required"),
            Some("none") => json!("none"),
            Some("tool") => json!({"type":"function","function":{"name":string(value,"name")?}}),
            _ => return Err(invalid("无效 tool_choice")),
        },
    };
    let mut request = wire::request(json!({"model":model,"messages":messages,"max_tokens":body["max_tokens"],
        "temperature":body["temperature"],"top_p":body["top_p"],"stream":body["stream"].as_bool().unwrap_or(false),
        "stop":body.get("stop_sequences").cloned().unwrap_or(json!([])),"tools":tools,"tool_choice":choice,
        "user":body["metadata"]["user_id"]}))?;
    const ALLOWED: &[&str] = &[
        "model",
        "max_tokens",
        "system",
        "messages",
        "tools",
        "tool_choice",
        "temperature",
        "top_p",
        "top_k",
        "stop_sequences",
        "stream",
        "metadata",
        "thinking",
        "output_config",
        "context_management",
        "cache_control",
    ];
    if let Some(key) = body.as_object().and_then(|map| map.keys().find(|key| !ALLOWED.contains(&key.as_str()))) {
        return Err(invalid(&format!("Messages 字段 {key} 尚未验证，不能安全转换")));
    }
    if needs_native {
        request.anthropic_native = Some(AnthropicNativeRequest { body, messages: request.messages.clone() });
    }
    Ok(request)
}

fn has_cache_control(body: &Value) -> bool {
    fn in_content(value: &Value) -> bool {
        value.as_array().is_some_and(|blocks| {
            blocks
                .iter()
                .any(|block| block.get("cache_control").is_some() || block.get("content").is_some_and(in_content))
        })
    }
    in_content(&body["system"])
        || body["tools"].as_array().is_some_and(|tools| tools.iter().any(|tool| tool.get("cache_control").is_some()))
        || body["messages"]
            .as_array()
            .is_some_and(|messages| messages.iter().any(|message| in_content(&message["content"])))
}

pub(super) fn stop_reason(reason: FinishReason) -> &'static str {
    match reason {
        FinishReason::Length => "max_tokens",
        FinishReason::ToolCalls => "tool_use",
        FinishReason::ContentFilter => "refusal",
        _ => "end_turn",
    }
}

pub(super) fn response(reply: ChatResponse) -> Value {
    if let Some(raw) = reply.raw.as_ref().filter(|raw| raw["type"] == "message" && raw["content"].is_array()) {
        return raw.clone();
    }
    let mut content = Vec::new();
    let text = reply.text_content();
    if !text.is_empty() {
        content.push(json!({"type":"text","text":text}));
    }
    for call in &reply.message.tool_calls {
        content.push(json!({"type":"tool_use","id":call.id,"name":call.name,"input":call.arguments}));
    }
    json!({"id":reply.id,"type":"message","role":"assistant","model":reply.model,"content":content,
        "stop_reason":stop_reason(reply.finish_reason),"stop_sequence":null,
        "usage":{"input_tokens":reply.usage.prompt_tokens,"output_tokens":reply.usage.completion_tokens}})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tool_results_and_images_survive_boundary_and_choices_reach_provider() {
        let value = json!({"model":"claude","max_tokens":128,"system":[{"type":"text","text":"system"}],
            "messages":[{"role":"assistant","content":[{"type":"tool_use","id":"call1","name":"read","input":{}}]},
                {"role":"user","content":[{"type":"tool_result","tool_use_id":"call1","content":"done"},
                    {"type":"image","source":{"type":"url","url":"https://example.test/image.png"}}]}],
            "tools":[{"name":"read","input_schema":{"type":"object"}}],"tool_choice":{"type":"any"},"stop_sequences":["STOP"]});
        let request = request(value, false).unwrap();
        assert_eq!(request.messages[2].tool_call_id.as_deref(), Some("call1"));
        assert!(request.has_image());
        let native = agf_aigw::convert::to_anthropic_body(&request, false);
        assert_eq!(native["tool_choice"]["type"], "any");
        assert_eq!(native["stop_sequences"], json!(["STOP"]));
    }

    #[test]
    fn multiple_tool_results_keep_nested_image_and_following_text_in_one_user_turn() {
        let input = json!({"model":"claude","max_tokens":128,
            "messages":[
                {"role":"assistant","content":[
                    {"type":"tool_use","id":"one","name":"screenshot","input":{}},
                    {"type":"tool_use","id":"two","name":"status","input":{}}]},
                {"role":"user","content":[
                    {"type":"tool_result","tool_use_id":"one","content":[
                        {"type":"text","text":"screen"},
                        {"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA"}}]},
                    {"type":"tool_result","tool_use_id":"two","content":"ready"},
                    {"type":"text","text":"继续"}]}]});
        let request = request(input, false).unwrap();
        assert!(request.has_image());
        let native = agf_aigw::convert::to_anthropic_body(&request, false);
        assert_eq!(native["messages"].as_array().unwrap().len(), 2);
        let blocks = &native["messages"][1]["content"];
        assert_eq!(blocks[0]["type"], "tool_result");
        assert_eq!(blocks[0]["content"][1]["source"]["data"], "AAAA");
        assert_eq!(blocks[1]["tool_use_id"], "two");
        assert_eq!(blocks[2]["type"], "text");
    }

    #[test]
    fn signed_thinking_and_context_options_reach_anthropic_only_when_messages_are_unchanged() {
        let input = json!({"model":"claude","max_tokens":4096,
            "thinking":{"type":"enabled","budget_tokens":1024},
            "context_management":{"edits":[{"type":"clear_thinking_20251015"}]},
            "output_config":{"effort":"high"},
            "system":[{"type":"text","text":"system","cache_control":{"type":"ephemeral"}}],
            "messages":[{"role":"assistant","content":[
                {"type":"thinking","thinking":"reasoned text","signature":"opaque-signature"},
                {"type":"tool_use","id":"call1","name":"Read","input":{"path":"a"}}]},
                {"role":"user","content":[{"type":"tool_result","tool_use_id":"call1","content":"ok"}]}]});
        let mut request = request(input, false).unwrap();
        assert!(request.anthropic_native.is_some());
        request.model = "routed-model".into();
        let native = agf_aigw::convert::to_anthropic_body(&request, true);
        assert_eq!(native["model"], "routed-model");
        assert_eq!(native["stream"], true);
        assert_eq!(native["messages"][0]["content"][0]["signature"], "opaque-signature");
        assert_eq!(native["context_management"]["edits"][0]["type"], "clear_thinking_20251015");
        assert_eq!(native["system"][0]["cache_control"]["type"], "ephemeral");
        request.messages[0].content = agf_aigw::wire::MessageContent::text("redacted");
        assert!(request.ensure_anthropic_native_unchanged().is_err());
    }

    #[test]
    fn native_response_keeps_thinking_signature_for_next_tool_turn() {
        let raw = json!({"id":"msg_1","type":"message","role":"assistant","model":"claude",
            "content":[{"type":"thinking","thinking":"private","signature":"signed"},
                {"type":"tool_use","id":"tool_1","name":"Read","input":{}}],
            "stop_reason":"tool_use","usage":{"input_tokens":5,"output_tokens":7}});
        let reply = agf_aigw::convert::from_anthropic_response(&raw).unwrap();
        assert_eq!(response(reply), raw);
    }

    #[test]
    fn cache_markers_and_parallel_tool_choice_use_native_anthropic_body() {
        let input = json!({"model":"claude","max_tokens":128,"top_k":12,
            "cache_control":{"type":"ephemeral"},
            "system":[{"type":"text","text":"system","cache_control":{"type":"ephemeral"}}],
            "messages":[{"role":"user","content":[{"type":"text","text":"hello",
                "cache_control":{"type":"ephemeral"}}]}],
            "tools":[{"name":"Read","input_schema":{"type":"object"},
                "cache_control":{"type":"ephemeral"}}],
            "tool_choice":{"type":"auto","disable_parallel_tool_use":true}});
        let parsed = request(input.clone(), false).unwrap();
        let forwarded = agf_aigw::convert::to_anthropic_body(&parsed, false);
        assert_eq!(forwarded["top_k"], 12);
        assert_eq!(forwarded["cache_control"], input["cache_control"]);
        assert_eq!(forwarded["system"], input["system"]);
        assert_eq!(forwarded["messages"], input["messages"]);
        assert_eq!(forwarded["tools"], input["tools"]);
        assert_eq!(forwarded["tool_choice"], input["tool_choice"]);
        let no_top_level = json!({"model":"claude","max_tokens":128,
            "messages":[{"role":"user","content":[{"type":"text","text":"hello",
                "cache_control":{"type":"ephemeral"}}]}]});
        assert!(request(no_top_level, false).unwrap().anthropic_native.is_some());
        let schema_property = json!({"model":"claude","max_tokens":128,
            "messages":[{"role":"user","content":"hello"}],
            "tools":[{"name":"Read","input_schema":{"type":"object","properties":{
                "cache_control":{"type":"string"}}}}]});
        assert!(request(schema_property, false).unwrap().anthropic_native.is_none());
        let unsupported = json!({"model":"claude","max_tokens":128,
            "messages":[{"role":"user","content":"hello"}],"service_tier":"auto"});
        assert!(request(unsupported, false).is_err());
    }
}
