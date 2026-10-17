//! OpenAI-compatible chat boundary. Upstream adapters continue using the canonical wire types.
use super::*;
use agf_aigw::wire::{ChatRequest, ChatResponse, StreamChunk};

pub(super) fn request(mut value: Value) -> ApiResult<ChatRequest> {
    if value["stop"].is_string() {
        value["stop"] = json!([value["stop"]]);
    }
    if let Some(messages) = value.get_mut("messages").and_then(Value::as_array_mut) {
        for message in messages {
            if message["content"].is_null() {
                message["content"] = json!("");
            }
            if message["role"] == "developer" {
                message["role"] = json!("system");
            }
            if let Some(parts) = message["content"].as_array_mut() {
                for part in parts {
                    if part["type"] == "image_url" {
                        *part =
                            json!({"type":"image","url":part["image_url"]["url"],"detail":part["image_url"]["detail"]});
                    }
                }
            }
            if let Some(calls) = message.get_mut("tool_calls").and_then(Value::as_array_mut) {
                for call in calls {
                    let arguments = call["function"]["arguments"].as_str().unwrap_or("{}");
                    *call = json!({"id":call["id"],"name":call["function"]["name"],
                        "arguments":serde_json::from_str::<Value>(arguments).map_err(|_| DomainError::Validation("工具参数必须为 JSON".into()))?});
                }
            }
        }
    }
    if let Some(tools) = value.get_mut("tools").and_then(Value::as_array_mut) {
        for tool in tools {
            if tool["type"] == "function" {
                *tool = json!({"name":tool["function"]["name"], "description":tool["function"]["description"].as_str().unwrap_or(""),
                    "parameters":tool["function"]["parameters"], "side_effecting":true});
            }
        }
    }
    let mut request: ChatRequest =
        serde_json::from_value(value).map_err(|e| DomainError::Validation(format!("聊天请求不合法: {e}")))?;
    if request.messages.is_empty() || request.messages.len() > 512 {
        return Err(DomainError::Validation("消息数量必须为 1–512".into()).into());
    }
    if request.max_tokens == Some(0)
        || request.temperature.is_some_and(|v| !(0.0..=2.0).contains(&v))
        || request.top_p.is_some_and(|v| !(0.0..=1.0).contains(&v))
        || request.stop.len() > 16
        || request.stop.iter().any(|s| s.is_empty() || s.len() > 1024)
    {
        return Err(DomainError::Validation("生成参数超出支持范围".into()).into());
    }
    if let Some(choice) = &request.tool_choice {
        let valid = matches!(choice.as_str(), Some("auto" | "none" | "required"))
            || (choice["type"] == "function"
                && choice["function"]["name"]
                    .as_str()
                    .is_some_and(|name| request.tools.iter().any(|t| t.name == name)));
        if !valid {
            return Err(DomainError::Validation("tool_choice 必须选择请求中的工具".into()).into());
        }
    }
    if request.model == "auto" {
        request.model.clear();
    }
    Ok(request)
}

pub(super) fn response(response: ChatResponse) -> Value {
    let usage = response.usage;
    let calls = response
        .message
        .tool_calls
        .iter()
        .map(|c| json!({"id":c.id, "type":"function", "function":{"name":c.name, "arguments":c.arguments.to_string()}}))
        .collect::<Vec<_>>();
    let mut message = json!({"role":"assistant", "content":response.message.content});
    if !calls.is_empty() {
        message["tool_calls"] = json!(calls);
    }
    json!({"id":response.id,"object":"chat.completion","created":chrono::Utc::now().timestamp(),
        "model":response.model,"choices":[{"index":0,"message":message,"finish_reason":response.finish_reason}],
        "usage":{"prompt_tokens":usage.prompt_tokens,"completion_tokens":usage.completion_tokens,
            "total_tokens":usage.prompt_tokens+usage.completion_tokens}})
}

pub(super) fn chunk(id: &str, model: &str, chunk: StreamChunk) -> Value {
    let calls = chunk.delta.tool_calls.iter().map(|c|
        json!({"index":c.index,"id":c.id,"type":"function","function":{"name":c.name,"arguments":c.arguments_fragment}})
    ).collect::<Vec<_>>();
    let mut delta = json!({"content":chunk.delta.content});
    if let Some(role) = chunk.delta.role {
        delta["role"] = json!(role);
    }
    if !calls.is_empty() {
        delta["tool_calls"] = json!(calls);
    }
    let mut value = json!({"id":id,"object":"chat.completion.chunk","created":chrono::Utc::now().timestamp(),
        "model":model,"choices":[{"index":0,"delta":delta,"finish_reason":chunk.finish_reason}]});
    if let Some(usage) = chunk.usage {
        value["usage"] = json!({"prompt_tokens":usage.prompt_tokens,"completion_tokens":usage.completion_tokens,
            "total_tokens":usage.prompt_tokens+usage.completion_tokens});
    }
    value
}
