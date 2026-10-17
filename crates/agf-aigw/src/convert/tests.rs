//! 由 `convert.rs` 拆分：`gateway_request` 等 27 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn gateway_request() -> ChatRequest {
    let mut req = ChatRequest {
        model: "gpt-4o".into(),
        messages: vec![
            ChatMessage::system("你是 AIGuardFabric 的安全分析师"),
            ChatMessage::user("研判这条告警：SSH 暴力破解"),
            ChatMessage::assistant("需要查询资产台账"),
        ],
        temperature: Some(0.0),
        max_tokens: Some(1024),
        stream: false,
        tools: vec![ToolDefinition::query(
            "query_asset",
            "查询资产",
            json!({"type": "object", "properties": {"id": {"type": "string"}}}),
        )],
        response_format: Some(ResponseFormat::JsonObject),
        user: Some("agent-42".into()),
        metadata: std::collections::BTreeMap::default(),
        ..ChatRequest::default()
    };
    // 助手消息带一次工具调用，覆盖 tool_calls 编码分支
    req.messages[2].tool_calls.push(ToolCall::new("call_1", "query_asset", json!({"id": "asset-1"})));
    req
}

// ---- OpenAI ----------------------------------------------------------

#[test]
pub(crate) fn openai_body_maps_roles_and_params() {
    let body = to_openai_body(&gateway_request(), false);
    eq!(body["model"], json!("gpt-4o"));
    eq!(body["messages"][0]["role"], json!("system"));
    eq!(body["messages"][1]["role"], json!("user"));
    eq!(body["messages"][2]["role"], json!("assistant"));
    eq!(body["temperature"], json!(0.0));
    eq!(body["max_tokens"], json!(1024));
    eq!(body["stream"], json!(false));
    eq!(body["user"], json!("agent-42"));
    eq!(body["response_format"]["type"], json!("json_object"));
    assert!(body.get("stream_options").is_none(), "非流式不应带 stream_options");
}

#[test]
pub(crate) fn openai_body_encodes_tools_as_string_arguments() {
    let body = to_openai_body(&gateway_request(), false);
    eq!(body["tools"][0]["type"], json!("function"));
    eq!(body["tools"][0]["function"]["name"], json!("query_asset"));
    eq!(body["tool_choice"], json!("auto"));
    // 关键：arguments 必须是 JSON **字符串**
    let args = body["messages"][2]["tool_calls"][0]["function"]["arguments"].clone();
    assert!(args.is_string(), "OpenAI 要求 arguments 为字符串，实际: {args}");
    eq!(parse_arguments(args.as_str().unwrap_or_default()), json!({"id": "asset-1"}));
}

#[test]
pub(crate) fn openai_stream_body_includes_usage_option() {
    let body = to_openai_body(&ChatRequest::simple("m", "hi"), true);
    eq!(body["stream"], json!(true));
    eq!(body["stream_options"]["include_usage"], json!(true));
}

#[test]
pub(crate) fn openai_tool_result_message_carries_call_id() {
    let req =
        ChatRequest { messages: vec![ChatMessage::tool_result("call_7", "{\"ok\":true}")], ..ChatRequest::default() };
    let body = to_openai_body(&req, false);
    eq!(body["messages"][0]["role"], json!("tool"));
    eq!(body["messages"][0]["tool_call_id"], json!("call_7"));
}

#[test]
pub(crate) fn openai_multimodal_content_maps_image_url() {
    let req = ChatRequest {
        messages: vec![ChatMessage::multi(
            Role::User,
            vec![ContentPart::text("描述这张图"), ContentPart::image("data:image/png;base64,AAA")],
        )],
        ..ChatRequest::default()
    };
    let body = to_openai_body(&req, false);
    eq!(body["messages"][0]["content"][0]["type"], json!("text"));
    eq!(body["messages"][0]["content"][1]["type"], json!("image_url"));
    eq!(body["messages"][0]["content"][1]["image_url"]["url"], json!("data:image/png;base64,AAA"));
}

#[test]
pub(crate) fn openai_response_roundtrip() {
    let raw = json!({
        "id": "chatcmpl-1",
        "model": "gpt-4o-2024-08-06",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "结论：恶意"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 100, "completion_tokens": 20,
                  "prompt_tokens_details": {"cached_tokens": 40}}
    });
    let resp = from_openai_response(&raw).unwrap_or_else(|e| panic!("{e}"));
    eq!(resp.id, "chatcmpl-1");
    eq!(resp.model, "gpt-4o-2024-08-06");
    eq!(resp.text_content(), "结论：恶意");
    eq!(resp.finish_reason, FinishReason::Stop);
    eq!(resp.usage, Usage::new(100, 20, 40));
    assert!(resp.raw.is_some());
}

#[test]
pub(crate) fn openai_response_parses_tool_calls() {
    let raw = json!({
        "id": "chatcmpl-2",
        "model": "gpt-4o",
        "choices": [{
            "message": {"role": "assistant", "content": null, "tool_calls": [
                {"id": "call_a", "type": "function",
                 "function": {"name": "query_asset", "arguments": "{\"id\":\"a-1\"}"}}
            ]},
            "finish_reason": "tool_calls"
        }],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5}
    });
    let resp = from_openai_response(&raw).unwrap_or_else(|e| panic!("{e}"));
    eq!(resp.finish_reason, FinishReason::ToolCalls);
    eq!(resp.tool_calls().len(), 1);
    eq!(resp.tool_calls()[0].id, "call_a");
    eq!(resp.tool_calls()[0].arguments, json!({"id": "a-1"}));
}

#[test]
pub(crate) fn openai_response_rejects_malformed() {
    assert!(from_openai_response(&json!({"error": "boom"})).is_err());
}

#[test]
pub(crate) fn openai_chunk_maps_delta_and_finish() {
    let chunk = from_openai_chunk(&json!({
        "choices": [{"index": 0, "delta": {"content": "你"}, "finish_reason": null}]
    }));
    eq!(chunk.delta.content, "你");
    assert!(chunk.finish_reason.is_none());

    let last = from_openai_chunk(&json!({
        "choices": [{"index": 0, "delta": {}, "finish_reason": "length"}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 4}
    }));
    eq!(last.finish_reason, Some(FinishReason::Length));
    eq!(last.usage, Some(Usage::new(3, 4, 0)));
}

#[test]
pub(crate) fn openai_chunk_usage_only_frame() {
    let c = from_openai_chunk(&json!({"choices": [], "usage": {"prompt_tokens": 7, "completion_tokens": 1}}));
    eq!(c.usage, Some(Usage::new(7, 1, 0)));
    assert!(c.delta.is_empty());
}

#[test]
pub(crate) fn openai_chunk_tool_call_fragments() {
    let c = from_openai_chunk(&json!({
        "choices": [{"delta": {"tool_calls": [
            {"index": 0, "id": "call_1", "function": {"name": "query", "arguments": "{\"a\""}}
        ]}}]
    }));
    eq!(c.delta.tool_calls.len(), 1);
    eq!(c.delta.tool_calls[0].name.as_deref(), Some("query"));
    eq!(c.delta.tool_calls[0].arguments_fragment, "{\"a\"");
}

// ---- Anthropic -------------------------------------------------------

#[test]
pub(crate) fn anthropic_body_hoists_system_prompt() {
    let body = to_anthropic_body(&gateway_request(), false);
    eq!(body["system"], json!("你是 AIGuardFabric 的安全分析师"));
    eq!(body["max_tokens"], json!(1024));
    // system 不得出现在 messages 中
    let roles: Vec<&str> =
        body["messages"].as_array().map(|a| a.iter().filter_map(|m| m["role"].as_str()).collect()).unwrap_or_default();
    eq!(roles, vec!["user", "assistant"]);
}

#[test]
pub(crate) fn anthropic_body_defaults_max_tokens() {
    let body = to_anthropic_body(&ChatRequest::simple("claude", "hi"), false);
    eq!(body["max_tokens"], json!(ANTHROPIC_DEFAULT_MAX_TOKENS));
    assert!(body.get("system").is_none());
}

#[test]
pub(crate) fn anthropic_body_tool_use_and_result_blocks() {
    let req = ChatRequest {
        model: "claude".into(),
        messages: vec![
            ChatMessage::user("查一下"),
            {
                let mut m = ChatMessage::assistant("");
                m.tool_calls.push(ToolCall::new("toolu_1", "query_asset", json!({"id": "a-1"})));
                m
            },
            ChatMessage::tool_result("toolu_1", "{\"name\":\"db-01\"}"),
        ],
        tools: vec![ToolDefinition::query("query_asset", "查询", json!({"type": "object"}))],
        ..ChatRequest::default()
    };
    let body = to_anthropic_body(&req, false);
    eq!(body["messages"][1]["content"][0]["type"], json!("tool_use"));
    eq!(body["messages"][1]["content"][0]["input"], json!({"id": "a-1"}));
    eq!(body["messages"][2]["content"][0]["type"], json!("tool_result"));
    eq!(body["messages"][2]["content"][0]["tool_use_id"], json!("toolu_1"));
    // Anthropic 工具定义是扁平的 input_schema
    eq!(body["tools"][0]["name"], json!("query_asset"));
    assert!(body["tools"][0]["input_schema"].is_object());
}

#[test]
pub(crate) fn anthropic_image_data_uri_becomes_base64_source() {
    let req = ChatRequest {
        messages: vec![ChatMessage::multi(Role::User, vec![ContentPart::image("data:image/jpeg;base64,ZZZ")])],
        ..ChatRequest::default()
    };
    let body = to_anthropic_body(&req, false);
    eq!(body["messages"][0]["content"][0]["source"]["type"], json!("base64"));
    eq!(body["messages"][0]["content"][0]["source"]["media_type"], json!("image/jpeg"));
    eq!(body["messages"][0]["content"][0]["source"]["data"], json!("ZZZ"));
}

#[test]
pub(crate) fn anthropic_response_maps_blocks_and_usage() {
    let raw = json!({
        "id": "msg_1",
        "model": "claude-3-5-sonnet-20241022",
        "content": [
            {"type": "text", "text": "我认为这是"},
            {"type": "text", "text": "一次暴力破解"},
            {"type": "tool_use", "id": "toolu_9", "name": "query_asset", "input": {"id": "a-1"}}
        ],
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 50, "output_tokens": 12,
            "cache_creation_input_tokens": 20, "cache_read_input_tokens": 8}
    });
    let resp = from_anthropic_response(&raw).unwrap_or_else(|e| panic!("{e}"));
    eq!(resp.text_content(), "我认为这是一次暴力破解");
    eq!(resp.finish_reason, FinishReason::ToolCalls);
    eq!(resp.tool_calls().len(), 1);
    eq!(resp.tool_calls()[0].id, "toolu_9");
    eq!(resp.tool_calls()[0].arguments, json!({"id": "a-1"}));
    eq!(
        resp.usage,
        Usage {
            prompt_tokens: 78,
            completion_tokens: 12,
            cached_tokens: 8,
            cache_write_tokens: 20,
            cache_write_1h_tokens: 0
        }
    );
}

#[test]
pub(crate) fn anthropic_response_rejects_malformed() {
    assert!(from_anthropic_response(&json!({"type": "error"})).is_err());
}

#[test]
pub(crate) fn anthropic_stream_events() {
    let start = from_anthropic_event(&json!({
        "type": "message_start",
        "message": {"usage": {"input_tokens": 30, "cache_creation_input_tokens": 20,
            "cache_creation":{"ephemeral_5m_input_tokens":10,"ephemeral_1h_input_tokens":10},
            "cache_read_input_tokens": 8, "output_tokens": 0}}
    }));
    eq!(
        start.usage,
        Some(Usage {
            prompt_tokens: 58,
            completion_tokens: 0,
            cached_tokens: 8,
            cache_write_tokens: 20,
            cache_write_1h_tokens: 10
        })
    );

    let block = from_anthropic_event(&json!({
        "type": "content_block_start", "index": 1,
        "content_block": {"type": "tool_use", "id": "toolu_1", "name": "query_asset"}
    }));
    eq!(block.delta.tool_calls[0].index, 1);
    eq!(block.delta.tool_calls[0].id.as_deref(), Some("toolu_1"));

    let text = from_anthropic_event(&json!({
        "type": "content_block_delta", "index": 0,
        "delta": {"type": "text_delta", "text": "恶意"}
    }));
    eq!(text.delta.content, "恶意");

    let json_delta = from_anthropic_event(&json!({
        "type": "content_block_delta", "index": 1,
        "delta": {"type": "input_json_delta", "partial_json": "{\"id\":"}
    }));
    eq!(json_delta.delta.tool_calls[0].arguments_fragment, "{\"id\":");

    let end = from_anthropic_event(&json!({
        "type": "message_delta", "delta": {"stop_reason": "max_tokens"},
        "usage": {"output_tokens": 20}
    }));
    eq!(end.finish_reason, Some(FinishReason::Length));
    eq!(end.usage, Some(Usage::new(0, 20, 0)));

    let ping = from_anthropic_event(&json!({"type": "ping"}));
    assert!(ping.delta.is_empty());
    assert!(ping.finish_reason.is_none());
}

// ---- Gemini ----------------------------------------------------------

#[test]
pub(crate) fn gemini_body_hoists_system_and_config() {
    let body = to_gemini_body(&gateway_request());
    eq!(body["systemInstruction"]["parts"][0]["text"], json!("你是 AIGuardFabric 的安全分析师"));
    eq!(body["generationConfig"]["maxOutputTokens"], json!(1024));
    eq!(body["generationConfig"]["responseMimeType"], json!("application/json"));
    let roles: Vec<&str> =
        body["contents"].as_array().map(|a| a.iter().filter_map(|m| m["role"].as_str()).collect()).unwrap_or_default();
    eq!(roles, vec!["user", "model"]);
    eq!(body["tools"][0]["functionDeclarations"][0]["name"], json!("query_asset"));
}

#[test]
pub(crate) fn gemini_body_forwards_sampling_and_stop_sequences() {
    let mut request = ChatRequest::simple("gemini-test", "hello");
    request.top_p = Some(0.8);
    request.stop = vec!["END".into(), "STOP".into()];
    let body = to_gemini_body(&request);
    assert!((body["generationConfig"]["topP"].as_f64().unwrap_or_default() - 0.8).abs() < 1e-6);
    eq!(body["generationConfig"]["stopSequences"], json!(["END", "STOP"]));
    request.top_p = None;
    request.stop.clear();
    let default = to_gemini_body(&request);
    assert!(default["generationConfig"].get("topP").is_none());
    assert!(default["generationConfig"].get("stopSequences").is_none());
}

#[test]
pub(crate) fn gemini_body_function_call_and_response() {
    let req = ChatRequest {
        messages: vec![
            {
                let mut m = ChatMessage::assistant("");
                m.tool_calls.push(ToolCall::new("call_0", "query_asset", json!({"id": "a-1"})));
                m
            },
            ChatMessage::tool_result("query_asset", "{\"name\":\"db-01\"}"),
        ],
        ..ChatRequest::default()
    };
    let body = to_gemini_body(&req);
    eq!(body["contents"][0]["parts"][0]["functionCall"]["name"], json!("query_asset"));
    eq!(body["contents"][0]["parts"][0]["functionCall"]["args"], json!({"id": "a-1"}));
    eq!(body["contents"][1]["parts"][0]["functionResponse"]["name"], json!("query_asset"));
}

#[test]
pub(crate) fn gemini_image_part_requires_data_uri() {
    let req = ChatRequest {
        messages: vec![ChatMessage::multi(
            Role::User,
            vec![ContentPart::image("data:image/png;base64,QQ=="), ContentPart::image("https://example.com/a.png")],
        )],
        ..ChatRequest::default()
    };
    let body = to_gemini_body(&req);
    eq!(body["contents"][0]["parts"][0]["inlineData"]["mimeType"], json!("image/png"));
    eq!(body["contents"][0]["parts"][0]["inlineData"]["data"], json!("QQ=="));
    // 非 data URI 无法内联，被丢弃（该降级已在模块文档声明）
    assert!(body["contents"][0]["parts"][1].get("inlineData").is_none());
}

#[test]
pub(crate) fn gemini_response_maps_parts_and_usage() {
    let raw = json!({
        "candidates": [{
            "content": {"role": "model", "parts": [
                {"text": "判定为"},
                {"functionCall": {"name": "query_asset", "args": {"id": "a-2"}}}
            ]},
            "finishReason": "STOP"
        }],
        "usageMetadata": {"promptTokenCount": 12, "candidatesTokenCount": 7, "cachedContentTokenCount": 3},
        "modelVersion": "gemini-1.5-pro"
    });
    let resp = from_gemini_response(&raw).unwrap_or_else(|e| panic!("{e}"));
    eq!(resp.text_content(), "判定为");
    eq!(resp.model, "gemini-1.5-pro");
    eq!(resp.finish_reason, FinishReason::Stop);
    eq!(resp.tool_calls()[0].name, "query_asset");
    eq!(resp.usage, Usage::new(12, 7, 3));
}

#[test]
pub(crate) fn gemini_response_safety_finish_maps_to_content_filter() {
    let raw = json!({"candidates": [{"finishReason": "SAFETY"}]});
    let resp = from_gemini_response(&raw).unwrap_or_else(|e| panic!("{e}"));
    eq!(resp.finish_reason, FinishReason::ContentFilter);
}

#[test]
pub(crate) fn gemini_response_rejects_malformed() {
    assert!(from_gemini_response(&json!({"promptFeedback": {}})).is_err());
}

#[test]
pub(crate) fn gemini_chunk_maps_text_and_finish() {
    let c = from_gemini_chunk(&json!({
        "candidates": [{"content": {"parts": [{"text": "恶"}]}}],
        "usageMetadata": {"promptTokenCount": 5}
    }));
    eq!(c.delta.content, "恶");
    eq!(c.usage, Some(Usage::new(5, 0, 0)));

    let last = from_gemini_chunk(&json!({"candidates": [{"finishReason": "MAX_TOKENS"}]}));
    eq!(last.finish_reason, Some(FinishReason::Length));
}

// ---- SSE -------------------------------------------------------------

#[test]
pub(crate) fn sse_decoder_emits_complete_events() {
    let mut d = SseDecoder::new();
    let events = d.feed(b"data: {\"a\":1}\n\ndata: {\"b\":2}\n\n");
    eq!(events.len(), 2);
    eq!(events[0].data, "{\"a\":1}");
    eq!(events[1].data, "{\"b\":2}");
    eq!(d.pending(), 0);
}
