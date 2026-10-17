//! 由 `wire.rs` 拆分：`sample_request` 等 22 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn sample_request() -> ChatRequest {
    let mut req = ChatRequest::simple("gpt-4o", "分析这条告警");
    req.messages.insert(0, ChatMessage::system("你是安全分析师"));
    req.temperature = Some(0.0);
    req
}

#[test]
pub(crate) fn role_parse_accepts_aliases() {
    assert_eq!(Role::parse("HUMAN"), Ok(Role::User));
    assert_eq!(Role::parse("model"), Ok(Role::Assistant));
    assert_eq!(Role::parse("function"), Ok(Role::Tool));
    assert!(Role::parse("nobody").is_err());
}

#[test]
pub(crate) fn message_content_plain_text_and_parts() {
    let mut m = ChatMessage::multi(Role::User, vec![ContentPart::text("看图"), ContentPart::image("https://x/y.png")]);
    assert!(m.content.has_image());
    assert_eq!(m.content.as_plain_text(), "看图");
    m.content = MessageContent::text("纯文本");
    assert!(!m.content.has_image());
    assert_eq!(m.content.approx_chars(), 3);
    assert!(MessageContent::default().is_empty());
}

#[test]
pub(crate) fn system_prompt_joins_multiple_system_messages() {
    let mut req = sample_request();
    req.messages.insert(1, ChatMessage::system("第二条系统提示"));
    let sp = req.system_prompt().unwrap_or_default();
    assert!(sp.contains("安全分析师"));
    assert!(sp.contains("第二条系统提示"));
    assert_eq!(req.conversation().len(), 1);
}

#[test]
pub(crate) fn token_estimate_latin_is_chars_over_four() {
    let req = ChatRequest::simple("m", "abcdefgh");
    // 8 拉丁字符 → 2 token，+ 3 引导符 + 4 消息开销 = 9
    assert_eq!(req.estimate_prompt_tokens(), 9);
}

#[test]
pub(crate) fn token_estimate_cjk_is_denser_than_latin() {
    let cjk = ChatRequest::simple("m", "这是一段中文提示词");
    let latin = ChatRequest::simple("m", "abcdefghij");
    // 9 个汉字 → 6 token；10 个拉丁字符 → 2.5 → ceil
    assert_eq!(cjk.estimate_prompt_tokens(), 4 + 3 + 6);
    assert_eq!(latin.estimate_prompt_tokens(), 4 + 3 + 3);
    assert!(cjk.estimate_prompt_tokens() * 10 > latin.estimate_prompt_tokens() * 10, "同字符数下中文 token 必须更多");
}

#[test]
pub(crate) fn token_estimate_counts_tools() {
    let mut req = ChatRequest::simple("m", "hi");
    let base = req.estimate_prompt_tokens();
    req.tools.push(ToolDefinition::query("query_asset", "查询资产台账", serde_json::json!({"type": "object"})));
    assert!(req.estimate_prompt_tokens() > base);
}

#[test]
pub(crate) fn token_estimate_reserves_image_budget() {
    let mut req = ChatRequest::simple("m", "看图");
    let text_only = req.estimate_prompt_tokens();
    req.messages[0].content =
        MessageContent::parts(vec![ContentPart::text("看图"), ContentPart::image("data:image/png;base64,AA==")]);
    assert_eq!(req.estimate_prompt_tokens(), text_only + 4_784);
    req.messages[0].content = MessageContent::parts(vec![
        ContentPart::image("data:image/png;base64,AA=="),
        ContentPart::image("data:image/png;base64,AA=="),
    ]);
    assert_eq!(req.estimate_prompt_tokens(), 3 + 4 + 2 * 4_784);
}

#[test]
pub(crate) fn token_estimate_other_unicode_uses_half_rate() {
    // 4 个 emoji → 2 token
    let req = ChatRequest::simple("m", "🙂🙂🙂🙂");
    assert_eq!(req.estimate_prompt_tokens(), 4 + 3 + 2);
}

#[test]
pub(crate) fn cjk_classification() {
    assert!(is_cjk('中'));
    assert!(is_cjk('あ'));
    assert!(is_cjk('、'));
    assert!(!is_cjk('a'));
    assert!(!is_cjk('🙂'));
}

#[test]
pub(crate) fn fingerprint_is_stable() {
    let a = sample_request();
    let b = sample_request();
    assert_eq!(a.fingerprint(), b.fingerprint());
    assert_eq!(a.fingerprint().len(), 64);
}

#[test]
pub(crate) fn fingerprint_ignores_metadata_and_stream_flag() {
    let a = sample_request();
    let mut b = sample_request();
    b.metadata.insert("trace_id".into(), "xyz".into());
    b.stream = true;
    b.user = Some("u-1".into());
    assert_eq!(a.fingerprint(), b.fingerprint(), "元数据/传输方式不得影响指纹");
}

#[test]
pub(crate) fn fingerprint_is_sensitive_to_content() {
    let base = sample_request();

    let mut content_changed = sample_request();
    if let Some(m) = content_changed.messages.last_mut() {
        m.content = MessageContent::text("分析另一条告警");
    }
    assert_ne!(base.fingerprint(), content_changed.fingerprint());

    let mut temp_changed = sample_request();
    temp_changed.temperature = Some(0.7);
    assert_ne!(base.fingerprint(), temp_changed.fingerprint(), "温度变化必须改变指纹");

    let mut tools_changed = sample_request();
    tools_changed.tools.push(ToolDefinition::query("t", "d", serde_json::json!({})));
    assert_ne!(base.fingerprint(), tools_changed.fingerprint(), "工具变化必须改变指纹");

    let mut order_changed = sample_request();
    order_changed.messages.reverse();
    assert_ne!(base.fingerprint(), order_changed.fingerprint(), "消息顺序必须影响指纹");
    let mut shorter = base.clone();
    shorter.max_tokens = Some(1);
    assert_ne!(base.fingerprint(), shorter.fingerprint());
    let mut stopped = base.clone();
    stopped.stop.push("STOP".into());
    assert_ne!(base.fingerprint(), stopped.fingerprint());
    let mut selected = base.clone();
    selected.tool_choice = Some(serde_json::json!("none"));
    assert_ne!(base.fingerprint(), selected.fingerprint());
}

#[test]
pub(crate) fn request_capability_probes() {
    let mut req = sample_request();
    assert!(!req.needs_tools());
    assert!(!req.has_side_effecting_tools());
    req.tools.push(ToolDefinition::mutating("write_file", "写文件", serde_json::json!({})));
    assert!(req.needs_tools());
    assert!(req.has_side_effecting_tools());
}

#[test]
pub(crate) fn data_class_hint_parsing() {
    let mut req = sample_request();
    assert!(req.data_class_hint().is_none());
    req.metadata.insert("data_class".into(), "Restricted".into());
    assert_eq!(req.data_class_hint(), Some(DataClass::Restricted));
    req.metadata.insert("data_class".into(), "bogus".into());
    assert!(req.data_class_hint().is_none());
}

#[test]
pub(crate) fn usage_accumulates() {
    let mut u = Usage::new(10, 5, 2);
    u.accumulate(Usage::new(1, 1, 0));
    assert_eq!(u, Usage::new(11, 6, 2));
    assert_eq!(u.total(), 17);
    assert!(!u.is_empty());
    assert!(Usage::default().is_empty());
}

#[test]
pub(crate) fn finish_reason_mapping() {
    assert_eq!(FinishReason::from_openai("max_tokens"), FinishReason::Length);
    assert_eq!(FinishReason::from_openai("tool_use"), FinishReason::ToolCalls);
    assert_eq!(FinishReason::from_openai("SAFETY"), FinishReason::ContentFilter);
    assert_eq!(FinishReason::from_openai("weird"), FinishReason::Other);
    assert_eq!(FinishReason::ToolCalls.as_str(), "tool_calls");
}

#[test]
pub(crate) fn stream_accumulator_rebuilds_response() {
    let mut acc = StreamAccumulator::new();
    acc.push(&StreamChunk::text("你好"));
    acc.push(&StreamChunk::text("，世界"));
    let mut tool_chunk = StreamChunk::default();
    tool_chunk.delta.tool_calls.push(ToolCallDelta {
        index: 0,
        id: Some("call_1".into()),
        name: Some("query_asset".into()),
        arguments_fragment: "{\"id\":".into(),
    });
    acc.push(&tool_chunk);
    let mut tool_chunk2 = StreamChunk::default();
    tool_chunk2.delta.tool_calls.push(ToolCallDelta {
        index: 0,
        id: None,
        name: None,
        arguments_fragment: "\"a-1\"}".into(),
    });
    acc.push(&tool_chunk2);
    acc.push(&StreamChunk::finished(FinishReason::ToolCalls, Some(Usage::new(9, 4, 0))));
    assert_eq!(acc.content(), "你好，世界");
    assert_eq!(acc.usage(), Usage::new(9, 4, 0));
    assert_eq!(acc.finish_reason(), Some(FinishReason::ToolCalls));
    let resp = acc.finish("gpt-4o");
    assert_eq!(resp.tool_calls().len(), 1);
    assert_eq!(resp.tool_calls()[0].name, "query_asset");
    assert_eq!(resp.tool_calls()[0].arguments, serde_json::json!({"id": "a-1"}));
    assert_eq!(resp.finish_reason, FinishReason::ToolCalls);
}

#[test]
pub(crate) fn unparseable_tool_arguments_are_preserved() {
    let v = parse_arguments("not-json");
    assert_eq!(v, serde_json::Value::String("not-json".into()));
    assert_eq!(parse_arguments(""), serde_json::Value::Null);
    assert_eq!(parse_arguments("{\"a\":1}"), serde_json::json!({"a": 1}));
}

#[test]
pub(crate) fn content_part_helpers() {
    assert_eq!(ContentPart::text("abc").text_len(), 3);
    assert_eq!(ContentPart::image("u").text_len(), 256);
    assert_eq!(ImageDetail::High.as_str(), "high");
    assert!(ResponseFormat::JsonObject.requires_json());
    assert!(!ResponseFormat::Text.requires_json());
}

#[test]
pub(crate) fn chat_message_constructors() {
    let m = ChatMessage::tool_result("call_9", "结果");
    assert_eq!(m.role, Role::Tool);
    assert_eq!(m.tool_call_id.as_deref(), Some("call_9"));
    assert_eq!(ChatMessage::system("s").role, Role::System);
    assert_eq!(ChatMessage::assistant("a").role, Role::Assistant);
    let mut req = ChatRequest::default();
    req.push(ChatMessage::user("x"));
    assert_eq!(req.messages.len(), 1);
}

#[test]
pub(crate) fn response_text_helpers() {
    let r = ChatResponse::text("mock-analyst-1", "结论：恶意", Usage::new(3, 2, 0));
    assert_eq!(r.text_content(), "结论：恶意");
    assert_eq!(r.finish_reason, FinishReason::Stop);
    assert!(r.id.starts_with("agf-"));
    assert!(r.tool_calls().is_empty());
}

#[test]
pub(crate) fn chat_delta_emptiness() {
    assert!(ChatDelta::default().is_empty());
    assert!(!ChatDelta::text("x").is_empty());
    // 结束分片的 delta 是空的（只有 finish_reason），且被标记为 final
    assert!(StreamChunk::finished(FinishReason::Stop, None).delta.is_empty());
    assert!(StreamChunk::finished(FinishReason::Stop, None).is_final());
    assert!(!StreamChunk::text("a").is_final());
}
