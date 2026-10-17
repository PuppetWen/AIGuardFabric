#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crate::{ChatMessage, ChatRequest, MessageContent, Role};
use agf_core::enums::DataClass;
use serde_json::{Value, json};

fn fixture() -> (ChatRequest, Value) {
    let raw = json!({"model":"owned-model","temperature":0,"max_tokens":100,"metadata":{"purpose":"owned"},"messages":[
        {"role":"system","content":"fixed instructions"},{"role":"user","content":"approved plain query"}]});
    (serde_json::from_value(raw.clone()).unwrap(), raw)
}

#[test]
fn only_user_text_varies_and_all_fixed_parameters_and_systems_remain_exact() {
    let (mut request, mut raw) = fixture();
    let first = inspect_request(&request, &raw, DataClass::Public, false).unwrap();
    assert_eq!(first.user_text(), "approved plain query");
    request.messages[1].content = MessageContent::Text("approved paraphrase".into());
    raw["messages"][1]["content"] = json!("approved paraphrase");
    let changed = inspect_request(&request, &raw, DataClass::Public, false).unwrap();
    assert_eq!(first.fixed_request(), changed.fixed_request());
    request.max_tokens = Some(101);
    assert_ne!(
        first.fixed_request(),
        inspect_request(&request, &raw, DataClass::Public, false).unwrap().fixed_request()
    );
    request.messages[0].content = MessageContent::Text("new fixed instructions".into());
    raw["messages"][0]["content"] = json!("new fixed instructions");
    assert_ne!(
        first.fixed_request(),
        inspect_request(&request, &raw, DataClass::Public, false).unwrap().fixed_request()
    );
}

#[test]
fn unknown_top_level_and_message_fields_cannot_disappear_into_a_semantic_hit() {
    for name in ["seed", "reasoning", "thinking", "cache_control", "unknown"] {
        let (request, mut raw) = fixture();
        raw[name] = json!(true);
        assert!(inspect_request(&request, &raw, DataClass::Public, false).is_none());
    }
    let (request, mut raw) = fixture();
    raw["messages"][0]["private_extension"] = json!("value");
    assert!(inspect_request(&request, &raw, DataClass::Public, false).is_none());
}

#[test]
fn missing_temperature_stream_tools_multiturn_rich_and_confidential_bypass() {
    let (mut request, raw) = fixture();
    request.temperature = None;
    assert!(inspect_request(&request, &raw, DataClass::Public, false).is_none());
    let (mut request, raw) = fixture();
    request.stream = true;
    assert!(inspect_request(&request, &raw, DataClass::Public, false).is_none());
    let (mut request, raw) = fixture();
    request.tool_choice = Some(json!("none"));
    assert!(inspect_request(&request, &raw, DataClass::Public, false).is_none());
    let (mut request, raw) = fixture();
    request.messages.push(ChatMessage {
        role: Role::Assistant,
        content: MessageContent::Text("previous".into()),
        tool_calls: vec![],
        tool_call_id: None,
        name: None,
    });
    assert!(inspect_request(&request, &raw, DataClass::Public, false).is_none());
    let (mut request, raw) = fixture();
    request.messages[1].content = MessageContent::Parts(vec![]);
    assert!(inspect_request(&request, &raw, DataClass::Public, false).is_none());
    let (request, raw) = fixture();
    for class in [DataClass::Confidential, DataClass::Restricted] {
        assert!(inspect_request(&request, &raw, class, true).is_none());
    }
    assert!(inspect_request(&request, &raw, DataClass::Internal, false).is_none());
    assert!(inspect_request(&request, &raw, DataClass::Internal, true).is_some());
}

#[test]
fn utf8_input_and_combined_system_bound_count_encoded_bytes() {
    let (mut request, mut raw) = fixture();
    let text = "中".repeat(2731);
    request.messages[1].content = MessageContent::Text(text.clone());
    raw["messages"][1]["content"] = json!(text);
    assert!(inspect_request(&request, &raw, DataClass::Public, false).is_none());
    let (mut request, mut raw) = fixture();
    let text = "s".repeat(16 * 1024);
    request.messages[0].content = MessageContent::Text(text.clone());
    raw["messages"][0]["content"] = json!(text);
    assert!(inspect_request(&request, &raw, DataClass::Public, false).is_none());
}
