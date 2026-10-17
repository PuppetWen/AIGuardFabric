//! Include native thinking and tool inputs when screening Anthropic output.
use crate::wire::{ChatResponse, MessageContent, StreamChunk};
use serde_json::Value;

pub(crate) fn native_response_view(response: &ChatResponse) -> Option<ChatResponse> {
    let raw = response.raw.as_ref()?;
    if raw.get("type").and_then(Value::as_str) != Some("message") {
        return None;
    }
    let blocks = raw.get("content")?.as_array()?;
    let mut text = String::new();
    for block in blocks {
        for field in ["text", "thinking"] {
            if let Some(value) = block.get(field).and_then(Value::as_str) {
                text.push_str(value);
                text.push('\n');
            }
        }
        if let Some(input) = block.get("input") {
            text.push_str(&input.to_string());
        }
    }
    let mut view = response.clone();
    view.message.content = MessageContent::text(text);
    Some(view)
}

pub(crate) fn native_stream_view(response: &ChatResponse, chunks: &[StreamChunk]) -> Option<ChatResponse> {
    if !chunks.iter().any(|chunk| chunk.anthropic_event.as_ref().is_some_and(|event| event["type"] == "message_start"))
    {
        return None;
    }
    let mut text = String::new();
    for event in chunks.iter().filter_map(|chunk| chunk.anthropic_event.as_ref()) {
        if let Some(delta) = event.get("delta") {
            for field in ["text", "thinking", "partial_json"] {
                if let Some(value) = delta.get(field).and_then(Value::as_str) {
                    text.push_str(value);
                }
            }
        }
        if let Some(input) = event.get("content_block").and_then(|block| block.get("input")) {
            text.push_str(&input.to_string());
        }
    }
    let mut view = response.clone();
    view.message.content = MessageContent::text(text);
    Some(view)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn screening_view_includes_private_thinking_and_tool_arguments() {
        let raw = json!({"type":"message","content":[{"type":"thinking","thinking":"secret"},
            {"type":"tool_use","input":{"path":"sensitive"}}]});
        let response = crate::convert::from_anthropic_response(&raw).unwrap();
        let view = native_response_view(&response).unwrap();
        assert!(view.text_content().contains("secret"));
        assert!(view.text_content().contains("sensitive"));
    }
}
