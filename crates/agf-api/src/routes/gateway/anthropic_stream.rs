//! Anthropic SSE event sequence. Tool arguments are buffered until a complete block exists.
use agf_aigw::wire::{FinishReason, StreamChunk, ToolCallDelta, Usage};
use axum::response::sse::Event;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) fn event(kind: &str, mut data: Value) -> Event {
    data["type"] = json!(kind);
    Event::default().event(kind).data(data.to_string())
}

#[derive(Default)]
pub(super) struct Encoder {
    started: bool,
    native: bool,
    stopped: bool,
    text_started: bool,
    tools: BTreeMap<u32, ToolCallDelta>,
    finish_reason: Option<FinishReason>,
    usage: Usage,
}

impl Encoder {
    pub(super) fn start(id: &str, model: &str) -> Event {
        event(
            "message_start",
            json!({"message":{"id":id,"type":"message","role":"assistant",
            "model":model,"content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":0,"output_tokens":0}}}),
        )
    }

    pub(super) fn chunk(&mut self, chunk: StreamChunk, id: &str, model: &str) -> Vec<Event> {
        let mut events = Vec::new();
        if let Some(raw) = chunk.anthropic_event {
            if let Some(kind) = raw["type"].as_str().map(str::to_owned) {
                self.started = true;
                self.native = true;
                self.stopped |= kind == "message_stop";
                events.push(event(&kind, raw));
            }
            return events;
        }
        if self.native {
            return events;
        }
        if !self.started {
            self.started = true;
            events.push(Self::start(id, model));
        }
        if !chunk.delta.content.is_empty() {
            if !self.text_started {
                self.text_started = true;
                events.push(event("content_block_start", json!({"index":0,"content_block":{"type":"text","text":""}})));
            }
            events.push(event(
                "content_block_delta",
                json!({"index":0,"delta":{"type":"text_delta","text":chunk.delta.content}}),
            ));
        }
        for call in chunk.delta.tool_calls {
            let entry = self.tools.entry(call.index).or_default();
            if call.id.is_some() {
                entry.id = call.id;
            }
            if call.name.is_some() {
                entry.name = call.name;
            }
            entry.arguments_fragment.push_str(&call.arguments_fragment);
        }
        if let Some(reason) = chunk.finish_reason {
            self.finish_reason = Some(reason);
        }
        if let Some(usage) = chunk.usage {
            self.usage.prompt_tokens = self.usage.prompt_tokens.max(usage.prompt_tokens);
            self.usage.completion_tokens = self.usage.completion_tokens.max(usage.completion_tokens);
        }
        events
    }

    pub(super) fn finish(&self, id: &str, model: &str) -> Vec<Event> {
        let mut events = Vec::new();
        if self.native {
            if !self.stopped {
                events.push(event("message_stop", json!({})));
            }
            return events;
        }
        if !self.started {
            events.push(Self::start(id, model));
        }
        if self.text_started {
            events.push(event("content_block_stop", json!({"index":0})));
        }
        for (index, call) in (usize::from(self.text_started)..).zip(self.tools.values()) {
            let args = if call.arguments_fragment.is_empty() { "{}" } else { &call.arguments_fragment };
            if call.id.is_none() || call.name.is_none() || serde_json::from_str::<Value>(args).is_err() {
                return vec![event(
                    "error",
                    json!({"error":{"type":"api_error","message":"上游返回了不完整的工具调用"}}),
                )];
            }
            events.push(event(
                "content_block_start",
                json!({"index":index,"content_block":{"type":"tool_use","id":call.id,"name":call.name,"input":{}}}),
            ));
            events.push(event(
                "content_block_delta",
                json!({"index":index,"delta":{"type":"input_json_delta","partial_json":args}}),
            ));
            events.push(event("content_block_stop", json!({"index":index})));
        }
        events.push(event("message_delta",json!({"delta":{"stop_reason":super::anthropic::stop_reason(self.finish_reason.unwrap_or(FinishReason::Stop)),
            "stop_sequence":null},"usage":{"input_tokens":self.usage.prompt_tokens,"output_tokens":self.usage.completion_tokens}})));
        events.push(event("message_stop", json!({})));
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_thinking_signature_and_context_delta_are_forwarded_once() {
        let mut encoder = Encoder::default();
        let source = [
            json!({"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant",
                "model":"claude","content":[],"usage":{"input_tokens":4,"output_tokens":0}}}),
            json!({"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}),
            json!({"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"reason"}}),
            json!({"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"signed"}}),
            json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":3},
                "context_management":{"applied_edits":[{"type":"clear_thinking_20251015"}]}}),
            json!({"type":"message_stop"}),
        ];
        let mut encoded = Vec::new();
        for raw in &source {
            let chunk = agf_aigw::convert::from_anthropic_event(raw);
            assert_eq!(chunk.anthropic_event.as_ref(), Some(raw));
            encoded.extend(encoder.chunk(chunk, "synthetic", "routed"));
        }
        encoded.extend(encoder.finish("synthetic", "routed"));
        assert_eq!(encoded.len(), source.len());
    }
}
