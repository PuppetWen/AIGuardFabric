use super::{anthropic, anthropic_stream, wire};
use agf_aigw::wire::{ChatResponse, StreamChunk};
use axum::response::sse::Event;
use serde_json::{Value, json};

#[derive(Clone, Copy)]
pub(super) enum Protocol {
    OpenAi,
    Anthropic,
}
impl Protocol {
    pub(super) fn response(self, response: ChatResponse) -> Value {
        match self {
            Self::OpenAi => wire::response(response),
            Self::Anthropic => anthropic::response(response),
        }
    }
}

pub(super) struct StreamEncoder {
    protocol: Protocol,
    id: String,
    model: String,
    anthropic: anthropic_stream::Encoder,
}
impl StreamEncoder {
    pub(super) fn new(protocol: Protocol, id: String, model: String) -> Self {
        Self { protocol, id, model, anthropic: anthropic_stream::Encoder::default() }
    }
    pub(super) fn chunk(&mut self, chunk: StreamChunk) -> Vec<Event> {
        match self.protocol {
            Protocol::OpenAi => vec![Event::default().data(wire::chunk(&self.id, &self.model, chunk).to_string())],
            Protocol::Anthropic => self.anthropic.chunk(chunk, &self.id, &self.model),
        }
    }
    pub(super) fn error(&self, message: &str) -> Event {
        let body = json!({"error":{"message":message,"type":"api_error"}});
        match self.protocol {
            Protocol::OpenAi => Event::default().data(body.to_string()),
            Protocol::Anthropic => anthropic_stream::event("error", body),
        }
    }
    pub(super) fn finish(&self) -> Vec<Event> {
        match self.protocol {
            Protocol::OpenAi => vec![Event::default().data("[DONE]")],
            Protocol::Anthropic => self.anthropic.finish(&self.id, &self.model),
        }
    }
}
