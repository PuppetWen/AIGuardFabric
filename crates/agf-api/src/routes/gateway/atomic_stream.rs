//! An intentional protocol terminator requires proof from the committed delivery owner.
use super::protocol::{Protocol, StreamEncoder};
use crate::gateway_settlement::{AdmittedDeliveryStream, AdmittedStream, Delivery};
use agf_aigw::wire::StreamChunk;
use agf_core::ids::Id;
use axum::response::{
    IntoResponse, Response, Sse,
    sse::{Event, KeepAlive},
};
use futures::StreamExt;
use std::{collections::VecDeque, convert::Infallible};

struct Output {
    chunks: AdmittedDeliveryStream,
    encoder: StreamEncoder,
    pending: VecDeque<Event>,
    tail: Vec<StreamChunk>,
    tail_bytes: usize,
    finished: bool,
}

impl Output {
    fn failed(&mut self) {
        self.tail.clear();
        self.pending.push_back(
            self.encoder.error("Model stream ended without confirmed delivery. Read its original attempt UUID."),
        );
        self.finished = true;
    }

    fn chunk(&mut self, chunk: StreamChunk) {
        if !self.tail.is_empty() || terminal(&chunk) {
            let bytes = serde_json::to_vec(&(&chunk, &chunk.anthropic_event)).map_or(usize::MAX, |bytes| bytes.len());
            self.tail_bytes = self.tail_bytes.saturating_add(bytes);
            if self.tail_bytes > 4 * 1024 * 1024 {
                self.failed();
            } else {
                self.tail.push(chunk);
            }
        } else {
            self.pending.extend(self.encoder.chunk(chunk));
        }
    }
}

fn terminal(chunk: &StreamChunk) -> bool {
    chunk.finish_reason.is_some()
        || chunk.usage.is_some()
        || chunk.anthropic_event.as_ref().and_then(|value| value["type"].as_str()) == Some("message_stop")
}

pub(super) fn response(protocol: Protocol, stream: AdmittedStream) -> Response {
    let (model, mocked, chunks) = stream.into_parts();
    let encoder = StreamEncoder::new(protocol, format!("chatcmpl-{}", Id::new()), model);
    let output = futures::stream::unfold(
        Output { chunks, encoder, pending: VecDeque::new(), tail: Vec::new(), tail_bytes: 0, finished: false },
        |mut state| async move {
            loop {
                if let Some(event) = state.pending.pop_front() {
                    return Some((Ok::<_, Infallible>(event), state));
                }
                if state.finished {
                    return None;
                }
                match state.chunks.next().await {
                    Some(Ok(Delivery::Chunk(chunk))) => state.chunk(chunk),
                    Some(Ok(Delivery::Committed(_proof))) => {
                        for chunk in state.tail.drain(..) {
                            state.pending.extend(state.encoder.chunk(chunk));
                        }
                        state.pending.extend(state.encoder.finish());
                        state.finished = true;
                    }
                    Some(Err(_)) | None => state.failed(),
                }
            }
        },
    );
    let mut response = Sse::new(output).keep_alive(KeepAlive::default()).into_response();
    response
        .headers_mut()
        .insert("x-agf-mocked", axum::http::HeaderValue::from_static(if mocked { "true" } else { "false" }));
    response
}

#[cfg(test)]
mod tests;
