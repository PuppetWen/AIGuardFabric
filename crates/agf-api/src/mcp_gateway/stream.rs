//! Incremental SSE parsing. Every JSON-RPC data frame is checked before any payload reaches the client.
use super::{MAX_FRAME, cursor, forward::Context, protocol, sessions, usage};
use crate::runtime_quota::Lease;
use agf_core::ids::Id;
use axum::{
    body::{Body, Bytes},
    http::{HeaderMap, HeaderValue},
    response::Response,
};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    convert::Infallible,
    time::{Duration, Instant},
};

#[derive(Default)]
pub(super) struct Decoder {
    pending: Vec<u8>,
    lines: Vec<String>,
    size: usize,
    blocks: VecDeque<Vec<String>>,
    started: bool,
}
impl Decoder {
    pub(super) fn push(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        self.pending.extend_from_slice(bytes);
        while let Some(index) = self.pending.iter().position(|byte| matches!(*byte, b'\r' | b'\n')) {
            let cr = self.pending[index] == b'\r';
            if cr && index + 1 == self.pending.len() {
                break;
            }
            let line = std::str::from_utf8(&self.pending[..index]).map_err(|_| "MCP SSE contains invalid UTF-8")?;
            let line = if !self.started { line.trim_start_matches('\u{feff}') } else { line }.to_string();
            self.started = true;
            self.size += line.len();
            if self.size > MAX_FRAME {
                return Err("MCP SSE frame exceeds 1 MiB");
            }
            if line.is_empty() {
                self.blocks.push_back(std::mem::take(&mut self.lines));
                self.size = 0;
            } else {
                self.lines.push(line);
            }
            let consumed = index + 1 + usize::from(cr && self.pending.get(index + 1) == Some(&b'\n'));
            self.pending.drain(..consumed);
        }
        if self.pending.len() + self.size > MAX_FRAME {
            return Err("MCP SSE frame exceeds 1 MiB");
        }
        Ok(())
    }

    pub(super) fn take_block(&mut self) -> Option<Vec<String>> {
        self.blocks.pop_front()
    }
}

struct Stream {
    context: Context,
    upstream: reqwest::Response,
    lease: Option<Lease>,
    attempt: Option<usage::Attempt>,
    recovery: Option<(Id, u64)>,
    decoder: Decoder,
    done: bool,
    last_data: Instant,
    last_renewal: Instant,
}

pub(super) fn response(
    context: Context,
    upstream: reqwest::Response,
    lease: Option<Lease>,
    attempt: Option<usage::Attempt>,
    mut headers: HeaderMap,
    recovery: Option<(Id, u64)>,
) -> Response {
    let now = Instant::now();
    let state = Stream {
        context,
        upstream,
        lease,
        attempt,
        recovery,
        decoder: Decoder::default(),
        done: false,
        last_data: now,
        last_renewal: now,
    };
    let stream = futures::stream::unfold(state, |mut state| async move {
        if state.done {
            return None;
        }
        let chunk = match state.next().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => return None,
            Err(message) => {
                state.done = true;
                let frame =
                    json!({"jsonrpc":"2.0","id":state.context.request_id,"error":{"code":-32000,"message":message}});
                format!("event: message\ndata: {frame}\n\n")
            }
        };
        Some((Ok::<_, Infallible>(Bytes::from(chunk)), state))
    });
    headers.insert("content-type", HeaderValue::from_static("text/event-stream"));
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert("x-accel-buffering", HeaderValue::from_static("no"));
    let mut response = Response::new(Body::from_stream(stream));
    *response.headers_mut() = headers;
    response
}

impl Stream {
    async fn next(&mut self) -> Result<Option<String>, String> {
        loop {
            if self.last_renewal.elapsed() >= Duration::from_mins(1) {
                if let Some((session, version)) = self.recovery {
                    sessions::renew(
                        &self.context.state,
                        &self.context.principal,
                        self.context.endpoint_id,
                        version,
                        session,
                    )
                    .await
                    .map_err(|_| "MCP session expired while the stream was active".to_string())?;
                }
                if let Some(lease) = &self.lease {
                    lease.renew().await.map_err(|error| error.to_string())?;
                }
                if let Some(sample) = &self.attempt {
                    sample.renew().await.map_err(|error| error.to_string())?;
                }
                self.last_renewal = Instant::now();
            }
            if let Some(block) = self.decoder.blocks.pop_front() {
                return self.block(block).await.map(Some);
            }
            let remaining = self.context.idle.saturating_sub(self.last_data.elapsed());
            if remaining.is_zero() {
                return Err("MCP upstream SSE exceeded the configured idle timeout".into());
            }
            match tokio::time::timeout(remaining.min(Duration::from_mins(1)), self.upstream.chunk()).await {
                Ok(Ok(Some(chunk))) => {
                    self.last_data = Instant::now();
                    if let Err(message) = self.decoder.push(&chunk) {
                        self.fail_visible_frame().await?;
                        return Err(message.into());
                    }
                }
                Ok(Ok(None)) => {
                    if !self.context.request_id.is_null() {
                        return Err("MCP upstream closed before returning the final JSON-RPC response".into());
                    }
                    self.done = true;
                    return Ok(None);
                }
                Ok(Err(_)) => return Err("MCP upstream SSE connection failed; the tool call was not retried".into()),
                Err(_) => return Ok(Some(": keepalive\n\n".into())),
            }
        }
    }

    async fn block(&mut self, lines: Vec<String>) -> Result<String, String> {
        let mut data = Vec::new();
        let mut event_id = None;
        let mut retry = None;
        for line in lines {
            let (field, value) = line.split_once(':').unwrap_or((&line, ""));
            let value = value.strip_prefix(' ').unwrap_or(value);
            match field {
                "data" => data.push(value.to_string()),
                "id" if !value.contains('\0') => event_id = Some(value.to_string()),
                "retry" if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => {
                    retry = Some(value.to_string());
                }
                _ => {}
            }
        }
        if data.iter().all(String::is_empty) {
            return Ok(self
                .client_event_id(event_id)?
                .map_or_else(|| ": keepalive\n\n".into(), |id| format!("id: {id}\n\n")));
        }
        let frame: Value = match serde_json::from_str(&data.join("\n")) {
            Ok(frame) => frame,
            Err(_) => {
                self.fail_visible_frame().await?;
                return Err("MCP SSE data is not a JSON-RPC message".into());
            }
        };
        if !protocol::valid_frame(&frame, false) {
            self.fail_visible_frame().await?;
            return Err("MCP SSE contains an invalid JSON-RPC message".into());
        }
        let is_response = frame.get("method").is_none();
        if self.context.modern
            && !is_response
            && !frame["method"].as_str().is_some_and(|m| m.starts_with("notifications/"))
        {
            self.fail_visible_frame().await?;
            return Err("This MCP protocol version requires server input requests inside MRTR results".into());
        }
        if is_response && !self.context.request_id.is_null() && frame["id"] != self.context.request_id {
            self.fail_visible_frame().await?;
            return Err("MCP SSE response ID does not match the request".into());
        }
        let outcome = usage::response_outcome(&frame);
        let checked = self.context.inspect(frame, true).await;
        if is_response && !self.context.request_id.is_null() {
            if let Some(sample) = self.attempt.take() {
                sample
                    .finish(if checked.is_ok() { outcome } else { usage::Outcome::Failed })
                    .await
                    .map_err(|error| error.to_string())?;
            }
            if let Some(lease) = self.lease.take() {
                lease.finish(None).await.map_err(|error| error.to_string())?;
            }
            self.done = true;
        }
        let checked = checked.map_err(|error| error.to_string())?;
        let mut result = String::new();
        if !self.context.modern {
            if let Some(id) = self.client_event_id(event_id)? {
                result.push_str(&format!("id: {id}\n"));
            }
            if let Some(retry) = retry {
                result.push_str(&format!("retry: {retry}\n"));
            }
        }
        result.push_str(&format!("event: message\ndata: {checked}\n\n"));
        Ok(result)
    }

    async fn fail_visible_frame(&mut self) -> Result<(), String> {
        // A visible frame failed validation; only an unconfirmed disconnect is unknown.
        if let Some(sample) = self.attempt.take() {
            sample.finish(usage::Outcome::Failed).await.map_err(|error| error.to_string())?;
        }
        if let Some(lease) = self.lease.take() {
            lease.finish(None).await.map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    fn client_event_id(&self, upstream: Option<String>) -> Result<Option<String>, String> {
        if self.context.modern {
            return Ok(None);
        }
        let Some(upstream) = upstream else { return Ok(None) };
        // An empty or malformed upstream ID resets the browser's SSE cursor. Such values
        // cannot be used as HTTP headers and must never be offered for recovery.
        if upstream.is_empty() || upstream.len() > 512 || !upstream.bytes().all(|byte| (32..=126).contains(&byte)) {
            return Ok(Some(String::new()));
        }
        let Some((session, version)) = self.recovery else { return Ok(None) };
        let id = cursor::seal(
            &self.context.state,
            &self.context.principal,
            self.context.endpoint_id,
            version,
            session,
            &upstream,
        )
        .map_err(|_| "MCP event cursor could not be issued".to_string())?;
        Ok(Some(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chunk_boundaries_crlf_bom_multiline_and_limits() {
        let raw = "\u{feff}: ping\r\n\r\nevent: message\ndata: {\ndata: \"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"text\":\"中文\"}}\n\n";
        let mut decoder = Decoder::default();
        for byte in raw.as_bytes() {
            decoder.push(&[*byte]).unwrap();
        }
        assert_eq!(decoder.blocks.len(), 2);
        assert_eq!(decoder.blocks[1].len(), 3);
        assert!(decoder.push(&vec![b'x'; MAX_FRAME + 1]).is_err());
    }
}
