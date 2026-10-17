//! Bounded request-scoped MCP framing. No GET stream, resume or server-request execution.
use agf_core::error::{DomainError, DomainResult};
use serde_json::Value;

pub(super) const LIMIT: usize = 64 * 1024;
pub(super) fn invalid() -> DomainError {
    DomainError::DependencyUnavailable {
        dependency: "mcp-target".into(),
        cause: "MCP response was unavailable, unsupported or invalid; no request is replayed".into(),
    }
}
pub(super) fn result(frame: Value, expected: u64) -> DomainResult<Value> {
    if frame["jsonrpc"] != "2.0"
        || frame["id"] != expected
        || frame.get("method").is_some()
        || frame.get("error").is_some()
        || !frame["result"].is_object()
    {
        return Err(invalid());
    }
    Ok(frame)
}
pub(super) struct Frames {
    buffer: Vec<u8>,
    data: Vec<u8>,
    events: usize,
    skip_lf: bool,
}
impl Frames {
    pub(super) fn new() -> Self {
        Self { buffer: Vec::new(), data: Vec::new(), events: 0, skip_lf: false }
    }
    pub(super) fn push(&mut self, chunk: &[u8], expected: u64) -> DomainResult<Option<Value>> {
        self.buffer.extend_from_slice(chunk);
        let mut final_response = None;
        loop {
            if self.skip_lf {
                if self.buffer.is_empty() {
                    break;
                }
                if self.buffer[0] == b'\n' {
                    self.buffer.remove(0);
                }
                self.skip_lf = false;
            }
            let Some(end) = self.buffer.iter().position(|byte| matches!(byte, b'\r' | b'\n')) else {
                break;
            };
            let mut line: Vec<_> = self.buffer.drain(..=end).collect();
            self.skip_lf = line.pop() == Some(b'\r');
            if line.is_empty() {
                if self.data.is_empty() {
                    continue;
                }
                self.events = self.events.checked_add(1).ok_or_else(invalid)?;
                if self.events > 128 {
                    return Err(invalid());
                }
                let frame: Value = serde_json::from_slice(&self.data).map_err(|_| invalid())?;
                self.data.clear();
                if frame.get("method").is_some() {
                    if frame["jsonrpc"] != "2.0"
                        || frame.get("id").is_some()
                        || !matches!(frame["method"].as_str(), Some("notifications/progress" | "notifications/message"))
                    {
                        return Err(invalid());
                    }
                } else {
                    if final_response.is_some() {
                        return Err(invalid());
                    }
                    final_response = Some(result(frame, expected)?);
                }
            } else if let Some(value) = line.strip_prefix(b"data:") {
                let value = value.strip_prefix(b" ").unwrap_or(value);
                if !self.data.is_empty() {
                    self.data.push(b'\n');
                }
                self.data.extend_from_slice(value);
            } else if !line.starts_with(b":")
                && !line.starts_with(b"event:")
                && !line.starts_with(b"id:")
                && !line.starts_with(b"retry:")
            {
                return Err(invalid());
            }
            if self.data.len() > LIMIT {
                return Err(invalid());
            }
        }
        if self.buffer.len() > LIMIT {
            return Err(invalid());
        }
        Ok(final_response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn split_crlf_comments_notifications_and_one_final_are_not_business_retries() -> DomainResult<()> {
        let mut frames = Frames::new();
        assert!(
            frames
                .push(b":keepalive\r\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\r\n\r\n", 1)?
                .is_none()
        );
        assert!(frames.push(b"data: {\"jsonrpc\":\"2.0\",\"id\":1,", 1)?.is_none());
        assert!(frames.push(b"\"result\":{\"tools\":[]}}\r\n\r\n", 1)?.is_some());
        Ok(())
    }
    #[test]
    fn server_requests_wrong_id_and_duplicate_final_are_rejected() {
        for bytes in [
            b"data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n\n".as_slice(),
            b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"sampling/createMessage\"}\n\n".as_slice(),
            b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n".as_slice(),
        ] { assert!(Frames::new().push(bytes,1).is_err()); }
    }
    #[test]
    fn cr_only_and_split_crlf_are_framed_and_incomplete_eof_is_not_success() -> DomainResult<()> {
        let mut frames = Frames::new();
        assert!(frames.push(b":comment\r", 1)?.is_none());
        assert!(frames.push(b"\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\r", 1)?.is_none());
        assert!(frames.push(b"\r", 1)?.is_some());
        assert!(Frames::new().push(b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n", 1)?.is_none());
        Ok(())
    }
}
