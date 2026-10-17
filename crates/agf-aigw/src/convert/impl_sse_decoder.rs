//! 由 `convert.rs` 拆分：`impl_SseDecoder`/`take_line` 等 2 项（纯搬移，逻辑不变）。
use super::*;

impl SseDecoder {
    /// 新建。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 喂入一段字节，返回本次可完整产出的事件。
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<SseEvent> {
        self.buffer.extend_from_slice(bytes);
        let mut out = Vec::new();
        while let Some((line, consumed)) = take_line(&self.buffer) {
            self.buffer.drain(..consumed);
            if let Some(ev) = self.consume_line(&line) {
                out.push(ev);
            }
        }
        out
    }

    /// 流结束时冲刷缓冲区（处理"最后一个事件没有以空行结尾"的宽容情形）。
    pub fn finish(&mut self) -> Vec<SseEvent> {
        let mut out = Vec::new();
        if !self.buffer.is_empty() {
            let raw = std::mem::take(&mut self.buffer);
            let line = String::from_utf8_lossy(&raw).trim_end_matches(['\r', '\n']).to_string();
            if let Some(ev) = self.consume_line(&line) {
                out.push(ev);
            }
        }
        if let Some(ev) = self.flush_event() {
            out.push(ev);
        }
        out
    }

    /// 缓冲区中尚未成形的内容（排障用）。
    #[must_use]
    pub fn pending(&self) -> usize {
        self.buffer.len()
    }

    pub(crate) fn consume_line(&mut self, line: &str) -> Option<SseEvent> {
        if line.is_empty() {
            // 空行 = 事件结束
            return self.flush_event();
        }
        if let Some(rest) = line.strip_prefix("event:") {
            self.event = Some(rest.trim().to_string());
            return None;
        }
        if let Some(rest) = line.strip_prefix("data:") {
            // 规范：冒号后的第一个空格要去掉，其余保留
            let value = rest.strip_prefix(' ').unwrap_or(rest);
            self.data_lines.push(value.to_string());
            return None;
        }
        // `:` 注释、`id:`、`retry:` 等字段一律忽略
        None
    }

    pub(crate) fn flush_event(&mut self) -> Option<SseEvent> {
        if self.data_lines.is_empty() && self.event.is_none() {
            return None;
        }
        let data = self.data_lines.join("\n");
        let event = self.event.take();
        self.data_lines.clear();
        // 只有 event: 没有 data: 的事件对解析无意义，直接丢弃
        if data.is_empty() {
            return None;
        }
        Some(SseEvent { event, data })
    }
}

/// 从缓冲区取出完整的一行（返回行内容与"已消费字节数"，含换行符）。
pub(crate) fn take_line(buffer: &[u8]) -> Option<(String, usize)> {
    let pos = buffer.iter().position(|b| *b == b'\n')?;
    // 注意：`\r\n` 时 `pos` 指向 `\n`，`\r` 由 trim 处理
    let line = String::from_utf8_lossy(&buffer[..pos]).trim_end_matches('\r').to_string();
    Some((line, pos + 1))
}
