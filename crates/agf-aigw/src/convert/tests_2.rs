//! 由 `convert.rs` 拆分：`sse_decoder_handles_split_across_boundaries` 等 12 个函数（纯搬移，逻辑不变）。
use super::*;

/// 经典 bug：把 SSE 流按任意字节切分喂入，必须仍然只产出完整事件。
#[test]
pub(crate) fn sse_decoder_handles_split_across_boundaries() {
    let payload = b"data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\ndata: [DONE]\n\n";
    // 逐字节喂入（最严苛的切分）
    let mut d = SseDecoder::new();
    let mut events = Vec::new();
    for b in payload {
        events.extend(d.feed(&[*b]));
    }
    eq!(events.len(), 2);
    eq!(events[0].data, "{\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}");
    assert!(events[1].is_done());

    // 再按固定窗口切分（模拟 TCP 分段），结果必须一致
    for window in [1_usize, 2, 3, 5, 7, 11, 13, 17, 29] {
        let mut d = SseDecoder::new();
        let mut events = Vec::new();
        for chunk in payload.chunks(window) {
            events.extend(d.feed(chunk));
        }
        eq!(events.len(), 2, "窗口 {window} 事件数不一致");
        eq!(events[1].is_done(), true);
    }
}

#[test]
pub(crate) fn sse_decoder_partial_line_is_not_lost() {
    let mut d = SseDecoder::new();
    let first = d.feed(b"data: {\"par");
    assert!(first.is_empty(), "半个事件不得产出");
    eq!(d.pending(), 11, "半行必须留在缓冲区，不得丢弃");
    let rest = d.feed(b"tial\":true}\n\n");
    eq!(rest.len(), 1);
    let value = rest[0].json().unwrap_or_else(|e| panic!("{e}"));
    eq!(value["partial"], json!(true));
}

#[test]
pub(crate) fn sse_decoder_multiline_data_joined_with_newline() {
    let mut d = SseDecoder::new();
    let events = d.feed(b"data: line1\ndata: line2\ndata: line3\n\n");
    eq!(events.len(), 1);
    eq!(events[0].data, "line1\nline2\nline3");
}

#[test]
pub(crate) fn sse_decoder_handles_crlf() {
    let mut d = SseDecoder::new();
    let events = d.feed(b"event: message_start\r\ndata: {\"type\":\"message_start\"}\r\n\r\n");
    eq!(events.len(), 1);
    eq!(events[0].event.as_deref(), Some("message_start"));
    eq!(events[0].data, "{\"type\":\"message_start\"}");
    eq!(d.pending(), 0, "CRLF 必须被完整消费");
}

#[test]
pub(crate) fn sse_decoder_ignores_comments_and_unknown_fields() {
    let mut d = SseDecoder::new();
    let events = d.feed(b": keep-alive\nid: 42\nretry: 1000\ndata: payload\n\n");
    eq!(events.len(), 1);
    eq!(events[0].data, "payload");
    eq!(events[0].event, None);
}

#[test]
pub(crate) fn sse_decoder_event_field_is_scoped_to_one_event() {
    let mut d = SseDecoder::new();
    let events = d.feed(b"event: a\ndata: 1\n\ndata: 2\n\n");
    eq!(events.len(), 2);
    eq!(events[0].event.as_deref(), Some("a"));
    eq!(events[1].event, None, "event 字段不得跨事件泄漏");
}

#[test]
pub(crate) fn sse_decoder_finish_flushes_trailing_event_without_blank_line() {
    let mut d = SseDecoder::new();
    assert!(d.feed(b"data: [DONE]\n").is_empty(), "无空行时事件未成形");
    let tail = d.finish();
    eq!(tail.len(), 1);
    assert!(tail[0].is_done());
}

#[test]
pub(crate) fn sse_decoder_drops_event_without_data() {
    let mut d = SseDecoder::new();
    let events = d.feed(b"event: ping\n\n");
    assert!(events.is_empty(), "只有 event 没有 data 的事件被丢弃");
}

#[test]
pub(crate) fn sse_decoder_strips_single_space_after_colon() {
    let mut d = SseDecoder::new();
    let events = d.feed(b"data:  two-spaces\n\n");
    eq!(events[0].data, " two-spaces", "只去掉第一个空格");
}

#[test]
pub(crate) fn sse_decoder_survives_utf8_split_in_the_middle_of_a_multibyte_char() {
    // "恶意" 的 UTF-8 字节被切成两半
    let full = "data: 恶意\n\n".as_bytes().to_vec();
    let cut = full.len() - 3; // 切在最后一个汉字中间
    let mut d = SseDecoder::new();
    let mut events = d.feed(&full[..cut]);
    assert!(events.is_empty());
    events.extend(d.feed(&full[cut..]));
    eq!(events.len(), 1);
    eq!(events[0].data, "恶意");
}

#[test]
pub(crate) fn sse_event_json_parse_error_is_reported() {
    let mut d = SseDecoder::new();
    let events = d.feed(b"data: not-json\n\n");
    assert!(events[0].json().is_err());
    assert!(SseEvent::default().json().is_err());
}

#[test]
pub(crate) fn sse_decoder_reset_between_conversations() {
    let mut a = SseDecoder::new();
    let _ = a.feed(b"data: leftover");
    let mut b = SseDecoder::new();
    eq!(b.pending(), 0);
    let ev = b.feed(b"data: fresh\n\n");
    eq!(ev[0].data, "fresh");
}
