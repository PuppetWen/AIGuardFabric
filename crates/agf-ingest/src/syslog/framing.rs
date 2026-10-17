//! TCP 分帧策略判定：octet-counting 与 non-transparent framing 的识别与切分结果。

use super::*;

/// TCP 传输分帧方式（RFC6587）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Framing {
    /// octet-counting：`<长度> SP <报文>`。
    OctetCounting,
    /// non-transparent framing：以 `\n`（可带 `\r`）分隔。
    NonTransparent,
}

impl Framing {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::OctetCounting => "octet-counting",
            Self::NonTransparent => "non-transparent",
        }
    }
}

/// 一次流式切分的结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FrameSplit {
    /// 已完整的帧。
    pub frames: Vec<Vec<u8>>,
    /// 已消费的字节数（调用方据此截断缓冲区）。
    pub consumed: usize,
    /// 是否存在超长/畸形帧被丢弃。
    pub dropped: usize,
}

/// Syslog TCP 分帧工具（纯函数，无 I/O，便于单测）。
#[derive(Debug, Clone, Copy, Default)]
pub struct SyslogFraming;

impl SyslogFraming {
    /// 依据缓冲区首字节判定分帧方式。
    ///
    /// 非透明分帧的报文必然以 `<` 开头，因此首字节为 ASCII 数字即 octet-counting。
    #[must_use]
    pub fn detect(buf: &[u8]) -> Framing {
        match buf.first() {
            Some(b) if b.is_ascii_digit() => Framing::OctetCounting,
            _ => Framing::NonTransparent,
        }
    }

    /// 切分缓冲区，返回完整帧与已消费字节数（不完整尾部保留给下次调用）。
    #[must_use]
    pub fn split(buf: &[u8], max_message_bytes: usize) -> FrameSplit {
        match Self::detect(buf) {
            Framing::OctetCounting => Self::split_octet_counting(buf, max_message_bytes),
            Framing::NonTransparent => Self::split_non_transparent(buf, max_message_bytes),
        }
    }

    /// octet-counting 切分。
    #[must_use]
    pub fn split_octet_counting(buf: &[u8], max_message_bytes: usize) -> FrameSplit {
        let mut out = FrameSplit::default();
        let mut pos = 0_usize;
        while pos < buf.len() {
            let Some(space_rel) = buf.get(pos..).and_then(|s| s.iter().position(|b| *b == b' ')) else {
                break; // 长度行尚未收全
            };
            let header = buf.get(pos..pos + space_rel).unwrap_or_default();
            if header.is_empty() || header.len() > 10 || !header.iter().all(u8::is_ascii_digit) {
                // 畸形长度头：整段丢弃，避免解析器陷入死循环
                out.dropped += 1;
                out.consumed = buf.len();
                return out;
            }
            let len: usize = header.iter().fold(0_usize, |acc, b| acc * 10 + usize::from(b - b'0'));
            let body_start = pos + space_rel + 1;
            if len == 0 || len > max_message_bytes {
                out.dropped += 1;
                out.consumed = body_start;
                pos = body_start;
                continue;
            }
            let Some(body) = buf.get(body_start..body_start + len) else {
                break; // 帧体未收全
            };
            out.frames.push(body.to_vec());
            pos = body_start + len;
        }
        out.consumed = pos;
        out
    }

    /// non-transparent（换行分隔）切分。
    #[must_use]
    pub fn split_non_transparent(buf: &[u8], max_message_bytes: usize) -> FrameSplit {
        let mut out = FrameSplit::default();
        let mut start = 0_usize;
        while let Some(rel) = buf.get(start..).and_then(|s| s.iter().position(|b| *b == b'\n')) {
            let end = start + rel;
            let mut frame = buf.get(start..end).unwrap_or_default();
            if frame.last() == Some(&b'\r') {
                frame = frame.get(..frame.len() - 1).unwrap_or_default();
            }
            if !frame.is_empty() {
                if frame.len() > max_message_bytes {
                    out.dropped += 1;
                } else {
                    out.frames.push(frame.to_vec());
                }
            }
            start = end + 1;
        }
        out.consumed = start;
        out
    }

    /// 按 octet-counting 编码一帧（客户端/测试构造报文用）。
    #[must_use]
    pub fn encode_octet_counting(payload: &[u8]) -> Vec<u8> {
        let mut out = format!("{} ", payload.len()).into_bytes();
        out.extend_from_slice(payload);
        out
    }

    /// 按 non-transparent 编码一帧（追加 `\n`）。
    #[must_use]
    pub fn encode_non_transparent(payload: &[u8]) -> Vec<u8> {
        let mut out = payload.to_vec();
        out.push(b'\n');
        out
    }
}

// ---------------------------------------------------------------------------
// 监听器
// ---------------------------------------------------------------------------
