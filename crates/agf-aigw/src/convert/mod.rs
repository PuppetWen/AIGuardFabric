//! 统一协议 ↔ 各厂商线格式转换，以及 SSE 增量解析器。
//!
//! 本模块是**纯函数集合**（无 I/O、无网络），因此可以低成本地做穷尽的单元测试
//! ——这正是规格里"经典 bug"（SSE 分片跨 chunk 边界、系统提示词位置、工具调用
//! 参数是字符串而非对象）最容易出问题的地方。
//!
//! ## 三家协议的关键差异
//!
//! | 维度 | OpenAI 兼容 | Anthropic Messages | Gemini `generateContent` |
//! |---|---|---|---|
//! | 系统提示词 | `messages[].role = "system"` | 顶层 `system` 字段 | `systemInstruction.parts[].text` |
//! | 助手角色名 | `assistant` | `assistant` | `model` |
//! | 工具定义 | `tools[].function` | `tools[]`（扁平） | `tools[].functionDeclarations` |
//! | 工具调用回传 | `assistant.tool_calls` + `role="tool"` | `content[] = tool_use` / `tool_result` 块 | `parts[].functionCall` / `functionResponse` |
//! | 工具参数 | **JSON 字符串** | **对象** | **对象** |
//! | 图片 | `image_url.url`（URL/data URI） | `image.source.base64` | `inlineData.data`（base64） |
//! | 用量字段 | `prompt/completion_tokens` | `input/output_tokens` | `promptTokenCount/candidatesTokenCount` |
//! | 最大输出 | 可选 | **必填** `max_tokens` | `generationConfig.maxOutputTokens` |
//!
//! ## 有损转换的显式声明
//!
//! 转换是"尽量对齐"而非"完全无损"，以下降级是**刻意**的，且在返回体里保留原文
//! （`ChatResponse.raw`）以便排障：
//!
//! - Anthropic 未传 `max_tokens` 时补默认 4096（否则上游 400）；
//! - Gemini 不支持 `Role::System` 出现在 `contents` 中（已提到顶层）；
//! - Gemini 的 `tool_result` 没有独立 id 字段，网关用"最近的 tool_use 调用 id"回填；
//! - 三家的 `finish_reason` 统一收敛为 [`FinishReason`] 四档（其余归 `Other`）。

pub(crate) use serde_json::Map;
pub(crate) use serde_json::Value;
pub(crate) use serde_json::json;

pub(crate) use crate::wire::ChatMessage;
pub(crate) use crate::wire::ChatRequest;
pub(crate) use crate::wire::ChatResponse;
pub(crate) use crate::wire::ContentPart;
pub(crate) use crate::wire::FinishReason;
pub(crate) use crate::wire::MessageContent;
pub(crate) use crate::wire::ResponseFormat;
pub(crate) use crate::wire::Role;
pub(crate) use crate::wire::StreamChunk;
pub(crate) use crate::wire::ToolCall;
pub(crate) use crate::wire::ToolCallDelta;
pub(crate) use crate::wire::ToolDefinition;
pub(crate) use crate::wire::Usage;
pub(crate) use crate::wire::parse_arguments;

#[cfg(test)]
pub(crate) use pretty_assertions::assert_eq as eq;

#[allow(unused_imports)]
pub use from_anthropic_event::*;
#[allow(unused_imports)]
pub(crate) use impl_sse_decoder::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests_2::*;
#[allow(unused_imports)]
pub use to_openai_body::*;

/// Anthropic 未提供 `max_tokens` 时的兜底值（该字段必填，缺省会被上游拒绝）。
pub const ANTHROPIC_DEFAULT_MAX_TOKENS: u32 = 4096;

/// Gemini 未提供 `max_tokens` 时的兜底值。
pub const GEMINI_DEFAULT_MAX_TOKENS: u32 = 4096;

/// Anthropic splits input usage into uncached, cache writes, and cache reads.
/// Canonical prompt_tokens includes all three; cached_tokens is the read subset.
fn anthropic_usage(value: &Value) -> crate::wire::Usage {
    let read = value.get("cache_read_input_tokens").and_then(Value::as_u64).unwrap_or(0);
    let writes = value.get("cache_creation_input_tokens").and_then(Value::as_u64).unwrap_or_else(|| {
        value
            .get("cache_creation")
            .map(|creation| {
                ["ephemeral_5m_input_tokens", "ephemeral_1h_input_tokens"]
                    .iter()
                    .filter_map(|key| creation.get(*key).and_then(Value::as_u64))
                    .fold(0_u64, u64::saturating_add)
            })
            .unwrap_or(0)
    });
    let uncached = value.get("input_tokens").and_then(Value::as_u64).unwrap_or(0);
    let one_hour = value
        .get("cache_creation")
        .and_then(|creation| creation.get("ephemeral_1h_input_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .min(writes);
    crate::wire::Usage {
        prompt_tokens: uncached.saturating_add(writes).saturating_add(read),
        completion_tokens: value.get("output_tokens").and_then(Value::as_u64).unwrap_or(0),
        cached_tokens: read,
        cache_write_tokens: writes,
        cache_write_1h_tokens: one_hour,
    }
}

// ---------------------------------------------------------------------------
// SSE 增量解析器
// ---------------------------------------------------------------------------

/// 一个完整的 SSE 事件。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SseEvent {
    /// `event:` 字段（Anthropic 用它区分 `content_block_delta` 等）。
    pub event: Option<String>,
    /// `data:` 字段拼接结果（多行 `data:` 以 `\n` 连接，符合 SSE 规范）。
    pub data: String,
}

/// SSE 增量解码器。
///
/// **核心不变量**：调用方可以把任意切分的字节块喂给 [`SseDecoder::feed`]
/// （网络分片、TCP 分段、UTF-8 多字节字符被切断……），解码器只会在遇到
/// **空行**（事件分隔符）时才产出一个 [`SseEvent`]，跨块的部分行与部分事件
/// 一律留在内部缓冲区——这是 SSE 解析最经典的 bug，见本模块测试
/// `sse_decoder_handles_split_across_boundaries`。
///
/// 支持 `\n` 与 `\r\n` 两种换行；忽略 `:` 开头的注释行与 `id:` / `retry:` 字段。
#[derive(Debug, Clone, Default)]
pub struct SseDecoder {
    buffer: Vec<u8>,
    event: Option<String>,
    data_lines: Vec<String>,
}

mod from_anthropic_event;
mod impl_sse_decoder;
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests;
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests_2;
mod to_openai_body;
