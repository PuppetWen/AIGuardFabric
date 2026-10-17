//! 统一协议（canonical wire format）。
//!
//! 本模块只定义 AIGuardFabric 内部的"共同语言"，**不做任何厂商格式转换**
//! （转换见 [`crate::convert`]），也**不做任何 I/O**，因此全部类型是纯 `serde`
//! 结构体，可安全序列化进审计日志、证据包与语义缓存。
//!
//! ## 设计要点
//!
//! 1. **超集而非交集**：canonical 类型取各厂商能力的并集（系统提示词、多轮、
//!    工具调用、图片、结构化输出），降级到具体厂商时由转换层丢弃不支持的部分；
//! 2. **内容与角色分离**：[`MessageContent`] 支持纯文本与多模态部件两种形态，
//!    `Text` 是 `Parts` 的语法糖，避免"单文本消息被包装成数组"导致的缓存指纹抖动；
//! 3. **可计量**：每个请求都能给出稳定指纹（[`ChatRequest::fingerprint`]）与
//!    token 估算（[`ChatRequest::estimate_prompt_tokens`]），前者用于语义缓存，
//!    后者用于预算前置拒绝与路由成本排序。

pub(crate) use std::collections::BTreeMap;

pub(crate) use agf_core::enums::DataClass;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use sha2::Digest;
pub(crate) use sha2::Sha256;

#[allow(unused_imports)]
pub use estimate_text_tokens::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 会话角色。
///
/// 与 OpenAI / Anthropic / Gemini 三家角色的映射关系见 [`crate::convert`] 模块文档。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// 系统提示词。
    System,
    /// 用户。
    User,
    /// 助手（模型）。
    Assistant,
    /// 工具执行结果（OpenAI 的 `tool` 角色）。
    Tool,
}

/// 图片细节级别（OpenAI 语义，其余厂商忽略）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageDetail {
    /// 自动。
    Auto,
    /// 低分辨率（省钱）。
    Low,
    /// 高分辨率。
    High,
}

/// 多模态内容部件。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentPart {
    /// 文本片段。
    Text {
        /// 文本。
        text: String,
    },
    /// 图片（URL 或 base64 data URI，**原样透传**，网关不解码）。
    Image {
        /// 图片地址（`https://...` 或 `data:image/png;base64,...`）。
        url: String,
        /// 细节级别。
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<ImageDetail>,
    },
    /// 工具调用记录（仅出现在助手消息里，OpenAI 的 `tool_calls` 内联形态）。
    ToolCall {
        /// 调用 id。
        id: String,
        /// 工具名。
        name: String,
        /// 参数（JSON）。
        arguments: serde_json::Value,
    },
}

/// 消息内容。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    /// 纯文本（最常见形态，指纹与转换都走这条快捷路径）。
    Text(String),
    /// 多模态部件数组。
    Parts(Vec<ContentPart>),
}

/// 一条对话消息。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChatMessage {
    /// 角色。
    pub role: Role,
    /// 内容。
    pub content: MessageContent,
    /// 工具调用列表（助手消息）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,
    /// 工具结果对应的调用 id（`Role::Tool` 时必填）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// 参与者名（多 Agent 场景区分同名角色）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// 工具（函数）定义。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// 工具名。
    pub name: String,
    /// 描述（模型据此决定是否调用）。
    #[serde(default)]
    pub description: String,
    /// JSON Schema 形式的参数定义。
    #[serde(default)]
    pub parameters: serde_json::Value,
    /// 是否为**有副作用**的工具（写文件、发请求、改配置…）。
    ///
    /// 该标记参与缓存判定：有副作用的工具调用结果不允许命中精确缓存
    /// （见 [`crate::cache::is_cacheable`]）。
    #[serde(default)]
    pub side_effecting: bool,
}

/// 工具调用。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    /// 调用 id（回填工具结果时使用）。
    pub id: String,
    /// 工具名。
    pub name: String,
    /// 参数（JSON）。
    #[serde(default)]
    pub arguments: serde_json::Value,
}

/// 结构化输出约束。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseFormat {
    /// 自由文本。
    Text,
    /// 强制 JSON（不保证 schema）。
    JsonObject,
    /// 严格 JSON Schema（OpenAI `json_schema` / 其余厂商降级为 `JsonObject`）。
    JsonSchema {
        /// schema 名。
        name: String,
        /// JSON Schema。
        schema: serde_json::Value,
        /// 是否严格模式。
        #[serde(default)]
        strict: bool,
    },
}

/// 统一聊天请求。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChatRequest {
    /// 模型标识（厂商侧 model id，如 `gpt-4o`、`claude-3-5-sonnet`）。
    pub model: String,
    /// 消息列表。
    pub messages: Vec<ChatMessage>,
    /// 采样温度。**语义缓存只在 `temperature == 0`（或缺省）时命中**，见 [`crate::cache`]。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// 最大输出 token。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Nucleus sampling, mapped to each provider's equivalent field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    /// Stop sequences. Their values participate in the response-cache fingerprint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stop: Vec<String>,
    /// OpenAI-style tool selection (`auto`, `none`, `required`, or a named function).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<serde_json::Value>,
    /// 是否流式。
    #[serde(default)]
    pub stream: bool,
    /// 工具定义。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolDefinition>,
    /// 结构化输出约束。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_format: Option<ResponseFormat>,
    /// 终端用户标识（厂商侧用于滥用追踪）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// 附加元数据（**不参与指纹**，用于审计标注、路由标签等）。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    /// Validated Anthropic-only body. Never use it after policy or screening rewrites messages.
    #[serde(skip)]
    pub anthropic_native: Option<AnthropicNativeRequest>,
}

/// Preserves native Messages fields and signed thinking blocks without bypassing canonical policy.
#[derive(Debug, Clone, PartialEq)]
pub struct AnthropicNativeRequest {
    /// Whitelisted, validated original request body.
    pub body: serde_json::Value,
    /// Canonical messages captured after parsing; changes invalidate native forwarding.
    pub messages: Vec<ChatMessage>,
}

/// token 用量。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    /// 输入 token。
    #[serde(default)]
    pub prompt_tokens: u64,
    /// 输出 token。
    #[serde(default)]
    pub completion_tokens: u64,
    /// 命中厂商侧 prompt cache 的 token（计价更低）。
    #[serde(default)]
    pub cached_tokens: u64,
    /// Tokens written into the provider prompt cache (a subset of prompt_tokens).
    #[serde(default)]
    pub cache_write_tokens: u64,
    /// One-hour cache writes (a subset of cache_write_tokens; the rest use five minutes).
    #[serde(default)]
    pub cache_write_1h_tokens: u64,
}

/// 结束原因（canonical：统一映射三家的 finish reason）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    /// 正常结束。
    Stop,
    /// 达到 `max_tokens`。
    Length,
    /// 模型请求调用工具。
    ToolCalls,
    /// 被内容安全策略拦截。
    ContentFilter,
    /// 其它。
    Other,
}

/// 一次模型回复。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChatResponse {
    /// 上游响应 id（无则本地生成）。
    pub id: String,
    /// 实际使用的模型。
    pub model: String,
    /// 回复消息。
    pub message: ChatMessage,
    /// 结束原因。
    pub finish_reason: FinishReason,
    /// token 用量。
    pub usage: Usage,
    /// 上游原始响应（排障用；Mock 模式下为合成体）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
}

/// 流式增量。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ChatDelta {
    /// 角色（通常只在第一个分片出现）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,
    /// 文本增量。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content: String,
    /// 工具调用增量（按 index 合并，见 [`StreamChunk::merge_tool_call`]）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCallDelta>,
}

/// 工具调用增量（流式下参数是逐字符下发的 JSON 片段）。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ToolCallDelta {
    /// 调用序号（同一序号的分片需要拼接）。
    pub index: u32,
    /// 调用 id（通常只在首个分片出现）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// 工具名。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// 参数 JSON 片段。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub arguments_fragment: String,
}

/// 流式分片。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StreamChunk {
    /// 增量内容。
    pub delta: ChatDelta,
    /// 结束原因（最后一个业务分片携带）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<FinishReason>,
    /// token 用量（通常只在最后一个分片携带）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
    /// Original Anthropic SSE event, retained for signed thinking and context-editing fidelity.
    #[serde(skip)]
    pub anthropic_event: Option<serde_json::Value>,
}

/// 流式分片累积器：把增量拼装回一条完整的 [`ChatResponse`]。
///
/// 网关用它把"流式转发"与"计量/缓存/后置过滤"统一起来：转发给客户端的是
/// 原始分片，同时累积一份完整回复用于计量与（可选的）缓存写入。
#[derive(Debug, Clone, Default)]
pub struct StreamAccumulator {
    content: String,
    calls: Vec<ToolCall>,
    finish_reason: Option<FinishReason>,
    usage: Usage,
}

mod estimate_text_tokens;
mod impl_role;
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests;
