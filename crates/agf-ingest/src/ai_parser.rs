//! AI 推断解析器（§4.5「无模板时 AI 推断字段并生成解析器」）。
//!
//! ## 降级行为（必读）
//!
//! 真正调用大模型属于 `agf-aigw` 的职责（模型路由/降级/配额都在那里）。本 crate 只提供
//! **服务端接入侧的推断落地点**：
//!
//! | 实现 | 状态 | 说明 |
//! |---|---|---|
//! | [`HeuristicAiParser`] | 已实现 | 离线启发式：报文形态识别（JSON/KV/CSV）+ 键名→ECS 词典匹配，**不联网** |
//! | [`MockAiParser`] | 已实现 | 固定返回一个可解析的模板，供演示与测试；`mocked=true` |
//! | [`RemoteAiParser`] | 未实现 | 通过 `agf-aigw` 调用 LLM；见 `TODO ingest-ai-parser-remote` |
//!
//! 任何推断结果都带 `mocked` 标记，**必须人工确认后**调用
//! [`crate::registry::ParserRegistry::register_ai_inferred`] 才进入匹配集——
//! 平台绝不让未经验证的解析器自动上线（否则一条坏模板会污染一整类日志）。

use std::collections::BTreeMap;

use agf_core::enums::{IngestProtocol, Severity};
use agf_core::error::{DomainError, DomainResult};
use agf_core::parser::{AiParserRequest, AiParserSuggestion, FieldMapping, ParserDefinition, ParserEngine};
use agf_core::time::Timestamp;
use serde_json::Value;

mod heuristic;
mod provider;

#[cfg(test)]
mod tests;

pub use heuristic::*;
pub use provider::*;
