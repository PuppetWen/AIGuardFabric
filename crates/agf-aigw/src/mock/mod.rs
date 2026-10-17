//! 离线 Mock 模型：**无 Key 时平台不报错**的实现位置。
//!
//! ## 为什么需要它
//!
//! 产品规格 §11 阶段一验收准则 5 要求"无 Key 时平台自动降级不报错"。
//! 真实厂商适配器在缺凭据时返回可降级错误（见 [`crate::provider`]），
//! 由 [`crate::gateway::AiGateway`] 判定"该走 Mock"后**改用本模块的实现**，
//! 因此上层永远拿得到一个合法 [`ChatResponse`]。
//!
//! ## 确定性
//!
//! Mock 的回复**不依赖任何随机数**：
//! - 优先按 [`RecordedFixture`] 的指纹匹配（真实录制回放）；
//! - 否则按**意图识别**（[`MockIntent`]）给出结构化答案；
//! - 否则回显一段简短的确定性摘要（含请求指纹前缀，便于对照审计）。
//!
//! ## 三个可演示的分析意图（离线演示用）
//!
//! | 意图 | 触发词（任一命中） | 输出形态 |
//! |---|---|---|
//! | [`MockIntent::AlertTriage`] | 研判 / 分析告警 / triage / verdict | JSON：`{"verdict":"malicious\|suspicious\|benign","confidence":…,"rationale":…,"cited_evidence":[…]}` |
//! | [`MockIntent::AttackChainSummary`] | 攻击链路 / attack chain / 横向移动 | 带阶段的编号清单（Markdown 兼容） |
//! | [`MockIntent::Report`] | 报告 / report / 复盘 | Markdown，固定含 `## 摘要 / ## 关键发现 / ## 影响 / ## 处置建议` 四节 |
//! | [`MockIntent::Echo`] | 其余 | 确定性简短摘要 |

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::sync::Arc;

pub(crate) use std::time::Duration;

pub(crate) use agf_core::adapter::Adapter;
pub(crate) use agf_core::adapter::AdapterConfig;
pub(crate) use agf_core::adapter::AdapterDescriptor;
pub(crate) use agf_core::adapter::AdapterHealth;
pub(crate) use agf_core::adapter::CircuitSnapshot;
pub(crate) use agf_core::adapter::PullRequest;
pub(crate) use agf_core::adapter::PullResponse;
pub(crate) use agf_core::adapter::PushPayload;
pub(crate) use agf_core::adapter::SyncDirection;
pub(crate) use agf_core::adapter::SyncOutcome;

pub(crate) use agf_core::enums::HealthState;
pub(crate) use agf_core::enums::LlmProvider;

pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::model::ModelEndpoint;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use async_trait::async_trait;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use serde_json::Value;
pub(crate) use serde_json::json;

pub(crate) use crate::provider::LLM_CAPABILITIES;
pub(crate) use crate::provider::ProviderAdapter;
pub(crate) use crate::provider::ProviderDescriptor;
pub(crate) use crate::provider::ProviderStream;

pub(crate) use crate::wire::ChatDelta;
pub(crate) use crate::wire::ChatMessage;
pub(crate) use crate::wire::ChatRequest;
pub(crate) use crate::wire::ChatResponse;
pub(crate) use crate::wire::FinishReason;
pub(crate) use crate::wire::MessageContent;
pub(crate) use crate::wire::StreamChunk;
pub(crate) use crate::wire::ToolDefinition;
pub(crate) use crate::wire::Usage;

#[cfg(test)]
pub(crate) use crate::wire::Role;

#[cfg(test)]
pub(crate) use pretty_assertions::assert_eq as eq;

#[allow(unused_imports)]
pub(crate) use impl_mock_intent::*;
#[allow(unused_imports)]
pub use impl_mock_provider::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// Mock 模型默认标识（`LlmProvider::Mock` 端点的模型名）。
pub const MOCK_MODEL: &str = "mock-analyst-1";

/// 研判意图识别结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MockIntent {
    /// 告警研判（输出结构化 JSON 判定）。
    AlertTriage,
    /// 攻击链路总结（输出分阶段清单）。
    AttackChainSummary,
    /// 报告生成（输出 Markdown 四节）。
    Report,
    /// 兜底：确定性简短摘要。
    Echo,
}

/// 录制响应 fixture（真实厂商调用的回放）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedFixture {
    /// 请求指纹（[`ChatRequest::fingerprint`]）。
    pub fingerprint: String,
    /// 回复文本。
    pub content: String,
    /// 使用的模型名。
    #[serde(default)]
    pub model: String,
    /// 用量（缺省按估算补齐）。
    #[serde(default)]
    pub usage: Option<Usage>,
    /// 结束原因。
    #[serde(default)]
    pub finish_reason: Option<FinishReason>,
}

/// fixtures 目录（相对 crate 根，存在则加载）。
pub const FIXTURE_DIR: &str = "tests/fixtures/mock_responses";

/// Mock 提供商。
#[derive(Debug, Clone)]
pub struct MockProvider {
    /// 使用的模型名。
    pub model: String,
    /// 录制响应表（指纹 → fixture）。
    fixtures: Arc<BTreeMap<String, RecordedFixture>>,
    /// 合成延迟（毫秒），模拟真实调用耗时，默认 1ms。
    pub synthetic_latency_ms: u64,
}

mod impl_mock_intent;
mod impl_mock_provider;
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests;
