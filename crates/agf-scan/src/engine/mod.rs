//! 扫描引擎：把"规则包 + 五大域检测器 + （可选）模型二次研判"串成一次扫描。
//!
//! ## 为什么研判用 trait 而不是直接依赖 `agf-aigw`
//!
//! `agf-aigw` 提供真实模型调用与 Mock 模型。扫描引擎只关心"给一段文本，得到结构化研判"，
//! 因此抽象为 [`LlmJudge`]：生产环境由 `agf-api` 用 `agf-aigw` 的网关实现，
//! 单测与离线演示使用 [`RuleBasedJudge`]（基于规则命中给出保守研判）。
//! 这保证了本 crate 的测试完全不依赖网络，也避免了 crate 之间的循环依赖。

pub(crate) use std::collections::BTreeMap;

pub(crate) use agf_core::enums::DataClass;
pub(crate) use agf_core::enums::EvidenceLevel;
pub(crate) use agf_core::enums::RiskDomain;
pub(crate) use agf_core::enums::Severity;
pub(crate) use agf_core::enums::Verdict;

pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::TenantId;

pub(crate) use agf_core::mcp::ToolTraits;

pub(crate) use agf_core::risk::Finding;
pub(crate) use agf_core::risk::LlmJudgement;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use async_trait::async_trait;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use tracing::debug;
pub(crate) use tracing::info;

pub(crate) use crate::detector::RuleHit;

pub(crate) use crate::domains::DomainDetector;
pub(crate) use crate::domains::DomainHit;
pub(crate) use crate::domains::DomainReport;
pub(crate) use crate::domains::DomainVerdict;
pub(crate) use crate::domains::aggregate_risk_score;

pub(crate) use crate::loader::RulePack;

#[cfg(test)]
pub(crate) use crate::loader::RulePackLoader;

#[cfg(test)]
pub(crate) use agf_core::enums::PolicyAction;
#[cfg(test)]
pub(crate) use agf_core::enums::RuleKind;

#[cfg(test)]
pub(crate) use agf_core::rule::Detection;
#[cfg(test)]
pub(crate) use agf_core::rule::RuleDefinition;
#[cfg(test)]
pub(crate) use agf_core::rule::RuleSamples;
pub(crate) use agf_core::rule::RuleTarget;

#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 扫描目标形态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScanTargetKind {
    /// 提示词/对话输入。
    Prompt,
    /// 日志/事件载荷。
    LogPayload,
    /// 知识库文档。
    Document,
    /// 工具调用参数。
    ToolArguments,
    /// 工具调用结果。
    ToolResult,
    /// MCP 请求。
    McpRequest,
    /// 模型输出。
    ModelOutput,
    /// MCP 响应。
    McpResponse,
    /// 配置内容。
    Config,
    /// 代码或文本文件。
    FileContent,
    /// 工具描述与 schema。
    ToolDefinition,
}

/// 一次扫描的目标。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTarget {
    /// 目标标识（资产名/文件路径/事件 id）。
    pub label: String,
    /// 目标形态。
    pub kind: ScanTargetKind,
    /// 文本内容。
    pub text: String,
    /// 关联资产 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<Id>,
    /// 数据分级。
    pub data_class: DataClass,
    /// 工具名（`kind = tool-arguments` 时提供）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    /// 工具能力画像。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_traits: Option<ToolTraits>,
}

/// 一次扫描请求。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    /// 目标列表。
    pub targets: Vec<ScanTarget>,
    /// 是否启用模型二次研判。
    pub use_llm_judge: bool,
    /// 只跑指定域（空 = 按目标形态的默认域）。
    pub domains: Vec<RiskDomain>,
    /// 是否把"疑似"也登记为 finding。
    pub report_suspicious: bool,
    /// 扫描任务名（写入报告）。
    pub job_name: String,
}

/// 扫描结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// 任务名。
    pub job_name: String,
    /// 租户。
    pub tenant_id: TenantId,
    /// 扫描目标数。
    pub targets_scanned: usize,
    /// 命中的规则（键 → 次数）。
    pub rule_hits: BTreeMap<String, usize>,
    /// 域报告（按目标聚合）。
    pub domain_reports: Vec<DomainReport>,
    /// 生成的 finding。
    pub findings: Vec<Finding>,
    /// 综合风险分（0-100）。
    pub risk_score: u8,
    /// 最高严重等级。
    pub max_severity: Severity,
    /// 模型研判（若启用）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub judgements: Option<Vec<LlmJudgement>>,
    /// 是否使用 Mock 模型。
    pub llm_mocked: bool,
    /// Requested judgements that failed or had no configured judge.
    #[serde(default)]
    pub judgement_failures: usize,
    /// 耗时（毫秒）。
    pub elapsed_ms: u64,
    /// 扫描时间。
    pub scanned_at: Timestamp,
}

/// 模型研判接口。
#[async_trait]
pub trait LlmJudge: Send + Sync {
    /// 对一段文本与命中给出研判。
    ///
    /// # Errors
    /// 模型调用失败（上层应降级为仅规则判定，而不是让扫描整体失败）。
    async fn judge(&self, domain: RiskDomain, text: &str, hits: &[DomainHit]) -> DomainResult<LlmJudgement>;

    /// 是否 Mock 模型。
    fn is_mocked(&self) -> bool {
        false
    }

    /// 模型名。
    fn model_name(&self) -> String {
        "unknown".to_string()
    }
}

/// 基于规则的保守研判（离线默认）。
///
/// 策略：命中即"恶意/疑似"，但置信度不超过 0.8；未命中为"良性"置信度 0.9。
/// 这样在无模型环境下，扫描链路的**结构与字段**与真实环境完全一致。
#[derive(Debug, Clone, Default)]
pub struct RuleBasedJudge;

/// 扫描引擎。
#[derive(Clone)]
pub struct ScanEngine {
    detector: DomainDetector,
    judge: Option<std::sync::Arc<dyn LlmJudge>>,
}

mod impl_scan_engine;
mod impl_scan_target_kind;
mod rule_reports;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_rule_scope;
