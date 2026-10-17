//! AI 红队：用例库、执行模拟、战役编排与报告（§4.2 AI 红队）。
//!
//! ## 离线可验证的设计
//!
//! 真实红队需要"被测 Agent/MCP 环境"。为了让阶段一（离线）也能跑通完整链路，
//! 这里引入 [`RedteamSimulator`]：它实现 [`TargetUnderTest`] trait，
//! 用工例的 `success_signals` 与目标能力画像**确定性**地判定"攻击是否得逞"。
//!
//! - `AGF_MOCK_MODE=1` 或未配置真实目标时 → 使用 [`RedteamSimulator`]（本地模拟实例）；
//! - Real adapters must provide structured interaction evidence through observe_case.
//!   Signal-only legacy adapters remain inconclusive; concrete API adapters are separate work.
//!
//! 因此"战役 → 用例执行 → 成功判定 → 报告 → CI 卡点"整条链路在离线环境可完整验证。

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::path::Path;
pub(crate) use std::path::PathBuf;

pub(crate) use agf_core::enums::EvidenceLevel;
pub(crate) use agf_core::enums::RiskDomain;
pub(crate) use agf_core::enums::Severity;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;
pub(crate) type RequestGuard =
    std::sync::Arc<dyn Fn() -> futures::future::BoxFuture<'static, DomainResult<()>> + Send + Sync>;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::NS_REDTEAM_CASE;
pub(crate) use agf_core::ids::TenantId;
pub(crate) use agf_core::ids::deterministic_id;

pub(crate) use agf_core::redteam::AttackCategory;
pub(crate) use agf_core::redteam::CampaignState;
pub(crate) use agf_core::redteam::CategoryStat;
pub(crate) use agf_core::redteam::EvaluationStatus;
pub(crate) use agf_core::redteam::ExecutionMode;
mod agent_http;
#[cfg(test)]
mod agent_http_tests;
mod mcp_http;
#[cfg(test)]
mod mcp_http_tests;
mod mcp_tool_meter;
mod observation;
#[cfg(test)]
mod observation_tests;
pub use agent_http::AgentHttpTarget;
pub(crate) use agf_core::redteam::RedteamCampaign;
pub(crate) use agf_core::redteam::RedteamCase;
pub(crate) use agf_core::redteam::RedteamReport;
pub(crate) use agf_core::redteam::RedteamResult;
pub(crate) use agf_core::redteam::aggregate_by_category;
pub use mcp_http::McpHttpTarget;
pub use mcp_tool_meter::{ToolCallOutcome, ToolCallReceipt};
pub use observation::TargetObservation;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use async_trait::async_trait;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use tracing::debug;
pub(crate) use tracing::info;

#[cfg(test)]
pub(crate) use agf_core::redteam::AttackTurn;

#[allow(unused_imports)]
pub use impl_redteam_outcome::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 用例库统计。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaseLibraryStats {
    /// 用例总数。
    pub total: usize,
    /// 按类别统计。
    pub by_category: BTreeMap<String, usize>,
    /// 按严重等级统计。
    pub by_severity: BTreeMap<String, usize>,
    /// 按执行方式统计。
    pub by_mode: BTreeMap<String, usize>,
    /// 来自公开真实 PoC 的用例数。
    pub public_poc: usize,
    /// 校验失败的用例（键/文件 → 问题）。
    pub invalid: BTreeMap<String, Vec<String>>,
    /// 全部信号词表（用例声明的 success_signals 去重集合）。
    pub signals: Vec<String>,
}

/// 红队用例库。
#[derive(Debug, Clone, Default)]
pub struct CaseLibrary {
    cases: Vec<RedteamCase>,
    stats: CaseLibraryStats,
}

/// 被测目标。
#[async_trait]
pub trait TargetUnderTest: Send + Sync {
    /// 目标名称（用于报告）。
    fn name(&self) -> &str;

    /// 目标能力（用于筛选适用用例）。
    fn capabilities(&self) -> Vec<String>;

    /// 执行一个用例，返回命中的成功信号。
    ///
    /// # Errors
    /// 执行环境错误（网络、超时等）。
    async fn run_case(&self, case: &RedteamCase) -> DomainResult<Vec<String>>;

    /// Structured observations are required for reportable real execution.
    async fn observe_case(&self, case: &RedteamCase) -> DomainResult<TargetObservation> {
        if self.is_simulated() {
            Ok(TargetObservation::evaluated(self.run_case(case).await?, vec![]))
        } else {
            Ok(TargetObservation::inconclusive("Target adapter does not provide verifiable observations."))
        }
    }

    /// 目标资产 id。
    fn asset_id(&self) -> Id;

    /// 是否本地模拟。
    fn is_simulated(&self) -> bool {
        false
    }
}

/// 本地模拟目标（离线演示与自测）。
///
/// 判定规则（确定性、可解释）：
/// 1. 记录按顺序执行的轮次内容；
/// 2. 若用例要求的工具或目标能力缺失，则该用例无法判定；
/// 3. 否则按用例键的哈希模拟"得逞/未得逞"，并给出命中信号与描述。
///
/// 这让"成功率的统计口径"在离线环境下也完全确定性，便于 CI 断言。
#[derive(Debug, Clone)]
pub struct RedteamSimulator {
    name: String,
    asset_id: Id,
    capabilities: Vec<String>,
    tools: Vec<String>,
    /// 拦截率（0-100）：模拟目标防护强度，越高越不容易被攻破。
    guard_strength: u8,
}

/// 单次红队执行结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedteamOutcome {
    /// Whether the adapter completed the case's declared checks.
    #[serde(default)]
    pub evaluation: EvaluationStatus,
    /// Non-secret explanation when the assessment is incomplete.
    #[serde(default)]
    pub evaluation_note: Option<String>,
    /// Bounded, redacted target interaction evidence.
    #[serde(default)]
    pub transcript: Vec<serde_json::Value>,
    /// 用例键。
    pub case_key: String,
    /// 用例标题。
    pub case_title: String,
    /// 类别。
    pub category: AttackCategory,
    /// 严重等级。
    pub severity: Severity,
    /// 目标资产。
    pub target_asset_id: Id,
    /// 是否得逞。
    pub succeeded: bool,
    /// 命中信号。
    pub matched_signals: Vec<String>,
    /// 绕过路径说明。
    pub bypass_path: Option<String>,
    /// 证据等级。
    pub evidence_level: EvidenceLevel,
    /// 耗时（毫秒）。
    pub latency_ms: u64,
    /// 是否本地模拟。
    pub simulated: bool,
}

/// 战役运行器。
#[derive(Debug, Clone, Default)]
pub struct CampaignRunner;

mod impl_case_library_stats;
mod impl_redteam_outcome;
#[cfg(test)]
mod tests;
