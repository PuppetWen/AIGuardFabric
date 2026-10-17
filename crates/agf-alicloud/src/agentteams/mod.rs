//! AgentTeams 适配器（§5.1 核心）：台账双向同步、免改造纳管、跨 Team 调用链、配额同步、审计事件汇聚。
//!
//! ## 职责
//!
//! | §5.1 要求 | 本模块落点 |
//! |---|---|
//! | 拉取 Team / Agent / Role；任务观测与声明分开 | [`AgentTeamsApi::pull_teams`]；Live DAG 未提供，Mock 声明显式标记 |
//! | 双向同步台账 | [`AgentTeamsApi::sync_teams`]（Mock 的 `SyncDirection::Both` 合并，冲突**平台为准并告警**；不证明云端写入） |
//! | 免改造纳管（侧车 / SDK 注入 / 网关注册） | [`AgentTeamsApi::select_onboarding`]（复用 [`OnboardingMode`]） |
//! | Team 内消息与任务审计 | [`AgentTeamsApi::pull_audit_events`]（交给 `agf-ingest` 联合分析） |
//! | Role 映射平台权限模型 | [`AgentTeamsApi::map_roles`] |
//! | 跨 Team 调用链可视化 | [`AgentTeamsApi::pull_cross_team_calls`] |
//! | 配额双向同步（冲突以平台为准并告警） | [`AgentTeamsApi::sync_quotas`] + [`QuotaSyncState::resolve`] |
//!
//! ## 纳管模式选择规则（公开可解释）
//!
//! 1. 已纳管（`asset_id` 已填充）→ 保持侧车；
//! 2. 引用自研工具 → [`OnboardingMode::SdkInjection`]（建议显式接入 SDK；不会自动注入）；
//! 3. 只调用模型 → [`OnboardingMode::GatewayRegistration`]（支持端点配置的客户端可改配置接入；不会自动重定向）；
//! 4. 有 MCP 工具 → [`OnboardingMode::Sidecar`]（需要操作者按指南配置 MCP 代理）；
//! 5. 无工具无模型 → [`OnboardingMode::ObserveOnly`]（旁路观测）。
//!
//! ## 降级
//!
//! 未配置时台账只读：停止双向同步与配额下发，**平台侧配置继续生效（平台为准）**；
//! 审计事件缺失由网关侧流量审计补位。

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::sync::Arc;

pub(crate) use agf_core::adapter::Adapter;
pub(crate) use agf_core::adapter::AdapterConfig;
pub(crate) use agf_core::adapter::AdapterDescriptor;
pub(crate) use agf_core::adapter::AdapterHealth;
pub(crate) use agf_core::adapter::PullRequest;
pub(crate) use agf_core::adapter::PullResponse;
pub(crate) use agf_core::adapter::PushPayload;
pub(crate) use agf_core::adapter::SyncDirection;
pub(crate) use agf_core::adapter::SyncOutcome;

pub(crate) use agf_core::agent::AgentFlavor;
pub(crate) use agf_core::agent::OnboardingMode;

pub(crate) use agf_core::cloud::AgentTeam;
pub(crate) use agf_core::cloud::AgentTeamMember;
pub(crate) use agf_core::cloud::AgentTeamRole;
pub(crate) use agf_core::cloud::CrossTeamCall;
pub(crate) use agf_core::cloud::OrchestrationNode;
pub(crate) use agf_core::cloud::QuotaSyncState;

pub(crate) use agf_core::enums::AliCloudService;
pub(crate) use agf_core::enums::QuotaDimension;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::NS_AGENT;
pub(crate) use agf_core::ids::TenantId;
pub(crate) use agf_core::ids::deterministic_id;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use async_trait::async_trait;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use crate::AdapterMode;

pub(crate) use crate::http::RpcClient;
pub(crate) use crate::http::json_array;
pub(crate) use crate::http::json_i64;
pub(crate) use crate::http::json_str;

pub(crate) use crate::mock;
pub(crate) use crate::mock::AdapterCore;
pub(crate) use crate::mock::NS_TEAM;
pub(crate) use crate::mock::null_transport;

#[cfg(test)]
pub(crate) use crate::test_support::fixture_config;

#[cfg(test)]
pub(crate) use agf_core::enums::HealthState;

#[allow(unused_imports)]
pub use impl_agent_teams_adapter::*;
#[allow(unused_imports)]
pub use impl_quota_sync_report::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests_2::*;

/// AgentTeams API 版本。
pub const AGENTTEAMS_API_VERSION: &str = "2026-06-05";

/// 配额同步结果（含冲突告警）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaSyncReport {
    /// 同步状态列表。
    pub states: Vec<QuotaSyncState>,
    /// 本次需要发出的冲突告警（说明文本）。
    pub conflict_alerts: Vec<String>,
    /// 生效值（平台为准）。
    pub effective: BTreeMap<String, i64>,
}

/// 团队同步结果。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TeamSyncReport {
    /// 拉取到的团队数。
    pub pulled: usize,
    /// 新建团队数。
    pub created: usize,
    /// 更新团队数。
    pub updated: usize,
    /// 跳过（无变化）数。
    pub skipped: usize,
    /// 冲突数（远端与平台不一致，**平台为准**）。
    pub conflicts: usize,
    /// 已纳管 Agent 数。
    pub managed_agents: usize,
    /// Agent 总数。
    pub total_agents: usize,
    /// 告警。
    pub warnings: Vec<String>,
    /// 团队（合并后）。
    pub teams: Vec<AgentTeam>,
}

/// AgentTeams 服务能力契约。
#[async_trait]
pub trait AgentTeamsApi: Send + Sync {
    /// 拉取团队与成员/角色库存；Live 不提供 DAG，Mock 仅返回明确演示声明。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn pull_teams(&self) -> DomainResult<Vec<AgentTeam>>;

    /// 合并声明：Mock 冲突平台为准；真实云推送仍需已实现的专用管理端点。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn sync_teams(&self, local: &[AgentTeam], direction: SyncDirection) -> DomainResult<TeamSyncReport>;

    /// 为团队成员选择免改造纳管模式。
    ///
    /// # Errors
    /// 目前不会失败。
    fn select_onboarding(&self, member: &AgentTeamMember) -> DomainResult<OnboardingMode>;

    /// 拉取跨 Team 调用链。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn pull_cross_team_calls(&self, since: Option<Timestamp>) -> DomainResult<Vec<CrossTeamCall>>;

    /// 配额双向同步（冲突以平台为准并告警）。
    ///
    /// # Errors
    /// 数据非法（如维度为空）。
    async fn sync_quotas(
        &self,
        integration_id: Id,
        platform_values: &[(QuotaDimension, i64)],
    ) -> DomainResult<QuotaSyncReport>;

    /// Role → 平台 RBAC 角色映射。
    ///
    /// # Errors
    /// 目前不会失败。
    fn map_roles(&self, roles: &[AgentTeamRole]) -> DomainResult<Vec<(String, String)>>;

    /// 拉取审计事件（交给 `agf-ingest` 做联合分析）。
    ///
    /// # Errors
    /// 网络失败或远端拒绝。
    async fn pull_audit_events(&self, limit: Option<u32>) -> DomainResult<Vec<serde_json::Value>>;
}

/// AgentTeams 适配器。Mock 与真实实现是同一类型的两种模式。
pub struct AgentTeamsAdapter {
    core: AdapterCore,
    instance_id: String,
    worker_name: String,
    quota_period: String,
    client: Option<Arc<RpcClient>>,
    transport: Arc<crate::http::RecordingTransport>,
    /// 最近一次配额同步状态（实现"冲突未消失不重复告警"，与 [`QuotaSyncState::resolve`] 配合）。
    quota_state: std::sync::Mutex<BTreeMap<String, QuotaSyncState>>,
}

mod definition_signature;
mod impl_agent_teams_adapter;
mod impl_quota_sync_report;
mod live;
mod live_quota;
/// Application-owned declarations and an isolated Mock receiver; no vendor DAG write API.
pub mod orchestration;
pub mod relations;
mod relations_fields;
#[cfg(test)]
mod relations_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_2;
#[cfg(test)]
mod tests_live;
