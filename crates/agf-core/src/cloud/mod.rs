//! 云平台集成模型（§5 阿里云 + 多云）。
//!
//! 与 [`crate::adapter`] 的分工：`adapter` 定义**契约**，本模块定义**云侧实体与绑定关系**
//! （云账号、AssumeRole 链、资源映射、配额同步状态）。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::enums::{AliCloudService, HealthState};

use crate::ids::{Id, TenantId};

use crate::time::Timestamp;

#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 云厂商。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CloudProvider {
    /// 阿里云。
    AliCloud,
    /// 华为云。
    HuaweiCloud,
    /// 腾讯云。
    TencentCloud,
    /// AWS。
    Aws,
    /// Azure。
    Azure,
    /// GCP。
    Gcp,
    /// 私有云/自建。
    Private,
}

/// 凭据类型（§5.3：优先 RAM Role / STS，禁止长期 AK 明文落盘）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CloudCredentialKind {
    /// 实例 RAM Role（无长期密钥，最优）。
    InstanceRole,
    /// STS 临时凭据。
    StsToken,
    /// 跨账号 AssumeRole。
    AssumeRole,
    /// 长期 AccessKey（**不推荐**，仅兼容遗留环境，需登记风险）。
    LongTermAk,
    /// 工作负载身份（K8s OIDC / IRSA）。
    WorkloadIdentity,
}

/// 云账号/集成绑定。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudIntegration {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 云厂商。
    pub provider: CloudProvider,
    /// 显示名。
    pub name: String,
    /// 主账号 UID / Account ID。
    pub account_id: String,
    /// 默认地域。
    pub region_id: String,
    /// 凭据类型。
    pub credential_kind: CloudCredentialKind,
    /// 凭据引用（密文存 `credentials`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<Id>,
    /// 跨账号 AssumeRole 的 Role ARN。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assume_role_arn: Option<String>,
    /// Role session 名。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_session_name: Option<String>,
    /// STS 过期时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sts_expires_at: Option<Timestamp>,
    /// 各服务的 endpoint 覆盖（Privatelink 私网 endpoint）。
    #[serde(default)]
    pub endpoints: BTreeMap<String, String>,
    /// 是否启用。
    pub enabled: bool,
    /// 健康状态。
    pub health: HealthState,
    /// 最近同步时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sync_at: Option<Timestamp>,
    /// 最近错误。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// 最小权限自检结果。
    #[serde(default)]
    pub permission_checks: Vec<PermissionCheck>,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 更新时间。
    pub updated_at: Timestamp,
}

/// 权限自检项（"云环境自检"页：连通性 / 最小权限 / 配额余量）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionCheck {
    /// 检查项名（如 `cms:PutCustomEvent`）。
    pub name: String,
    /// 是否通过。
    pub passed: bool,
    /// 结论说明。
    pub note: String,
    /// 是否需要该权限（否则只是提示）。
    pub required: bool,
    /// 检查时间。
    pub checked_at: Timestamp,
}

/// 云资源与平台资产的映射关系。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudResourceMapping {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 集成 id。
    pub integration_id: Id,
    /// 服务。
    pub service: AliCloudService,
    /// 云资源 id（实例 id / 网关 id / 命名空间）。
    pub resource_id: String,
    /// 资源类型（`ecs` / `ack-cluster` / `apig-gateway` / `mse-namespace`）。
    pub resource_kind: String,
    /// 关联的平台资产 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<Id>,
    /// 资源属性（保真）。
    #[serde(default)]
    pub attributes: BTreeMap<String, serde_json::Value>,
    /// 发现时间。
    pub discovered_at: Timestamp,
    /// 更新时间。
    pub updated_at: Timestamp,
    /// 资源是否已消失（云侧删除）。
    #[serde(default)]
    pub stale: bool,
}

/// AgentTeams 团队。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTeam {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 云侧 team id。
    pub cloud_team_id: String,
    /// 团队名。
    pub name: String,
    /// 描述。
    #[serde(default)]
    pub description: String,
    /// 团队成员（Agent 列表）。
    #[serde(default)]
    pub agents: Vec<AgentTeamMember>,
    /// 角色定义。
    #[serde(default)]
    pub roles: Vec<AgentTeamRole>,
    /// 任务编排定义（DAG）。
    #[serde(default)]
    pub orchestration: Vec<OrchestrationNode>,
    /// 纳管模式。
    pub onboarding: crate::agent::OnboardingMode,
    /// 是否与平台台账同步。
    pub synced: bool,
    /// 云侧更新时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_updated_at: Option<Timestamp>,
    /// 本地记录时间。
    pub created_at: Timestamp,
    /// 更新时间。
    pub updated_at: Timestamp,
}

/// 团队成员（Agent）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTeamMember {
    /// 云侧 agent id。
    pub cloud_agent_id: String,
    /// 名称。
    pub name: String,
    /// 引用的模型端点。
    #[serde(default)]
    pub models: Vec<String>,
    /// 引用的工具/Skill 名。
    #[serde(default)]
    pub tools: Vec<String>,
    /// 绑定的角色名。
    #[serde(default)]
    pub role_names: Vec<String>,
    /// 映射到的平台资产 id（免改造纳管后填充）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<Id>,
    /// 运行状态。
    #[serde(default)]
    pub status: String,
}

/// 团队角色（映射平台 RBAC 权限模型）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTeamRole {
    /// 角色名。
    pub name: String,
    /// 描述。
    #[serde(default)]
    pub description: String,
    /// 允许的工具。
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    /// 映射到平台角色名。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapped_platform_role: Option<String>,
}

/// 任务编排节点。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestrationNode {
    /// 节点 id。
    pub node_id: String,
    /// 节点名。
    pub name: String,
    /// 执行的 Agent（云侧 id）。
    #[serde(default)]
    pub agent_ids: Vec<String>,
    /// 依赖的上游节点。
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// 触发方式（`manual` / `cron` / `event`）。
    #[serde(default)]
    pub trigger: String,
    /// cron 表达式。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cron: Option<String>,
}

/// 跨 Team 调用链（可视化）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossTeamCall {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 调用方 team id。
    pub from_team_id: String,
    /// 调用方 agent id。
    pub from_agent_id: String,
    /// 被调用 team id。
    pub to_team_id: String,
    /// 被调用 agent id。
    pub to_agent_id: String,
    /// 调用类型（`a2a` / `mcp` / `model`）。
    pub call_kind: String,
    /// 是否跨账号。
    pub cross_account: bool,
    /// 是否被策略阻断。
    pub blocked: bool,
    /// 耗时（毫秒）。
    pub latency_ms: u64,
    /// 发生时间。
    pub at: Timestamp,
}

/// 配额双向同步状态（§5.1：冲突以平台为准并告警）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaSyncState {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 集成 id。
    pub integration_id: Id,
    /// 配额维度。
    pub dimension: crate::enums::QuotaDimension,
    /// 平台侧值。
    pub platform_value: i64,
    /// 云侧值。
    pub cloud_value: i64,
    /// 是否冲突。
    pub conflict: bool,
    /// 最终生效值（以平台为准）。
    pub effective_value: i64,
    /// 冲突告警是否已发出。
    #[serde(default)]
    pub conflict_alerted: bool,
    /// 最近同步时间。
    pub synced_at: Timestamp,
}

/// 定时任务注册（SchedulerX3 与本地 tokio-cron 双模，§5.2）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleRegistration {
    /// 主键。
    pub id: Id,
    /// 租户。
    pub tenant_id: TenantId,
    /// 任务名。
    pub name: String,
    /// 任务类型（`asset-inventory` / `log-pull` / `redteam-cruise` / `rule-hot-reload` / `report` / `archive`）。
    pub job_kind: String,
    /// cron 表达式。
    pub cron: String,
    /// 执行后端。
    pub backend: ScheduleBackend,
    /// 云端 job id（注册成功后回填）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_job_id: Option<String>,
    /// 分片数。
    #[serde(default = "default_one")]
    pub shard_count: u32,
    /// 失败重试次数。
    #[serde(default = "default_retries")]
    pub max_retries: u32,
    /// 依赖的上游任务 id。
    #[serde(default)]
    pub depends_on: Vec<Id>,
    /// 是否启用。
    pub enabled: bool,
    /// 上次执行时间。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_run_at: Option<Timestamp>,
    /// 上次执行结果。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_result: Option<String>,
    /// 创建时间。
    pub created_at: Timestamp,
}

const fn default_one() -> u32 {
    1
}

const fn default_retries() -> u32 {
    3
}

/// 调度后端。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScheduleBackend {
    /// 阿里云 SchedulerX3。
    SchedulerX3,
    /// 本地 tokio-cron（无云环境默认）。
    LocalCron,
    /// K8s CronJob。
    K8sCronJob,
    /// 进程内周期任务（简单固定间隔）。
    Interval,
}

mod impl_cloud_provider;
#[cfg(test)]
mod tests;
