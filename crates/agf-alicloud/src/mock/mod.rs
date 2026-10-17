//! Mock 实现（六个服务 + AgentTeams 共享 fixtures）+ 适配器公共内核。
//!
//! ## 两种运行形态，同一套接口
//!
//! 本 crate 的策略是**"一个适配器，两种模式"**：
//!
//! - `AdapterMode::Live`：走签名 RPC（[`crate::http::RpcClient`]）；
//! - `AdapterMode::Mocked`：走本模块的**确定性 fixtures**，业务方法签名逐字相同。
//!
//! [`crate::http::RpcClient::live`] 会拒绝为 Mock 模式构造客户端，因此 Mock 路径在
//! 类型与运行时两层都不可能触网。把两种模式放进同一结构体（而不是两份 `impl`）的
//! 好处是**接口签名由编译器保证一致**，代价是真实分支需显式 `self.live_client()?`。
//!
//! ## Mock 入口
//!
//! | 服务 | Mock 构造器 | 确定性 fixtures |
//! |---|---|---|
//! | CMS | [`mock_cms`] | [`cms_alarm_histories`] |
//! | APIG | [`mock_apig`] | [`apig_gateways`] / [`apig_routes`] / [`apig_plugins`] |
//! | MSE | [`mock_mse`] | [`mse_services`] / [`mse_configs`] |
//! | Privatelink | [`mock_privatelink`] | [`privatelink_endpoints`] / [`privatelink_probe`] |
//! | SchedulerX3 | [`mock_schedulerx3`] | [`schedulerx3_jobs`] |
//! | AgentTeams | [`mock_agentteams`] | [`agentteams_teams`] / [`agentteams_cross_calls`] |
//!
//! fixtures 使用 [`TenantId::default_tenant`] 与 `deterministic_id`，因此**可复现、可断言具体值**。

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::sync::Arc;

pub(crate) use agf_core::adapter::AdapterCapability;
pub(crate) use agf_core::adapter::AdapterConfig;
pub(crate) use agf_core::adapter::AdapterDescriptor;
pub(crate) use agf_core::adapter::AdapterHealth;
pub(crate) use agf_core::adapter::CircuitBreakerConfig;
pub(crate) use agf_core::adapter::CircuitSnapshot;
pub(crate) use agf_core::adapter::CircuitState;
pub(crate) use agf_core::adapter::PullRequest;
pub(crate) use agf_core::adapter::RetryConfig;

pub(crate) use agf_core::agent::OnboardingMode;

pub(crate) use agf_core::cloud::AgentTeam;
pub(crate) use agf_core::cloud::AgentTeamMember;
pub(crate) use agf_core::cloud::AgentTeamRole;
pub(crate) use agf_core::cloud::CloudIntegration;
pub(crate) use agf_core::cloud::CloudProvider;
pub(crate) use agf_core::cloud::CrossTeamCall;
pub(crate) use agf_core::cloud::OrchestrationNode;

pub(crate) use agf_core::enums::AliCloudService;
pub(crate) use agf_core::enums::HealthState;
pub(crate) use agf_core::enums::QuotaDimension;
pub(crate) use agf_core::enums::Severity;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::ids::Id;
pub(crate) use agf_core::ids::NS_AGENT;
pub(crate) use agf_core::ids::TenantId;
pub(crate) use agf_core::ids::deterministic_id;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use crate::AdapterMode;

pub(crate) use crate::agentteams::AgentTeamsAdapter;

pub(crate) use crate::apig::ApigAdapter;
pub(crate) use crate::apig::ApigGateway;
pub(crate) use crate::apig::ApigPlugin;
pub(crate) use crate::apig::ApigRoute;

pub(crate) use crate::cms::CmsAdapter;
pub(crate) use crate::cms::CmsAlarmHistory;
pub(crate) use crate::cms::CmsEvent;
pub(crate) use crate::cms::CmsMetric;

pub(crate) use crate::credential::AssumeRoleResolver;
pub(crate) use crate::credential::CloudCredential;
pub(crate) use crate::credential::CredentialContext;
pub(crate) use crate::credential::CredentialOutcome;
pub(crate) use crate::credential::CredentialResolver;
pub(crate) use crate::credential::CredentialWarning;
pub(crate) use crate::credential::EnvResolver;
pub(crate) use crate::credential::MapSecretStore;
pub(crate) use crate::credential::REFRESH_THRESHOLD_SECS;
pub(crate) use crate::credential::StaticResolver;

pub(crate) use crate::endpoint::EndpointStyle;
pub(crate) use crate::endpoint::ResolvedEndpoint;
pub(crate) use crate::endpoint::resolve;

pub(crate) use crate::http::RecordingTransport;
pub(crate) use crate::http::ReqwestTransport;
pub(crate) use crate::http::RpcClient;
pub(crate) use crate::http::RpcClientConfig;
pub(crate) use crate::http::SignStyle;
pub(crate) use crate::http::TlsPolicy;

pub(crate) use crate::mse::MseAdapter;
pub(crate) use crate::mse::MseCluster;
pub(crate) use crate::mse::MseConfig;
pub(crate) use crate::mse::MseService;

pub(crate) use crate::privatelink::PrivatelinkAdapter;
pub(crate) use crate::privatelink::PrivatelinkEndpoint;
pub(crate) use crate::privatelink::PrivatelinkProbe;

pub(crate) use crate::schedulerx3::SchedulerX3Adapter;
pub(crate) use crate::schedulerx3::SchedulerX3Execution;
pub(crate) use crate::schedulerx3::SchedulerX3Job;

#[allow(unused_imports)]
pub use apig_access_logs::*;
#[allow(unused_imports)]
pub use capabilities_of::*;
#[allow(unused_imports)]
pub use fixture_cloud_integration::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// fixture 客户账号 id。
pub const FIXTURE_ACCOUNT_ID: &str = "1234567890";

/// fixture 地域。
pub const FIXTURE_REGION: &str = "cn-hangzhou";

/// fixture 客户名。
pub const FIXTURE_INTEGRATION_NAME: &str = "Mock 云账号";

/// Mock 模式下的确定性 AccessKeyId（**不是真实凭据**）。
pub const FIXTURE_ACCESS_KEY_ID: &str = "LTAI5tFixtureMockOnly00";

/// Mock 模式下的确定性 AccessKeySecret（**不是真实凭据**）。
pub const FIXTURE_ACCESS_KEY_SECRET: &str = "fixture-mock-secret-not-real";

/// fixture 团队 id。
pub const FIXTURE_TEAM_IDS: [&str; 3] = ["team-risk", "team-research", "team-ops"];

/// 平台默认调度任务的稳定 id 命名空间。
pub const NS_SCHEDULE: &str = "aiguardfabric.alicloud.schedule";

/// AgentTeams id 命名空间。
pub const NS_TEAM: &str = "aiguardfabric.alicloud.agentteams";

// ---------------------------------------------------------------------------
// 公共内核
// ---------------------------------------------------------------------------

/// 适配器共享内核：模式、配置快照、endpoint、凭据、熔断。
pub struct AdapterCore {
    /// 服务。
    pub service: AliCloudService,
    /// 运行模式。
    pub mode: AdapterMode,
    /// 未配置原因。
    pub unconfigured_reason: Option<String>,
    /// 地域。
    pub region: String,
    /// 账号 id。
    pub account_id: String,
    /// 租户。
    pub tenant_id: TenantId,
    /// Endpoint 风格。
    pub style: EndpointStyle,
    /// 签名风格。
    pub sign_style: SignStyle,
    /// 超时（秒）。
    pub timeout_secs: u64,
    /// endpoint 覆盖。
    pub endpoint_overrides: BTreeMap<String, String>,
    /// 自定义信任锚（`settings.ca_pem`，PEM 文本；仅 `AGF_ENV=dev` 或显式开关下生效）。
    pub tls_ca_pem: Option<String>,
    /// 跳过证书校验（`settings.insecure_tls`；同样只允许 dev/显式开关）。
    pub tls_allow_insecure: bool,
    /// 已解析 endpoint。
    pub endpoint: Option<ResolvedEndpoint>,
    /// 凭据。
    pub credential: Option<CloudCredential>,
    /// 凭据风险告警。
    pub credential_warnings: Vec<CredentialWarning>,
    /// 熔断配置。
    pub circuit_config: CircuitBreakerConfig,
    /// 重试配置。
    pub retry_config: RetryConfig,
    /// 熔断快照。
    pub circuit: CircuitSnapshot,
    /// 配置主键。
    pub config_id: Option<Id>,
}

/// 各服务降级行为说明（控制台直接展示）。
#[must_use]
pub const fn degradation_of(service: AliCloudService) -> &'static str {
    match service {
        AliCloudService::Cms => {
            "未配置时不上报自定义事件与指标（本地事件照常落库），报警订阅回退为 ingest 侧本地轮询；平台主流程与已入库数据不受影响"
        }
        AliCloudService::Apig => {
            "未配置时不下发限流/Token 配额/内容安全/模型路由策略，agf-aigw 继续用本地策略兜底并记告警；访问日志改用本地采集通道"
        }
        AliCloudService::Mse => {
            "未配置时停止 Nacos 服务清单同步与配置热更新，资产发现回退为网段扫描 + 终端上报；已有资产标记 stale 但绝不删除"
        }
        AliCloudService::Privatelink => {
            "未配置时私网探测不可用，连通性判定降级为「未知」而非「不通」；采集器继续本地缓存并在恢复后补传"
        }
        AliCloudService::SchedulerX3 => {
            "未配置时全部云任务回退本地 tokio-cron（ScheduleBackend::fallback），无云环境零配置可用；分片退化为单实例串行"
        }
        AliCloudService::AgentTeams => {
            "未配置时台账只读：停止双向同步与配额下发，平台侧配置继续生效（平台为准）；审计事件缺失由网关侧流量审计补位"
        }
    }
}

/// Mock 构造器名。
#[must_use]
pub const fn mock_constructor_name(service: AliCloudService) -> &'static str {
    match service {
        AliCloudService::Cms => "mock_cms",
        AliCloudService::Apig => "mock_apig",
        AliCloudService::Mse => "mock_mse",
        AliCloudService::Privatelink => "mock_privatelink",
        AliCloudService::SchedulerX3 => "mock_schedulerx3",
        AliCloudService::AgentTeams => "mock_agentteams",
    }
}

/// 各服务文档锚点。
#[must_use]
pub const fn doc_anchor_of(service: AliCloudService) -> &'static str {
    match service {
        AliCloudService::Cms => "docs/adapter-spec.md#alicloud-cms",
        AliCloudService::Apig => "docs/adapter-spec.md#alicloud-apig",
        AliCloudService::Mse => "docs/adapter-spec.md#alicloud-mse",
        AliCloudService::Privatelink => "docs/adapter-spec.md#alicloud-privatelink",
        AliCloudService::SchedulerX3 => "docs/adapter-spec.md#alicloud-schedulerx3",
        AliCloudService::AgentTeams => "docs/adapter-spec.md#alicloud-agentteams",
    }
}

/// 各服务显示名。
#[must_use]
pub const fn display_name_of(service: AliCloudService) -> &'static str {
    match service {
        AliCloudService::Cms => "阿里云云监控（CMS）",
        AliCloudService::Apig => "阿里云 AI 网关（APIG）",
        AliCloudService::Mse => "阿里云微服务引擎（MSE）",
        AliCloudService::Privatelink => "阿里云私网链接（PrivateLink）",
        AliCloudService::SchedulerX3 => "阿里云分布式任务调度（SchedulerX3）",
        AliCloudService::AgentTeams => "阿里云 AgentTeams 多智能体治理",
    }
}

/// Mock：`(配额维度, 平台值, 云侧值)`——第 1、3 项故意不一致以触发冲突告警。
#[must_use]
pub const fn agentteams_quota_fixture() -> [(QuotaDimension, i64, i64); 4] {
    use QuotaDimension::{Concurrency, Cost, Requests, Tokens};
    [(Tokens, 1_000_000, 500_000), (Requests, 50_000, 50_000), (Concurrency, 32, 16), (Cost, 20_000, 20_000)]
}

mod apig_access_logs;
mod capabilities_of;
mod fixture_cloud_integration;
#[cfg(test)]
mod tests;
