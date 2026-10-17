//! 云环境自检（§5.3）：连通性 / 最小权限 / 配额余量，产出 [`CloudSelfCheckReport`] 供控制台"云环境自检"页。
//!
//! ## 三类判定
//!
//! 1. **连通性**：能不能拿到凭据 + 能不能解析出合法 endpoint。**未配置不是故障**，
//!    结论为"未配置（降级为不触达云 API）"；Mock 模式结论为"Mock 模式：未真实校验"。
//! 2. **最小权限**：逐项列出该服务**必需**的 RAM Action（[`required_permissions`]）。
//!    必需项未通过 → [`PermissionCheck::is_blocking`] 为真，自检页标红并阻断接入。
//! 3. **配额余量**：核心 API 的日配额（[`QuotaHeadroom`]）；已用超过 90% 告警。
//!
//! ## 为什么权限清单要写在代码里
//!
//! "最小权限"必须可交付：运维需要一份可以直接照抄到 RAM 自定义策略里的 Action 清单。
//! 把它做成常量（[`required_permissions`]），既让自检页可渲染，也避免文档与实际实现漂移。

pub(crate) use std::collections::BTreeMap;

pub(crate) use agf_core::cloud::PermissionCheck;

pub(crate) use agf_core::enums::AliCloudService;
pub(crate) use agf_core::enums::HealthState;
pub(crate) use agf_core::enums::Severity;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::ids::Id;

pub(crate) use agf_core::time::Timestamp;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use crate::AdapterMode;

pub(crate) use crate::mock::AdapterCore;

#[allow(unused_imports)]
pub use impl_quota_headroom::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 配额告警阈值（已用占比）。
pub const QUOTA_WARN_RATIO: f64 = 0.9;

/// 一条配额余量记录。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuotaHeadroom {
    /// 服务。
    pub service: AliCloudService,
    /// 配额维度（如 `PutCustomEvent/日`）。
    pub dimension: String,
    /// 上限。
    pub limit: i64,
    /// 已用。
    pub used: i64,
    /// 检查时间。
    pub checked_at: Timestamp,
}

/// 自检报告（控制台"云环境自检"页数据源）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudSelfCheckReport {
    /// 适配器名。
    pub adapter: String,
    /// 服务。
    pub service: AliCloudService,
    /// 运行模式。
    pub mode: AdapterMode,
    /// 集成 id。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integration_id: Option<Id>,
    /// 连通性结论（中文，直接展示）。
    pub connectivity: String,
    /// 连通性是否通过。
    pub connectivity_ok: bool,
    /// 延迟（毫秒）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    /// 权限检查项。
    pub permission_checks: Vec<PermissionCheck>,
    /// 配额余量。
    pub quotas: Vec<QuotaHeadroom>,
    /// 综合状态。
    pub state: HealthState,
    /// 实际生效的 TLS 策略。
    ///
    /// `custom-ca` / `insecure-skip-verify` 表示**已放松证书校验**（仅 dev/显式开关可生效），
    /// 会在 [`CloudSelfCheckReport::readyz_notes`] 里显式标注，供 `/readyz` 与自检页展示。
    #[serde(default = "default_tls_policy")]
    pub tls_policy: crate::http::TlsPolicy,
    /// 检查时间。
    pub checked_at: Timestamp,
}

/// 全部服务的必需权限清单（策略 JSON 与自检页共用）。
#[must_use]
pub const fn required_permissions(service: AliCloudService) -> &'static [&'static str] {
    match service {
        AliCloudService::Cms => &["cms:DescribeAlertHistoryList"],
        AliCloudService::Apig => &["apig:ListGateways"],
        AliCloudService::Mse => &["mse:ListClusters"],
        AliCloudService::Privatelink => &["privatelink:ListVpcEndpoints"],
        AliCloudService::SchedulerX3 => &["schedulerx3:ListJobs"],
        // This version has no published RAM action matrix. Never invent authorization actions.
        AliCloudService::AgentTeams => &[],
    }
}

/// Extra permissions are requested only for the explicitly selected operation.
#[must_use]
pub const fn optional_permissions(service: AliCloudService) -> &'static [&'static str] {
    match service {
        AliCloudService::Cms => &["cms:PutCustomEvent", "cms:PutCustomMetric"],
        AliCloudService::Apig => {
            &["apig:ListHttpApis", "apig:ListHttpApiRoutes", "apig:ListPlugins", "apig:CreatePluginAttachment"]
        }
        AliCloudService::Mse => {
            &["mse:ListAnsServices", "mse:GetNacosConfig", "mse:CreateNacosConfig", "mse:UpdateNacosConfig"]
        }
        AliCloudService::Privatelink => {
            &["privatelink:GetVpcEndpointAttribute", "privatelink:ListVpcEndpointSecurityGroups"]
        }
        AliCloudService::SchedulerX3 => {
            &["schedulerx3:CreateJob", "schedulerx3:UpdateJob", "schedulerx3:ListJobExecutions"]
        }
        AliCloudService::AgentTeams => &[],
    }
}

/// 服务的配额定义：`(API 维度, 日配额上限, 预计已用占比)`。
///
/// 仅供 Mock 演示：不是当前云端配额或实际使用量；
/// 这里给出确定性数值，使自检页在无云环境也能渲染出有意义的余量视图。
#[must_use]
pub const fn quota_definitions(service: AliCloudService) -> &'static [(&'static str, i64, f64)] {
    match service {
        AliCloudService::Cms => &[("PutCustomEvent/日", 5_000_000, 0.12), ("PutCustomMetric/日", 5_000_000, 0.35)],
        AliCloudService::Apig => &[("API 调用/日", 1_000_000, 0.21)],
        AliCloudService::Mse => &[("Nacos 配置推送/日", 100_000, 0.08)],
        AliCloudService::Privatelink => &[("终端节点/地域", 100, 0.02)],
        AliCloudService::SchedulerX3 => &[("任务执行/日", 200_000, 0.93)],
        AliCloudService::AgentTeams => &[("配额更新/日", 10_000, 0.40)],
    }
}

/// 多云聚合报告（控制台"云环境自检"页顶部）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudSelfCheckSuite {
    /// 各服务报告。
    pub reports: Vec<CloudSelfCheckReport>,
}

mod impl_cloud_self_check_suite;
mod impl_quota_headroom;
#[cfg(test)]
mod tests;
