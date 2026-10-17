//! 阿里云适配器注册表：按配置构建六个适配器、暴露描述符、汇总健康与自检（控制台"接入管理/阿里云"页）。
//!
//! ## 六个适配器一起构建的收益
//!
//! 1. **描述符口径统一**：六个 `descriptor()` 都来自 [`crate::mock::descriptor_of`]，
//!    不会出现"某个服务的降级行为没写"；
//! 2. **自检可聚合**：一次 `self_check_suite()` 产出六个服务的报告 + 合并后的 RAM 策略，
//!    直接喂给"云环境自检"页；
//! 3. **热插拔有据可依**：控制台按 [`ServiceRecord`] 决定是否启用某个服务，
//!    未配置的服务保持 `Unconfigured` 而**不影响平台启动**。

pub(crate) use std::collections::BTreeMap;

pub(crate) use std::sync::Arc;

pub(crate) use agf_core::adapter::Adapter;
pub(crate) use agf_core::adapter::AdapterCapability;
pub(crate) use agf_core::adapter::AdapterConfig;
pub(crate) use agf_core::adapter::AdapterDescriptor;
pub(crate) use agf_core::adapter::AdapterHealth;

pub(crate) use agf_core::enums::AliCloudService;

pub(crate) use agf_core::error::DomainError;
pub(crate) use agf_core::error::DomainResult;

pub(crate) use agf_core::ids::TenantId;

pub(crate) use serde::Deserialize;
pub(crate) use serde::Serialize;

pub(crate) use crate::agentteams::AgentTeamsAdapter;

pub(crate) use crate::apig::ApigAdapter;

pub(crate) use crate::cms::CmsAdapter;

pub(crate) use crate::mse::MseAdapter;

pub(crate) use crate::privatelink::PrivatelinkAdapter;

pub(crate) use crate::schedulerx3::SchedulerX3Adapter;

pub(crate) use crate::selfcheck::CloudSelfCheckReport;
pub(crate) use crate::selfcheck::CloudSelfCheckSuite;
pub(crate) use crate::selfcheck::build_report;

pub(crate) use crate::AdapterMode;
pub(crate) use crate::mock;

#[cfg(test)]
pub(crate) use crate::test_support::fixture_config;

#[allow(unused_imports)]
pub use enrich::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 一个服务的控制台展示记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRecord {
    /// 服务。
    pub service: AliCloudService,
    /// 适配器描述符（含降级行为与 Mock 位置）。
    pub descriptor: AdapterDescriptor,
    /// 是否已配置（有凭据或显式 Mock）。
    pub configured: bool,
    /// 运行模式。
    pub mode: AdapterMode,
    /// 是否启用（`AdapterConfig::enabled`）。
    pub enabled: bool,
    /// 配置主键。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_id: Option<agf_core::ids::Id>,
    /// 关联的云集成 id（若配置里指定）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integration_id: Option<agf_core::ids::Id>,
    /// 能力。
    pub capabilities: Vec<AdapterCapability>,
    /// 说明。
    pub note: String,
}

/// 六个适配器组成的注册表。
pub struct AliCloudRegistry {
    cms: Arc<CmsAdapter>,
    apig: Arc<ApigAdapter>,
    mse: Arc<MseAdapter>,
    privatelink: Arc<PrivatelinkAdapter>,
    schedulerx3: Arc<SchedulerX3Adapter>,
    agentteams: Arc<AgentTeamsAdapter>,
    records: BTreeMap<String, ServiceRecord>,
}

mod enrich;
mod impl_service_record;
#[cfg(test)]
mod tests;
