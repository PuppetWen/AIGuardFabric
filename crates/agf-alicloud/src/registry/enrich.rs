//! 由 `registry.rs` 拆分：`enrich` 等 6 个函数（纯搬移，逻辑不变）。
use super::*;

/// 把真实核心的 endpoint / 凭据 / 模式信息复制到自检用的核心副本上。
pub(crate) fn enrich(target: &mut mock::AdapterCore, source: &mock::AdapterCore) {
    target.mode = source.mode;
    target.region = source.region.clone();
    target.account_id = source.account_id.clone();
    target.tenant_id = source.tenant_id;
    target.endpoint = source.endpoint.clone();
    target.credential = source.credential.clone();
    if source.mode != AdapterMode::Unconfigured {
        target.unconfigured_reason = None;
    }
}

/// Mock 模式的全部服务记录。
pub(crate) fn mock_records() -> BTreeMap<String, ServiceRecord> {
    AliCloudService::all()
        .iter()
        .map(|service| {
            (
                service.as_str().to_string(),
                ServiceRecord {
                    service: *service,
                    descriptor: mock::descriptor_of(*service),
                    configured: false,
                    mode: AdapterMode::Mocked,
                    enabled: true,
                    config_id: None,
                    integration_id: None,
                    capabilities: mock::capabilities_of(*service),
                    note: "无云凭据环境：以 Mock 模式运行（确定性 fixtures，不触达云 API）".to_string(),
                },
            )
        })
        .collect()
}

/// 取某服务的可变适配器引用（`from_configs` 初始化用）。
pub(crate) fn adapter_mut<'a>(
    service: AliCloudService,
    cms: &'a mut CmsAdapter,
    apig: &'a mut ApigAdapter,
    mse: &'a mut MseAdapter,
    privatelink: &'a mut PrivatelinkAdapter,
    schedulerx3: &'a mut SchedulerX3Adapter,
    agentteams: &'a mut AgentTeamsAdapter,
) -> &'a mut dyn Adapter {
    match service {
        AliCloudService::Cms => cms,
        AliCloudService::Apig => apig,
        AliCloudService::Mse => mse,
        AliCloudService::Privatelink => privatelink,
        AliCloudService::SchedulerX3 => schedulerx3,
        AliCloudService::AgentTeams => agentteams,
    }
}

/// 读取某服务当前模式。
pub(crate) fn target_mode(
    service: AliCloudService,
    cms: &CmsAdapter,
    apig: &ApigAdapter,
    mse: &MseAdapter,
    privatelink: &PrivatelinkAdapter,
    schedulerx3: &SchedulerX3Adapter,
    agentteams: &AgentTeamsAdapter,
) -> AdapterMode {
    match service {
        AliCloudService::Cms => cms.mode(),
        AliCloudService::Apig => apig.mode(),
        AliCloudService::Mse => mse.mode(),
        AliCloudService::Privatelink => privatelink.mode(),
        AliCloudService::SchedulerX3 => schedulerx3.mode(),
        AliCloudService::AgentTeams => agentteams.mode(),
    }
}

/// 控制台"接入管理"页要展示的一行（服务 → 关键状态）。
#[must_use]
pub fn console_row(record: &ServiceRecord) -> BTreeMap<String, String> {
    let mut row = BTreeMap::new();
    row.insert("service".to_string(), record.service.as_str().to_string());
    row.insert("display_name".to_string(), record.descriptor.display_name.clone());
    row.insert("mode".to_string(), record.mode.as_str().to_string());
    row.insert("enabled".to_string(), record.enabled.to_string());
    row.insert(
        "capabilities".to_string(),
        record.capabilities.iter().map(agf_core::adapter::AdapterCapability::as_str).collect::<Vec<_>>().join(","),
    );
    row.insert("degradation".to_string(), record.descriptor.degradation.clone());
    row.insert("mock_location".to_string(), record.descriptor.mock_location.clone());
    row.insert("doc_anchor".to_string(), record.descriptor.doc_anchor.clone());
    row
}

/// 把配置列表按服务拆分（控制台编辑页保存时用）。
///
/// # Errors
/// 出现两个同服务的配置时返回 [`DomainError::Conflict`]（同一服务只允许一个默认实例）。
pub fn index_configs(configs: &[AdapterConfig]) -> DomainResult<BTreeMap<String, AdapterConfig>> {
    let mut out = BTreeMap::new();
    for config in configs {
        if out.insert(config.adapter.clone(), config.clone()).is_some() {
            return Err(DomainError::Conflict(format!(
                "适配器 {} 存在重复配置；同一服务只允许一个实例",
                config.adapter
            )));
        }
    }
    Ok(out)
}
