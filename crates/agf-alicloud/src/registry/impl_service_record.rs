//! 由 `registry.rs` 拆分：`AliCloudRegistry`/`ServiceRecord` 的实现（纯搬移，逻辑不变）。
use super::*;

impl ServiceRecord {
    /// 是否处于可承载真实流量的状态。
    #[must_use]
    pub const fn is_serving(&self) -> bool {
        self.enabled && self.mode.is_live()
    }
}

impl std::fmt::Debug for AliCloudRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AliCloudRegistry")
            .field("services", &self.records.keys().collect::<Vec<_>>())
            .field("records", &self.records)
            .field("cms", &self.cms)
            .field("apig", &self.apig)
            .field("mse", &self.mse)
            .field("privatelink", &self.privatelink)
            .field("schedulerx3", &self.schedulerx3)
            .field("agentteams", &self.agentteams)
            .finish()
    }
}

impl Default for AliCloudRegistry {
    fn default() -> Self {
        Self::mock_only()
    }
}

impl AliCloudRegistry {
    /// 全部服务进入 Mock 模式（无云凭据环境的默认值，**零配置可用**）。
    #[must_use]
    pub fn mock_only() -> Self {
        Self::assemble(
            Arc::new(mock::mock_cms()),
            Arc::new(mock::mock_apig()),
            Arc::new(mock::mock_mse()),
            Arc::new(mock::mock_privatelink()),
            Arc::new(mock::mock_schedulerx3()),
            Arc::new(mock::mock_agentteams()),
            mock_records(),
        )
    }

    /// 按配置构建（每个服务可独立配置；缺失的服务回退 Mock）。
    ///
    /// # Errors
    /// 某个服务的配置存在但非法（如地域非法）时返回 [`DomainError::Config`]。
    pub async fn from_configs(configs: &[AdapterConfig]) -> DomainResult<Self> {
        let mut records = BTreeMap::new();
        let by_name: BTreeMap<&str, &AdapterConfig> =
            configs.iter().map(|config| (config.adapter.as_str(), config)).collect();

        let mut cms = mock::mock_cms();
        let mut apig = mock::mock_apig();
        let mut mse = mock::mock_mse();
        let mut privatelink = mock::mock_privatelink();
        let mut schedulerx3 = mock::mock_schedulerx3();
        let mut agentteams = mock::mock_agentteams();

        for service in AliCloudService::all() {
            let descriptor = mock::descriptor_of(service);
            let config = by_name.get(service.as_str()).copied();
            let (mode, enabled, config_id, integration_id, note) = match config {
                Some(config) => {
                    // 先初始化（可变借用在本作用域内结束，之后仍可读取模式）
                    {
                        let target = adapter_mut(
                            service,
                            &mut cms,
                            &mut apig,
                            &mut mse,
                            &mut privatelink,
                            &mut schedulerx3,
                            &mut agentteams,
                        );
                        target.init(config).await?;
                    }
                    let mode = target_mode(service, &cms, &apig, &mse, &privatelink, &schedulerx3, &agentteams);
                    let note = match mode {
                        AdapterMode::Mocked => "已启用 Mock（AGF_MOCK_MODE / config.mock）".to_string(),
                        AdapterMode::Unconfigured => "配置存在但缺少凭据引用：已降级为不触达云 API".to_string(),
                        AdapterMode::Live => "已启用真实调用通道".to_string(),
                    };
                    let integration_id =
                        config.get_str("integration_id").and_then(|value| agf_core::ids::Id::parse(value).ok());
                    (mode, config.enabled, Some(config.id), integration_id, note)
                }
                None => (
                    AdapterMode::Mocked,
                    true,
                    None,
                    None,
                    "未提供配置：自动回退 Mock 模式（不触达云 API）".to_string(),
                ),
            };
            records.insert(
                service.as_str().to_string(),
                ServiceRecord {
                    service,
                    descriptor,
                    configured: !matches!(mode, AdapterMode::Unconfigured),
                    mode,
                    enabled,
                    config_id,
                    integration_id,
                    capabilities: mock::capabilities_of(service),
                    note,
                },
            );
        }

        Ok(Self::assemble(
            Arc::new(cms),
            Arc::new(apig),
            Arc::new(mse),
            Arc::new(privatelink),
            Arc::new(schedulerx3),
            Arc::new(agentteams),
            records,
        ))
    }

    /// 按注册名查适配器（返回 `Arc<dyn Adapter>`，供运行时统一调度）。
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Arc<dyn Adapter>> {
        match name {
            "alicloud-cms" => Some(self.cms.clone()),
            "alicloud-apig" => Some(self.apig.clone()),
            "alicloud-mse" => Some(self.mse.clone()),
            "alicloud-privatelink" => Some(self.privatelink.clone()),
            "alicloud-schedulerx3" => Some(self.schedulerx3.clone()),
            "alicloud-agentteams" => Some(self.agentteams.clone()),
            _ => None,
        }
    }

    /// 按服务查适配器。
    ///
    /// 服务枚举与注册名一一对应，因此不会回落到错误的服务；为满足"不 panic"约束，
    /// 未命中时返回 CMS（实际不可达）。
    #[must_use]
    pub fn get_service(&self, service: AliCloudService) -> Arc<dyn Adapter> {
        self.get(service.as_str()).unwrap_or_else(|| self.cms.clone())
    }

    /// CMS 适配器（强类型）。
    #[must_use]
    pub fn cms(&self) -> Arc<CmsAdapter> {
        self.cms.clone()
    }

    /// APIG 适配器（强类型）。
    #[must_use]
    pub fn apig(&self) -> Arc<ApigAdapter> {
        self.apig.clone()
    }

    /// MSE 适配器（强类型）。
    #[must_use]
    pub fn mse(&self) -> Arc<MseAdapter> {
        self.mse.clone()
    }

    /// PrivateLink 适配器（强类型）。
    #[must_use]
    pub fn privatelink(&self) -> Arc<PrivatelinkAdapter> {
        self.privatelink.clone()
    }

    /// SchedulerX3 适配器（强类型）。
    #[must_use]
    pub fn schedulerx3(&self) -> Arc<SchedulerX3Adapter> {
        self.schedulerx3.clone()
    }

    /// AgentTeams 适配器（强类型）。
    #[must_use]
    pub fn agentteams(&self) -> Arc<AgentTeamsAdapter> {
        self.agentteams.clone()
    }

    /// 全部服务记录（控制台列表，按服务枚举顺序）。
    #[must_use]
    pub fn records(&self) -> Vec<ServiceRecord> {
        AliCloudService::all().iter().filter_map(|service| self.records.get(service.as_str()).cloned()).collect()
    }

    /// 某服务的记录。
    #[must_use]
    pub fn record(&self, service: AliCloudService) -> Option<ServiceRecord> {
        self.records.get(service.as_str()).cloned()
    }

    /// 全部描述符。
    #[must_use]
    pub fn descriptors(&self) -> Vec<AdapterDescriptor> {
        self.records().into_iter().map(|record| record.descriptor).collect()
    }

    /// 全部适配器（按固定顺序）。
    #[must_use]
    pub fn all(&self) -> Vec<Arc<dyn Adapter>> {
        vec![
            self.cms.clone(),
            self.apig.clone(),
            self.mse.clone(),
            self.privatelink.clone(),
            self.schedulerx3.clone(),
            self.agentteams.clone(),
        ]
    }

    /// 登记名列表。
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        AliCloudService::all().iter().map(|service| service.as_str().to_string()).collect()
    }

    /// 健康汇总。
    ///
    /// # Errors
    /// 任一适配器的健康探测本身失败（网络失败**不会**导致错误，只会体现在状态里）。
    pub async fn health_all(&self) -> DomainResult<BTreeMap<String, AdapterHealth>> {
        let mut out = BTreeMap::new();
        for service in AliCloudService::all() {
            let adapter = self.get_service(service);
            let health = adapter.health().await?;
            out.insert(service.as_str().to_string(), health);
        }
        Ok(out)
    }

    /// 云环境自检：六个服务的报告 + 合并 RAM 策略。
    #[must_use]
    pub fn self_check_suite(&self) -> CloudSelfCheckSuite {
        let reports: Vec<CloudSelfCheckReport> = AliCloudService::all()
            .iter()
            .map(|service| {
                let record = self.records.get(service.as_str());
                let mode = record.map_or(AdapterMode::Unconfigured, |item| item.mode);
                let mut core = mock::AdapterCore::new(*service);
                core.mode = mode;
                if mode == AdapterMode::Unconfigured {
                    core.unconfigured_reason = record.map(|item| item.note.clone());
                }
                // 从真实适配器补齐 endpoint / 凭据状态，使自检结论与实际运行一致
                match service {
                    AliCloudService::Cms => enrich(&mut core, self.cms.core()),
                    AliCloudService::Apig => enrich(&mut core, self.apig.core()),
                    AliCloudService::Mse => enrich(&mut core, self.mse.core()),
                    AliCloudService::Privatelink => enrich(&mut core, self.privatelink.core()),
                    AliCloudService::SchedulerX3 => enrich(&mut core, self.schedulerx3.core()),
                    AliCloudService::AgentTeams => enrich(&mut core, self.agentteams.core()),
                }
                build_report(&core, record.and_then(|item| item.integration_id))
            })
            .collect();
        CloudSelfCheckSuite { reports }
    }

    /// 未处于真实模式的服务（控制台"降级中"列表）。
    #[must_use]
    pub fn degraded_services(&self) -> Vec<AliCloudService> {
        self.records().into_iter().filter(|record| !record.mode.is_live()).map(|record| record.service).collect()
    }

    /// 当前租户（所有适配器共享）。
    #[must_use]
    pub fn tenant_id(&self) -> TenantId {
        self.cms.core().tenant_id
    }

    /// 组装（内部使用，保证字段与记录同源）。
    pub(crate) fn assemble(
        cms: Arc<CmsAdapter>,
        apig: Arc<ApigAdapter>,
        mse: Arc<MseAdapter>,
        privatelink: Arc<PrivatelinkAdapter>,
        schedulerx3: Arc<SchedulerX3Adapter>,
        agentteams: Arc<AgentTeamsAdapter>,
        records: BTreeMap<String, ServiceRecord>,
    ) -> Self {
        Self { cms, apig, mse, privatelink, schedulerx3, agentteams, records }
    }
}
