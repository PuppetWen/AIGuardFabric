//! 由 `privatelink.rs` 拆分：`PrivatelinkAdapter`/`PrivatelinkEndpoint`/`WhitelistVerdict` 的实现（纯搬移，逻辑不变）。
use super::*;

impl PrivatelinkEndpoint {
    /// 是否可用（状态与连接都正常）。
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status.eq_ignore_ascii_case("Active") && self.connection_status.eq_ignore_ascii_case("Connected")
    }

    /// 是否多可用区（高可用要求）。
    #[must_use]
    pub fn is_multi_zone(&self) -> bool {
        self.zone_ids.len() >= 2
    }
}

impl WhitelistVerdict {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::NoIngress => "no-ingress",
            Self::Minimal => "minimal",
            Self::TooBroad => "too-broad",
            Self::PubliclyOpen => "publicly-open",
            Self::Unbound => "unbound",
        }
    }

    /// 是否可接受。
    #[must_use]
    pub const fn is_acceptable(&self) -> bool {
        matches!(self, Self::Minimal | Self::NoIngress)
    }

    /// 严重等级。
    #[must_use]
    pub const fn severity(&self) -> agf_core::enums::Severity {
        use agf_core::enums::Severity;
        match self {
            Self::Unknown => Severity::Medium,
            Self::NoIngress | Self::Minimal => Severity::Info,
            Self::TooBroad => Severity::High,
            Self::PubliclyOpen => Severity::Critical,
            Self::Unbound => Severity::Critical,
        }
    }
}

impl std::fmt::Debug for PrivatelinkAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivatelinkAdapter")
            .field("core", &self.core)
            .field("has_client", &self.client.is_some())
            .field("transport", &"<transport-double>")
            .finish_non_exhaustive()
    }
}

impl Default for PrivatelinkAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivatelinkAdapter {
    /// 未配置态构造。
    #[must_use]
    pub fn new() -> Self {
        Self {
            core: AdapterCore::new(AliCloudService::Privatelink),
            probe_port: None,
            ecs_endpoint: None,
            client: None,
            transport: null_transport(),
        }
    }

    /// Mock 模式构造。
    #[must_use]
    pub fn mocked() -> Self {
        let mut adapter = Self::new();
        adapter.core.mode = AdapterMode::Mocked;
        adapter.core.unconfigured_reason = None;
        adapter
    }

    /// 注入录制替身（测试用）。
    ///
    /// # Errors
    /// 缺少凭据或未初始化。
    pub fn with_recording_transport(&mut self, transport: Arc<dyn crate::http::Transport>) -> DomainResult<()> {
        self.client = Some(self.core.build_test_client(transport)?);
        Ok(())
    }

    /// 当前模式。
    #[must_use]
    pub const fn mode(&self) -> AdapterMode {
        self.core.mode()
    }

    /// 只读核心。
    #[must_use]
    pub const fn core(&self) -> &AdapterCore {
        &self.core
    }

    /// 可变核心。
    pub const fn core_mut(&mut self) -> &mut AdapterCore {
        &mut self.core
    }

    /// 传输替身句柄（Mock 模式下恒不被调用；测试用它断言"零网络"）。
    #[must_use]
    pub fn transport(&self) -> Arc<crate::http::RecordingTransport> {
        self.transport.clone()
    }

    /// 未配置时的连通性结论：**未知**（不是"不通"）。
    #[must_use]
    pub fn unknown_probe(target: &str) -> PrivatelinkProbe {
        PrivatelinkProbe {
            target: target.to_string(),
            reachable: false,
            latency_ms: 0,
            endpoint_id: String::new(),
            resolved_ip: String::new(),
            detail: "未配置 PrivateLink / 未初始化：连通性未知（降级为未知而非不通）".to_string(),
            at: Timestamp::now(),
        }
    }

    pub(crate) fn live_client(&self) -> DomainResult<&RpcClient> {
        if self.core.is_mock() {
            return Err(mock::mock_blocked(AliCloudService::Privatelink));
        }
        self.client.as_deref().ok_or_else(|| {
            mock::unavailable(AliCloudService::Privatelink, "适配器未初始化或凭据未就绪（无真实调用通道）")
        })
    }
}

#[async_trait]
impl Adapter for PrivatelinkAdapter {
    fn name(&self) -> &str {
        AliCloudService::Privatelink.as_str()
    }

    fn descriptor(&self) -> AdapterDescriptor {
        mock::descriptor_of(AliCloudService::Privatelink)
    }

    async fn init(&mut self, config: &AdapterConfig) -> DomainResult<()> {
        self.core.load_from_config(config)?;
        self.ecs_endpoint = config.get_str("ecs_endpoint").filter(|s| !s.trim().is_empty()).map(str::to_owned);
        self.probe_port = config
            .settings
            .get("probe_port")
            .map(|value| {
                value
                    .as_u64()
                    .and_then(|port| u16::try_from(port).ok())
                    .filter(|port| *port > 0)
                    .ok_or_else(|| DomainError::Config("probe_port 必须为 1 至 65535 的整数".into()))
            })
            .transpose()?;
        self.client = self.core.build_live_client();
        mock::log_init(AliCloudService::Privatelink, self.core.mode());
        Ok(())
    }

    async fn health(&self) -> DomainResult<AdapterHealth> {
        Ok(self.core.health_of())
    }

    async fn sync(&self, direction: SyncDirection, req: &PullRequest) -> DomainResult<SyncOutcome> {
        let started = std::time::Instant::now();
        let mut outcome = SyncOutcome {
            mocked: self.core.is_mock(),
            degraded: !self.core.is_live(),
            finished_at: Some(Timestamp::now()),
            ..SyncOutcome::default()
        };
        if direction.includes_pull() {
            let endpoints = self.pull_endpoints().await?;
            let checks = self.check_security_groups().await?;
            outcome.pulled = endpoints.len();
            outcome.changes.insert("vpc_endpoint".to_string(), endpoints.len());
            outcome
                .changes
                .insert("endpoint_inactive".to_string(), endpoints.iter().filter(|e| !e.is_active()).count());
            outcome.changes.insert("security_group".to_string(), checks.len());
            let risky = checks.iter().filter(|c| !c.verdict.is_acceptable()).count();
            outcome.changes.insert("whitelist_risky".to_string(), risky);
            if risky > 0 {
                outcome.warnings.push(format!(
                    "{risky} 个安全组需要复核（规则未知、过宽或含公网来源），需按最小化要求收敛（详见 self_check）"
                ));
            }
            // 探测每个终端节点对应的私网域名（Mock 恒为确定性结果）
            for endpoint in &endpoints {
                let target = if self.core.is_mock() { &endpoint.name } else { &endpoint.endpoint_id };
                if !self.core.is_mock() && self.probe_port.is_none() {
                    outcome.warnings.push("未配置 probe_port，未验证业务端口连通性".into());
                    break;
                }
                let probe = self.probe(target).await?;
                if !probe.reachable {
                    outcome
                        .warnings
                        .push(format!("终端节点 {} 私网探测未通过：{}", endpoint.endpoint_id, probe.detail));
                }
            }
        }
        if direction.includes_push() {
            // PrivateLink 无"下发策略"语义：显式记为不支持，避免静默吞掉上层请求
            outcome.skipped += 1;
            outcome
                .warnings
                .push("PrivateLink 不支持配置下发（skipped）；如需变更请走云控制台或 Terraform".to_string());
        }
        if self.core.is_mock() {
            outcome
                .warnings
                .push("Mock 模式：返回确定性 fixtures，未触达真实 PrivateLink（AGF_MOCK_MODE）".to_string());
        }
        if !req.resource.is_empty() {
            outcome.changes.insert("requested_resource".to_string(), 1);
        }
        outcome.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(outcome)
    }

    async fn push(&self, payload: &PushPayload) -> DomainResult<()> {
        // PrivateLink 是纯基础设施面：平台不通过它下发策略，显式拒绝而不是静默成功。
        Err(DomainError::NotImplemented(format!(
            "PrivateLink 适配器不支持下发实体 {}（不支持 push，请改用云控制台/Terraform）",
            payload.entity
        )))
    }

    async fn pull(&self, req: &PullRequest) -> DomainResult<PullResponse> {
        let resource = if req.resource.is_empty() { "endpoints".to_string() } else { req.resource.clone() };
        let items = match resource.as_str() {
            "endpoints" | "vpc-endpoints" => self
                .pull_endpoints()
                .await?
                .into_iter()
                .map(|e| serde_json::to_value(e).unwrap_or(serde_json::Value::Null))
                .collect(),
            "security-groups" => self
                .check_security_groups()
                .await?
                .into_iter()
                .map(|c| serde_json::to_value(c).unwrap_or(serde_json::Value::Null))
                .collect(),
            other => return Err(DomainError::Validation(format!("PrivateLink 不支持拉取资源类型 {other}"))),
        };
        Ok(PullResponse {
            items,
            next_cursor: None,
            mocked: self.core.is_mock(),
            origin: if self.core.is_mock() {
                format!("fixture:crates/agf-alicloud/src/mock.rs#{resource}")
            } else {
                format!("https://{}", self.core.endpoint_host().unwrap_or_default())
            },
        })
    }

    async fn self_check(&self) -> DomainResult<AdapterHealth> {
        let mut health = self.core.health_of();
        let checks = crate::selfcheck::service_checks(AliCloudService::Privatelink, &self.core, None);
        health.message = Some(crate::selfcheck::summarize_checks(&checks, self.core.mode()));
        Ok(health)
    }

    async fn shutdown(&mut self) -> DomainResult<()> {
        self.core.shutdown_common();
        self.client = None;
        Ok(())
    }
}
