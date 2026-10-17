//! 由 `cms.rs` 拆分：`default_severity`/`impl_CmsEvent` 等 11 项（纯搬移，逻辑不变）。
use super::*;

/// `CmsEvent::severity` 的缺省值（信息级）。
pub(crate) fn default_severity() -> Severity {
    Severity::Info
}

impl CmsEvent {
    /// 云监控 `Level` 值。
    #[must_use]
    pub const fn level(&self) -> &'static str {
        match self.severity {
            Severity::Critical | Severity::High => "CRITICAL",
            Severity::Medium => "WARN",
            _ => "INFO",
        }
    }

    /// 组装 `PutCustomEvent` 参数（`EventInfo.N.*` 从 1 开始编号）。
    #[must_use]
    pub fn params(&self) -> Vec<(String, String)> {
        vec![
            ("EventInfo.1.EventName".to_string(), self.event_name.clone()),
            ("EventInfo.1.Content".to_string(), self.content.clone()),
            ("EventInfo.1.GroupId".to_string(), self.group_id.clone()),
            ("EventInfo.1.Time".to_string(), self.at.as_datetime().format("%Y%m%dT%H%M%S%.3f%z").to_string()),
        ]
    }
}

/// 默认指标命名空间。
pub(crate) fn default_namespace() -> String {
    "acs_agf".to_string()
}

/// 默认指标单位。
pub(crate) fn default_unit() -> String {
    "Count".to_string()
}

impl CmsMetric {
    /// 新指标（默认命名空间 `acs_agf`）。
    #[must_use]
    pub fn new(metric_name: impl Into<String>, value: f64) -> Self {
        Self {
            group_id: String::new(),
            metric_name: metric_name.into(),
            namespace: "acs_agf".to_string(),
            dimensions: std::collections::BTreeMap::new(),
            at: Timestamp::now(),
            value,
            unit: "Count".to_string(),
        }
    }

    /// 组装公开 PutCustomMetric 的单个原始数据点。
    #[must_use]
    pub fn params(&self) -> Vec<(String, String)> {
        vec![
            ("MetricList.1.Type".into(), "0".into()),
            ("MetricList.1.GroupId".into(), self.group_id.clone()),
            ("MetricList.1.MetricName".into(), self.metric_name.clone()),
            ("MetricList.1.Dimensions".into(), serde_json::json!(self.dimensions).to_string()),
            ("MetricList.1.Time".into(), self.at.unix_millis().to_string()),
            ("MetricList.1.Values".into(), serde_json::json!({"value":self.value}).to_string()),
        ]
    }
}

impl std::fmt::Debug for CmsAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CmsAdapter")
            .field("core", &self.core)
            .field("has_client", &self.client.is_some())
            .field("transport", &"<transport-double>")
            .finish()
    }
}

impl Default for CmsAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl CmsAdapter {
    /// 构造（未配置态，需 `init`）。
    #[must_use]
    pub fn new() -> Self {
        Self { core: AdapterCore::new(AliCloudService::Cms), client: None, transport: null_transport() }
    }

    /// 构造 Mock 模式实例（不触网；`init` 仍会按配置覆盖模式）。
    #[must_use]
    pub fn mocked() -> Self {
        let mut adapter = Self::new();
        adapter.core.mode = AdapterMode::Mocked;
        adapter.core.unconfigured_reason = None;
        adapter
    }

    /// 传输替身句柄。
    ///
    /// Mock 模式下恒为"录制型"替身且**永不被调用**；真实模式下仅由
    /// [`Self::with_recording_transport`] 在测试里替换，用于断言请求构造。
    /// 暴露它是为了让上层（如 `agf-runtime` 的调试接口）能查看"该适配器当前是否绑定了网络通道"。
    #[must_use]
    pub fn transport(&self) -> Arc<crate::http::RecordingTransport> {
        self.transport.clone()
    }

    /// 测试用：注入请求录制替身并重建真实模式客户端。
    ///
    /// # Errors
    /// 当前核心无凭据（未配置/未初始化）时返回错误。
    pub fn with_recording_transport(&mut self, transport: Arc<dyn crate::http::Transport>) -> DomainResult<()> {
        self.client = Some(self.core.build_test_client(transport)?);
        Ok(())
    }

    /// 当前模式。
    #[must_use]
    pub const fn mode(&self) -> AdapterMode {
        self.core.mode()
    }

    /// 核心（只读）。
    #[must_use]
    pub const fn core(&self) -> &AdapterCore {
        &self.core
    }

    /// 核心（可变，供测试/凭据刷新使用）。
    pub const fn core_mut(&mut self) -> &mut AdapterCore {
        &mut self.core
    }

    /// 真实调用入口：Mock / 未配置时明确报错，绝不触网。
    pub(crate) fn live_client(&self) -> DomainResult<&RpcClient> {
        if self.core.is_mock() {
            return Err(mock::mock_blocked(AliCloudService::Cms));
        }
        self.client
            .as_deref()
            .ok_or_else(|| mock::unavailable(AliCloudService::Cms, "适配器未初始化或凭据未就绪（无真实调用通道）"))
    }
}

#[async_trait]
impl Adapter for CmsAdapter {
    fn name(&self) -> &str {
        AliCloudService::Cms.as_str()
    }

    fn descriptor(&self) -> AdapterDescriptor {
        mock::descriptor_of(AliCloudService::Cms)
    }

    async fn init(&mut self, config: &AdapterConfig) -> DomainResult<()> {
        self.core.load_from_config(config)?;
        self.client = self.core.build_live_client();
        mock::log_init(AliCloudService::Cms, self.core.mode());
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
            let alarms = self.pull_alarm_histories(req).await?;
            outcome.pulled = alarms.len();
            outcome.changes.insert("alarm_history".to_string(), alarms.len());
            outcome
                .changes
                .insert("critical_alarm".to_string(), alarms.iter().filter(|a| a.level == "CRITICAL").count());
        }
        if direction.includes_push() {
            // 平台 → 云监控：把当前待上报事件/指标计数暴露出来（真实推送由 push() 逐条完成）
            outcome.skipped = 0;
        }
        if self.core.is_mock() {
            outcome.warnings.push("Mock 模式：返回确定性 fixtures，未触达真实云监控（AGF_MOCK_MODE）".to_string());
        }
        outcome.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(outcome)
    }

    async fn push(&self, payload: &PushPayload) -> DomainResult<()> {
        match payload.entity.as_str() {
            "event" => {
                let mut event: CmsEvent = serde_json::from_value(payload.body.clone())?;
                if event.event_name.is_empty() {
                    event.event_name = payload.entity_id.clone();
                }
                self.put_event(&event).await?;
                Ok(())
            }
            "metric" => {
                let metric: CmsMetric = serde_json::from_value(payload.body.clone())?;
                self.put_metric(&metric).await?;
                Ok(())
            }
            other => Err(DomainError::Validation(format!("CMS 适配器只接受 event / metric 载荷，收到 {other}"))),
        }
    }

    async fn pull(&self, req: &PullRequest) -> DomainResult<PullResponse> {
        let resource = if req.resource.is_empty() { "alarms".to_string() } else { req.resource.clone() };
        match resource.as_str() {
            "alarms" | "alarm-histories" => {
                let items = self.pull_alarm_histories(req).await?;
                let next_cursor = if !self.core.is_mock() && items.len() == req.limit.unwrap_or(50) as usize {
                    req.cursor
                        .as_deref()
                        .unwrap_or("1")
                        .parse::<u32>()
                        .ok()
                        .and_then(|page| page.checked_add(1))
                        .map(|page| page.to_string())
                } else {
                    None
                };
                Ok(PullResponse {
                    items: items
                        .into_iter()
                        .map(|a| serde_json::to_value(a).unwrap_or(serde_json::Value::Null))
                        .collect(),
                    next_cursor,
                    mocked: self.core.is_mock(),
                    origin: self.origin_label("alarms"),
                })
            }
            other => Err(DomainError::Validation(format!("CMS 不支持拉取资源类型 {other}"))),
        }
    }

    async fn self_check(&self) -> DomainResult<AdapterHealth> {
        let mut health = self.core.health_of();
        let checks = crate::selfcheck::service_checks(AliCloudService::Cms, &self.core, None);
        health.message = Some(crate::selfcheck::summarize_checks(&checks, self.core.mode()));
        Ok(health)
    }

    async fn shutdown(&mut self) -> DomainResult<()> {
        self.core.shutdown_common();
        self.client = None;
        Ok(())
    }
}

impl CmsAdapter {
    /// 来源标签（排障用）。
    pub(crate) fn origin_label(&self, resource: &str) -> String {
        if self.core.is_mock() {
            format!("fixture:crates/agf-alicloud/src/mock.rs#{resource}")
        } else {
            format!("https://{}", self.core.endpoint_host().unwrap_or_default())
        }
    }
}

#[async_trait]
impl CmsApi for CmsAdapter {
    async fn put_event(&self, event: &CmsEvent) -> DomainResult<String> {
        if self.core.is_mock() {
            return Ok(mock::cms_put_event(event));
        }
        let client = self.live_client()?;
        let response = client.call_async("PutCustomEvent", CMS_API_VERSION, "POST", &event.params()).await?;
        Ok(json_str(&response.body, "RequestId").unwrap_or_else(|| event.event_name.clone()))
    }

    async fn put_metric(&self, metric: &CmsMetric) -> DomainResult<String> {
        if self.core.is_mock() {
            return Ok(mock::cms_put_metric(metric));
        }
        let client = self.live_client()?;
        if metric.group_id.trim().is_empty() || !metric.value.is_finite() {
            return Err(DomainError::Validation("CMS 指标必须填写 group_id，且数值必须有限".into()));
        }
        let response = client.call_async("PutCustomMetric", CMS_API_VERSION, "POST", &metric.params()).await?;
        Ok(json_str(&response.body, "RequestId").unwrap_or_else(|| metric.metric_name.clone()))
    }

    async fn pull_alarm_histories(&self, req: &PullRequest) -> DomainResult<Vec<CmsAlarmHistory>> {
        if self.core.is_mock() {
            return Ok(mock::cms_alarm_histories(req));
        }
        let client = self.live_client()?;
        let page = req
            .cursor
            .as_deref()
            .unwrap_or("1")
            .parse::<u32>()
            .ok()
            .filter(|page| *page > 0)
            .ok_or_else(|| DomainError::Validation("CMS 页码必须为正整数".into()))?;
        let limit = req.limit.unwrap_or(50);
        if !(1..=100).contains(&limit) {
            return Err(DomainError::Validation("CMS 每页数量必须为 1 至 100".into()));
        }
        let mut params = vec![("PageSize".into(), limit.to_string()), ("Page".into(), page.to_string())];
        for (key, name) in
            [("start_time", "StartTime"), ("end_time", "EndTime"), ("group_id", "GroupId"), ("rule_id", "RuleId")]
        {
            if let Some(value) = req.filter.get(key).filter(|value| !value.is_empty()) {
                params.push((name.into(), value.clone()));
            }
        }
        let response = client.call_async("DescribeAlertHistoryList", CMS_API_VERSION, "GET", &params).await?;
        if response.body.pointer("/AlarmHistoryList/AlarmHistory").and_then(serde_json::Value::as_array).is_none() {
            return Err(DomainError::Parse("CMS 报警响应缺少 AlarmHistoryList.AlarmHistory".into()));
        }
        Ok(parse_alarm_histories(&response))
    }

    fn subscribe_alarm_callback(&self, callback_base: &str) -> DomainResult<CmsAlarmSubscription> {
        let base = callback_base.trim_end_matches('/');
        let token = agf_core::secret::generate_token();
        let url = format!("{base}/api/v1/ingest/webhook/alicloud-cms?token={}", percent_encode(&token));
        Ok(CmsAlarmSubscription {
            callback_url: url,
            verify_token_masked: agf_core::secret::mask_default(&token),
            subscribed_at: Timestamp::now(),
        })
    }
}
