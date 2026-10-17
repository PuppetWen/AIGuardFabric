//! 由 `client.rs` 拆分：`AgentClient` 的实现（纯搬移，逻辑不变）。
use super::*;

impl AgentClient {
    /// 新建客户端（按配置选择 Mock / mTLS / 明文 HTTP 传输）。
    #[must_use]
    pub fn new(identity: AgentIdentity, config: ClientConfig) -> Self {
        Self::build(identity, config, None)
    }

    /// 内部构造：`preset_error` 为已知的传输装配失败原因（`from_env` 预检时产生）。
    fn build(identity: AgentIdentity, config: ClientConfig, preset_error: Option<DomainError>) -> Self {
        let (transport, transport_config_error) = Self::select_transport(&identity, &config, preset_error);
        let queue = LocalQueue::new(config.queue.clone());
        Self {
            identity,
            config,
            transport,
            transport_config_error,
            queue,
            recorded: Vec::new(),
            registered: false,
            last_snapshot: None,
            started_at: Instant::now(),
        }
    }

    /// 选择传输层：Mock → mTLS/TLS/明文 → 配置错误时**明确报错的占位传输**。
    fn select_transport(
        identity: &AgentIdentity,
        config: &ClientConfig,
        preset_error: Option<DomainError>,
    ) -> (Arc<dyn AgentTransport>, Option<DomainError>) {
        if config.mock {
            return (Arc::new(MockTransport), None);
        }
        if let Some(error) = preset_error {
            // 配置在 `from_env` 阶段就已判定非法：不建连接，把原因一路带到健康画像与回执 note。
            return (Arc::new(HttpTransportNotImplemented::with_cause(error.to_string())), Some(error));
        }
        if !config.has_server() {
            // 未配置服务端时不上网；走占位传输（回执会说明"未配置"而不是"未实现"）。
            return (Arc::new(HttpTransportNotImplemented::default()), None);
        }
        match TlsTransport::from_config(&config.tls, config.server_url.as_deref()) {
            Ok(transport) => {
                let mut transport = transport.with_agent_id(identity.agent_id.clone());
                if let Some(token) = &config.token {
                    transport = transport.with_token(token.expose_secret().to_string());
                }
                (Arc::new(transport), None)
            }
            Err(error) => {
                tracing::warn!(
                    kind = TlsErrorKind::of(&error).as_str(),
                    "mTLS 传输装配失败，上行将明确报错而不是静默降级"
                );
                (Arc::new(HttpTransportNotImplemented::with_cause(error.to_string())), Some(error))
            }
        }
    }

    /// 新建并载入本地队列（断点续传）。
    ///
    /// # Errors
    /// 队列文件存在但不可读时返回错误。
    pub fn with_persisted_queue(identity: AgentIdentity, config: ClientConfig) -> DomainResult<Self> {
        let queue = LocalQueue::load(config.queue.clone())?;
        let (transport, transport_config_error) = Self::select_transport(&identity, &config, None);
        Ok(Self {
            identity,
            config,
            transport,
            transport_config_error,
            queue,
            recorded: Vec::new(),
            registered: false,
            last_snapshot: None,
            started_at: Instant::now(),
        })
    }

    /// 从环境变量装配（`AGF_MOCK_MODE` / `AGF_AGENT_TLS_*` 生效；TLS 配置错误在此**预检并留痕**）。
    #[must_use]
    pub fn from_env(identity: AgentIdentity) -> Self {
        let config = ClientConfig::from_env();
        // 预检：证书缺失/不成对/未授权的跳过校验在这里就被定性，而不是等到第一次上行。
        let preset = config.tls.validate(config.server_url.as_deref()).err();
        Self::build(identity, config, preset)
    }

    /// 注入自定义传输（测试与阶段二接入真实 HTTP）。
    #[must_use]
    pub fn with_transport(mut self, transport: Arc<dyn AgentTransport>) -> Self {
        self.transport = transport;
        self
    }

    /// 身份。
    #[must_use]
    pub const fn identity(&self) -> &AgentIdentity {
        &self.identity
    }

    /// 配置。
    #[must_use]
    pub const fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// 运行模式。
    #[must_use]
    pub fn mode(&self) -> ClientMode {
        if self.config.mock {
            ClientMode::Mock
        } else if self.config.has_server() {
            ClientMode::Live
        } else {
            ClientMode::Unconfigured
        }
    }

    /// 传输名。
    #[must_use]
    pub fn transport_name(&self) -> &'static str {
        self.transport.name()
    }

    /// TLS 健康画像（含配置错误分类；**绝不回显凭据**）。
    #[must_use]
    pub fn tls_health(&self) -> TlsHealth {
        let mut health = self.config.tls_health();
        if let Some(error) = &self.transport_config_error {
            health.material_ready = false;
            health.error_kind = Some(TlsErrorKind::of(error));
            health.detail = error.to_string();
        }
        health
    }

    /// TLS 模式（`plaintext` / `server-auth` / `mutual`）。
    #[must_use]
    pub fn tls_mode(&self) -> TlsMode {
        self.config.tls_mode()
    }

    /// 传输装配失败的原因（`None` = 未发生配置错误）。
    #[must_use]
    pub const fn transport_config_error(&self) -> Option<&DomainError> {
        self.transport_config_error.as_ref()
    }

    /// 最近一次真实上行响应（状态码 / 协商协议 / 协商密码套件）。
    ///
    /// 只有真实 HTTP 传输会返回 `Some`（Mock / 占位传输恒 `None`）。
    /// **这不改变上行契约**，只是把"服务端到底回了什么"暴露给自检与端到端验证。
    #[must_use]
    pub fn last_uplink_response(&self) -> Option<TlsResponse> {
        self.transport.last_response()
    }

    /// 是否已注册。
    #[must_use]
    pub const fn is_registered(&self) -> bool {
        self.registered
    }

    /// 运行时长（秒）。
    #[must_use]
    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// 队列只读视图。
    #[must_use]
    pub const fn queue(&self) -> &LocalQueue {
        &self.queue
    }

    /// 队列统计。
    #[must_use]
    pub fn queue_stats(&self) -> QueueStats {
        self.queue.stats()
    }

    /// Mock 模式的投递记录。
    #[must_use]
    pub fn recorded_deliveries(&self) -> &[RecordedDelivery] {
        &self.recorded
    }

    /// 最近一次快照（用于计算 diff）。
    #[must_use]
    pub const fn last_snapshot(&self) -> Option<&AgentReport> {
        self.last_snapshot.as_ref()
    }

    /// 第 `attempt` 次（从 0 开始）重试前的退避毫秒数。
    ///
    /// **刻意不加抖动**：终端侧需要可预测的上行节奏，且便于测试断言；
    /// 生产可通过 `retry.jitter` 字段留待阶段二与真实 HTTP 一起启用。
    #[must_use]
    pub fn backoff_ms(&self, attempt: u32) -> u64 {
        self.config.retry.backoff_ms(attempt)
    }

    /// 上行地址（`server_url` + 路径）。
    ///
    /// # Errors
    /// 未配置 `server_url` 时返回 `DomainError::Config`。
    pub fn endpoint_for(&self, kind: PayloadKind) -> DomainResult<String> {
        let base = self
            .server_url()
            .ok_or_else(|| DomainError::Config(format!("未配置 {ENV_SERVER_URL}：无法上行 {}", kind.as_str())))?;
        Ok(format!("{}{}", base.trim_end_matches('/'), self.config.paths.for_kind(kind)))
    }

    /// 服务端基址。
    #[must_use]
    pub fn server_url(&self) -> Option<&str> {
        self.config.server_url.as_deref().map(str::trim).filter(|u| !u.is_empty())
    }

    /// 严格上行：**不入队**，失败即返回明确错误。
    ///
    /// # Errors
    /// Mock 模式恒 `Ok`；未配置返回 `Config`；传输失败返回最后一次错误（含 `TODO(agent-http)`）。
    pub async fn deliver_strict(
        &mut self,
        kind: PayloadKind,
        envelope_json: &str,
        idempotency_key: &str,
    ) -> DomainResult<DeliveryOutcome> {
        match self.mode() {
            ClientMode::Mock => {
                let endpoint = self.server_url().unwrap_or("mock://agf").to_string();
                self.record(kind, &endpoint, envelope_json, idempotency_key);
                Ok(DeliveryOutcome {
                    kind,
                    mocked: true,
                    queued: false,
                    attempts: 1,
                    latency_ms: 0,
                    endpoint,
                    note: Some("AGF_MOCK_MODE：只记录不发送".to_string()),
                })
            }
            ClientMode::Unconfigured => {
                Err(DomainError::Config(format!("未配置 {ENV_SERVER_URL}：{} 无法上行", kind.as_str())))
            }
            ClientMode::Live => {
                let endpoint = self.endpoint_for(kind)?;
                let started = Instant::now();
                let attempts = self.config.retry.max_attempts.max(1);
                let mut last_error: Option<DomainError> = None;
                for attempt in 0..attempts {
                    match self.transport.send(&endpoint, envelope_json) {
                        Ok(()) => {
                            return Ok(DeliveryOutcome {
                                kind,
                                mocked: false,
                                queued: false,
                                attempts: attempt + 1,
                                latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                                endpoint: redact_endpoint(&endpoint),
                                note: None,
                            });
                        }
                        Err(error) => {
                            let retryable = error.is_degradable() || matches!(error, DomainError::Timeout(_));
                            last_error = Some(error);
                            if !retryable || attempt + 1 >= attempts {
                                break;
                            }
                            let backoff = self.backoff_ms(attempt);
                            tracing::debug!(attempt, backoff, endpoint = %redact_endpoint(&endpoint), "上行失败，退避重试");
                            tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
                        }
                    }
                }
                Err(last_error.unwrap_or_else(|| DomainError::Internal("上行未产生结果".to_string())))
            }
        }
    }

    /// 默认上行：严格失败后**入本地队列**（可重试错误）或直接报错（载荷非法）。
    ///
    /// # Errors
    /// 载荷本身非法（`Validation` / `Parse`）时返回错误（入队只会无限重放坏载荷）。
    pub async fn deliver(
        &mut self,
        kind: PayloadKind,
        envelope_json: &str,
        idempotency_key: &str,
    ) -> DomainResult<DeliveryOutcome> {
        match self.deliver_strict(kind, envelope_json, idempotency_key).await {
            Ok(outcome) => Ok(outcome),
            Err(error) => {
                if matches!(error, DomainError::Validation(_) | DomainError::Parse(_)) {
                    return Err(error);
                }
                self.queue.push_payload(kind, idempotency_key, envelope_json);
                let stats = self.queue.stats();
                tracing::warn!(
                    kind = kind.as_str(),
                    depth = stats.depth,
                    evicted = stats.evicted_total,
                    "上行失败已入本地队列等待补传"
                );
                Ok(DeliveryOutcome {
                    kind,
                    mocked: false,
                    queued: true,
                    attempts: self.config.retry.max_attempts.max(1),
                    latency_ms: 0,
                    endpoint: self.endpoint_for(kind).unwrap_or_else(|_| "unconfigured".to_string()),
                    note: Some(format!("已入本地队列（深度 {}）：{error}", self.queue.len())),
                })
            }
        }
    }

    /// 注册（首次上线）。
    ///
    /// # Errors
    /// 载荷序列化或不可重试的上行失败。
    pub async fn register(&mut self) -> DomainResult<DeliveryOutcome> {
        #[derive(serde::Serialize)]
        struct RegisterPayload<'a> {
            agent_id: &'a str,
            agent_version: &'a str,
            hostname: &'a str,
            os: &'a str,
            heartbeat_interval_secs: u64,
        }
        let payload = RegisterPayload {
            agent_id: &self.identity.agent_id,
            agent_version: &self.identity.agent_version,
            hostname: &self.identity.hostname,
            os: &self.identity.os,
            heartbeat_interval_secs: self.config.heartbeat_interval_secs,
        };
        let envelope = Envelope::new(&self.identity, PayloadKind::Register, payload)?;
        let json = envelope.to_json()?;
        let outcome = self.deliver(PayloadKind::Register, &json, &envelope.idempotency_key).await?;
        if !outcome.queued {
            self.registered = true;
        }
        Ok(outcome)
    }

    /// 上报资产快照（成功后更新 diff 基线）。
    ///
    /// # Errors
    /// 信封构造或不可重试的上行失败。
    pub async fn send_snapshot(
        &mut self,
        report: AgentReport,
        extras: CollectionExtras,
    ) -> DomainResult<DeliveryOutcome> {
        let payload = SnapshotPayload { report: report.clone(), extras };
        let envelope = Envelope::new(&self.identity, PayloadKind::Snapshot, payload)?;
        let json = envelope.to_json()?;
        let outcome = self.deliver(PayloadKind::Snapshot, &json, &envelope.idempotency_key).await?;
        self.last_snapshot = Some(report);
        Ok(outcome)
    }

    /// 上报增量变更。
    ///
    /// # Errors
    /// 信封构造或不可重试的上行失败。
    pub async fn send_diff(&mut self, diff: &DiffPayload) -> DomainResult<DeliveryOutcome> {
        let envelope = Envelope::new(&self.identity, PayloadKind::Diff, diff)?;
        let json = envelope.to_json()?;
        self.deliver(PayloadKind::Diff, &json, &envelope.idempotency_key).await
    }

    /// 上报心跳。
    ///
    /// # Errors
    /// 信封构造或不可重试的上行失败。
    pub async fn send_heartbeat(&mut self, heartbeat: &HeartbeatPayload) -> DomainResult<DeliveryOutcome> {
        let envelope = Envelope::new(&self.identity, PayloadKind::Heartbeat, heartbeat)?;
        let json = envelope.to_json()?;
        self.deliver(PayloadKind::Heartbeat, &json, &envelope.idempotency_key).await
    }

    /// 由最近快照与当前报告计算增量（首次上报时全部计为新增）。
    #[must_use]
    pub fn compute_diff(&self, current: &AgentReport) -> DiffPayload {
        compute_diff(self.last_snapshot.as_ref(), current)
    }

    /// 构造心跳载荷。
    #[must_use]
    pub fn heartbeat_payload(&self, collectors: Vec<crate::payload::CollectorStatus>) -> HeartbeatPayload {
        HeartbeatPayload {
            uptime_secs: self.uptime_secs(),
            queue_depth: self.queue.len(),
            last_snapshot_at: self.last_snapshot.as_ref().map(|r| r.collected_at),
            collectors,
        }
    }

    /// 补传队列（单次尝试；失败累计次数，超上限丢弃）。
    pub async fn flush_queue(&mut self, max: usize) -> FlushStats {
        let mut stats = FlushStats::default();
        let batch = self.queue.drain_batch(max);
        for entry in batch {
            stats.attempted += 1;
            let endpoint = match self.endpoint_for(entry.kind) {
                Ok(endpoint) => endpoint,
                Err(_) => {
                    // 未配置服务端：整批回插，等配置补齐
                    self.queue.requeue_front(entry);
                    stats.requeued += 1;
                    continue;
                }
            };
            match self.transport.send(&endpoint, &entry.body) {
                Ok(()) => {
                    stats.delivered += 1;
                }
                Err(error) => {
                    // 回插（保留 attempts）后再判定是否超限丢弃
                    self.queue.requeue_front(entry.clone());
                    if self.queue.note_failure(&entry.idempotency_key) {
                        stats.dropped += 1;
                    } else {
                        stats.requeued += 1;
                    }
                    tracing::debug!(error = %error, endpoint = %redact_endpoint(&endpoint), "补传失败");
                }
            }
        }
        stats
    }

    /// 队列落盘（`queue.path` 未配置时为 no-op）。
    ///
    /// # Errors
    /// 目录不可创建或写入失败。
    pub fn save_queue(&self) -> DomainResult<()> {
        self.queue.save()
    }

    /// 记录一次 Mock 投递。
    pub(crate) fn record(&mut self, kind: PayloadKind, endpoint: &str, body: &str, idempotency_key: &str) {
        self.recorded.push(RecordedDelivery {
            kind,
            endpoint: endpoint.to_string(),
            bytes: body.len(),
            idempotency_key: idempotency_key.to_string(),
            at_unix_secs: agf_core::time::Timestamp::now().unix_secs(),
        });
    }

    /// 令牌是否已配置（不暴露明文）。
    #[must_use]
    pub fn has_token(&self) -> bool {
        self.config.token.as_ref().is_some_and(|t| !t.expose_secret().is_empty())
    }
}
