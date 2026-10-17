//! 由 `engine.rs` 拆分：`EngineConfig`/`RuntimeEngine` 的实现（纯搬移，逻辑不变）。
use super::*;

impl Default for EngineConfig {
    /// 默认配置：**要求三个拦截点都被覆盖**（§4.3），审计缓冲 4096 条。
    fn default() -> Self {
        Self {
            tenant_id: TenantId::default_tenant(),
            required_points: vec![InterceptPoint::McpProxy, InterceptPoint::AiGateway, InterceptPoint::ProcessHook],
            redaction_mode: RedactionMode::default(),
            audit_capacity: InterceptionAuditLog::DEFAULT_CAPACITY,
            enroll_self_proxy: true,
            heartbeat_interval_secs: 30,
        }
    }
}

impl EngineConfig {
    /// 必须覆盖的拦截点。
    #[must_use]
    pub fn required_intercept_points(&self) -> Vec<InterceptPoint> {
        self.required_points.clone()
    }

    /// 覆盖"必须覆盖的拦截点"清单（例：只部署 MCP 代理时可收窄为单点）。
    #[must_use]
    pub fn with_required_points(mut self, points: Vec<InterceptPoint>) -> Self {
        self.required_points = points;
        self
    }

    /// 设置租户。
    #[must_use]
    pub const fn with_tenant(mut self, tenant_id: TenantId) -> Self {
        self.tenant_id = tenant_id;
        self
    }

    /// 设置脱敏模式。
    #[must_use]
    pub const fn with_redaction_mode(mut self, mode: RedactionMode) -> Self {
        self.redaction_mode = mode;
        self
    }

    /// 设置审计缓冲容量。
    #[must_use]
    pub const fn with_audit_capacity(mut self, capacity: usize) -> Self {
        self.audit_capacity = capacity;
        self
    }

    /// 是否注册本进程代理端点的心跳。
    #[must_use]
    pub const fn with_self_proxy_enrollment(mut self, enabled: bool) -> Self {
        self.enroll_self_proxy = enabled;
        self
    }

    /// 设置心跳间隔。
    #[must_use]
    pub const fn with_heartbeat_interval(mut self, secs: i64) -> Self {
        self.heartbeat_interval_secs = secs;
        self
    }
}

impl RuntimeEngine {
    /// 在装配时共用管理面的拦截审计链。
    #[must_use]
    pub fn with_audit_log(mut self, audit: Arc<InterceptionAuditLog>) -> Self {
        self.audit = audit;
        self
    }
    /// 当前黑名单规则快照。
    pub async fn blocklist_rules(&self) -> Vec<crate::blocklist::RuleRule> {
        self.blocklist.lock().await.rules()
    }
    /// 完全离线构造（**无 Redis / 无 PostgreSQL**）。
    ///
    /// 装配结果：
    /// - 策略：`policies`（会做源码与签名校验）；
    /// - 黑名单：[`Blocklist::with_defaults`]（内置最低防线）；
    /// - 配额：`quotas` + [`InMemoryQuotaStore`]；
    /// - 审批：[`InMemoryApprovalStore`]；
    /// - 审计：内存哈希链；
    /// - 心跳：注册一个本进程代理端点（可用 [`EngineConfig::with_self_proxy_enrollment`] 关闭）。
    ///
    /// # Errors
    /// 策略源码/签名配置非法（Rego 编译错误等）。
    pub fn in_memory(
        policies: Vec<agf_core::policy::Policy>,
        quotas: Vec<Quota>,
        config: EngineConfig,
    ) -> DomainResult<Self> {
        Self::in_memory_with(policies, quotas, Blocklist::with_defaults(), config)
    }
    /// 离线构造（自定义黑名单）。
    ///
    /// # Errors
    /// 策略源码/签名配置非法。
    pub fn in_memory_with(
        policies: Vec<agf_core::policy::Policy>,
        quotas: Vec<Quota>,
        blocklist: Blocklist,
        config: EngineConfig,
    ) -> DomainResult<Self> {
        let engine = PolicyEngine::new()
            .with_signature_mode(SignatureMode::Disabled)
            .with_eval_error_mode(EvalErrorMode::FailClosed)
            .with_hit_source(HitSource::PolicyFirst)
            .from_policies(policies)?;
        Ok(Self::assemble(
            engine,
            blocklist,
            QuotaService::new(quotas, Arc::new(InMemoryQuotaStore::new())),
            Arc::new(InMemoryApprovalStore::new()),
            config,
        ))
    }
    /// 生产构造：显式给出策略引擎、黑名单、配额服务与审批存储。
    ///
    /// 调用方（`agf-api`）负责：
    /// - 从 [`agf_storage::Store::with_tenant`] + [`agf_storage::PolicyRepo::list_enabled`] 装载策略；
    /// - 用 [`crate::signature::PolicySigner`] 配置密钥（生产必须 `Enforce`）；
    /// - 用 [`crate::quota::RedisQuotaStore`] 构造配额服务。
    #[must_use]
    pub fn assemble(
        engine: PolicyEngine,
        blocklist: Blocklist,
        quotas: QuotaService,
        approvals: Arc<dyn ApprovalStore>,
        config: EngineConfig,
    ) -> Self {
        let audit = Arc::new(InterceptionAuditLog::with_capacity(config.audit_capacity));
        let heartbeats = HeartbeatMonitor::new();
        if config.enroll_self_proxy {
            heartbeats.register(ManagedEndpoint::new(
                format!("proxy:runtime-{}", std::process::id()),
                "proxy",
                config.heartbeat_interval_secs,
            ));
        }
        Self {
            config: config.clone(),
            engine: RwLock::new(engine),
            blocklist: Mutex::new(blocklist),
            quotas: RwLock::new(Some(quotas)),
            approvals,
            audit,
            heartbeats,
            proxy_builder: ProxyBuilder {
                redaction_mode: config.redaction_mode,
                max_frame_bytes: JsonRpcFrame::DEFAULT_MAX_BYTES,
            },
        }
    }
    /// 配置。
    #[must_use]
    pub const fn config(&self) -> &EngineConfig {
        &self.config
    }
    /// 审计链。
    #[must_use]
    pub fn audit(&self) -> &Arc<InterceptionAuditLog> {
        &self.audit
    }
    /// 心跳监控。
    #[must_use]
    pub const fn heartbeats(&self) -> &HeartbeatMonitor {
        &self.heartbeats
    }
    /// 审批存储。
    #[must_use]
    pub fn approvals(&self) -> &Arc<dyn ApprovalStore> {
        &self.approvals
    }
    /// 设置 MCP 帧大小上限。
    pub fn set_max_frame_bytes(&mut self, max: usize) {
        self.proxy_builder.max_frame_bytes = max;
    }
    /// 安装策略签名器（会按当前模式重新装载策略）。
    ///
    /// # Errors
    /// 重新装载失败（源码错误）。
    pub async fn install_signer(&self, signer: PolicySigner, mode: SignatureMode) -> DomainResult<()> {
        let mut guard = self.engine.write().await;
        let policies = guard.policies().to_vec();
        let fresh = PolicyEngine::new()
            .with_signer(signer)
            .with_signature_mode(mode)
            .with_eval_error_mode(guard.eval_error_mode())
            .with_hit_source(guard.hit_source())
            .from_policies(policies)?;
        *guard = fresh;
        Ok(())
    }
    /// 热重载策略集（原子替换；失败保持旧策略集）。
    ///
    /// # Errors
    /// 新策略集源码错误。
    pub async fn reload_policies(&self, policies: Vec<agf_core::policy::Policy>) -> DomainResult<()> {
        self.engine.write().await.replace(policies)
    }
    /// 热重载黑名单（原子替换；失败保持旧规则集）。
    ///
    /// # Errors
    /// 新规则集正则非法。
    pub async fn reload_blocklist(&self, rules: Vec<crate::blocklist::RuleRule>) -> DomainResult<()> {
        self.blocklist.lock().await.reload(rules)
    }
    /// 恢复内置黑名单。
    pub async fn reload_default_blocklist(&self) {
        self.blocklist.lock().await.reload_defaults();
    }
    /// 热重载配额。
    pub async fn reload_quotas(&self, quotas: Vec<Quota>) {
        if let Some(service) = self.quotas.write().await.as_mut() {
            service.replace_quotas(quotas);
        }
    }
    /// 当前生效策略数。
    pub async fn policy_count(&self) -> usize {
        self.engine.read().await.len()
    }
    /// 当前黑名单规则数。
    pub async fn blocklist_len(&self) -> usize {
        self.blocklist.lock().await.len()
    }
    /// 策略求值（南北向网关与 MCP 代理共用）。
    ///
    /// 内部顺序：**黑名单 → 策略**（策略引擎会保留黑名单的 `Deny` 否决权）。
    ///
    /// # Errors
    /// - 策略后端求值失败且引擎为 fail-closed ⇒ [`DomainError::PolicyDenied`]；
    /// - 黑名单规则内部错误。
    pub async fn evaluate(&self, ctx: PolicyContext) -> DomainResult<PolicyDecision> {
        let hit = {
            let mut bl = self.blocklist.lock().await;
            bl.evaluate(&ctx)?
        };
        let engine = self.engine.read().await;
        engine.evaluate(&ctx, hit.as_ref())
    }
    /// 仅用命令文本求值（eBPF/进程 Hook 东西向：没有完整上下文）。
    ///
    /// # Errors
    /// 与 [`Self::evaluate`] 相同。
    pub async fn evaluate_command(
        &self,
        tenant_id: TenantId,
        session_id: &str,
        command: &str,
    ) -> DomainResult<PolicyDecision> {
        let ctx = PolicyContext {
            tenant_id,
            session_id: session_id.to_string(),
            agent_id: None,
            department: None,
            intercept_point: InterceptPoint::ProcessHook,
            tool_name: Some("process_exec".to_string()),
            path: None,
            domain: None,
            command: Some(command.to_string()),
            payload: serde_json::json!({"command": command}),
            payload_bytes: u64::try_from(command.len()).unwrap_or(u64::MAX),
            risk_domains: Vec::new(),
            max_severity: None,
            data_class: agf_core::enums::DataClass::Internal,
            now: Timestamp::now(),
        };
        self.evaluate(ctx).await
    }
    /// MCP 请求拦截（按原始 JSON-RPC 帧）。
    ///
    /// `ctx` 提供租户 / Agent / 会话 / 拦截点；帧本身提供工具名与参数。
    /// **帧里的工具与目标会覆盖 `ctx` 中同名字段**（帧是事实来源），
    /// 但 `ctx.intercept_point` 会被强制为 [`InterceptPoint::McpProxy`]，
    /// 避免调用方传错拦截点导致策略路由错误。
    ///
    /// # Errors
    /// 帧非法、策略求值失败或审批服务不可用。
    pub async fn intercept_mcp_request(&self, ctx: PolicyContext, raw: &str) -> DomainResult<InterceptOutcome> {
        let frame = JsonRpcFrame::parse_with_limit(raw, self.proxy_builder.max_frame_bytes)?;
        let session = McpProxySession::new(ctx.tenant_id, Id::nil(), McpTransport::Http)
            .with_session_id(ctx.session_id.clone())
            .with_context(ctx.clone());
        let session = match ctx.agent_id {
            Some(id) => session.with_agent(id),
            None => session,
        };
        let proxy = self.snapshot_proxy().await;
        proxy.intercept_request(&session, &frame).await
    }
    /// MCP 请求拦截（已解析的帧，便于 SSE/HTTP 网关复用）。
    ///
    /// # Errors
    /// 同 [`Self::intercept_mcp_request`]。
    pub async fn intercept_frame(&self, ctx: &PolicyContext, frame: &JsonRpcFrame) -> DomainResult<InterceptOutcome> {
        let session = McpProxySession::new(ctx.tenant_id, Id::nil(), McpTransport::Http)
            .with_session_id(ctx.session_id.clone())
            .with_context(ctx.clone());
        let session = match ctx.agent_id {
            Some(id) => session.with_agent(id),
            None => session,
        };
        let proxy = self.snapshot_proxy().await;
        proxy.intercept_request(&session, frame).await
    }
    /// MCP 响应拦截（出站脱敏）。
    ///
    /// # Errors
    /// 帧非法或响应方向错误。
    pub async fn intercept_mcp_response(&self, ctx: &PolicyContext, raw: &str) -> DomainResult<InterceptOutcome> {
        let frame = JsonRpcFrame::parse_with_limit(raw, self.proxy_builder.max_frame_bytes)?;
        let session = McpProxySession::new(ctx.tenant_id, Id::nil(), McpTransport::Http)
            .with_session_id(ctx.session_id.clone())
            .with_context(ctx.clone());
        let session = match ctx.agent_id {
            Some(id) => session.with_agent(id),
            None => session,
        };
        let proxy = self.snapshot_proxy().await;
        proxy.intercept_response(&session, &frame).await
    }
    /// 请求完成：归还并发额度并记录后置用量。
    ///
    /// **必须在每次成功拦截后调用一次**（含被阻断？——**不含**：被阻断的请求没有持有并发额度，
    /// 重复归还只会让计数偏低，`QuotaStore::release` 已做下界保护，但语义上应只在放行路径调用）。
    ///
    /// # Errors
    /// 配额存储不可达（调用方通常记日志即可，不应因此改写请求结果）。
    pub async fn complete_call(&self, ctx: &PolicyContext, consumption: QuotaConsumption) -> DomainResult<()> {
        let guard = self.quotas.read().await;
        let Some(service) = guard.as_ref() else {
            return Ok(());
        };
        service.complete(ctx.tenant_id, ctx.agent_id, &ctx.session_id, &consumption).await
    }
    /// 只读配额快照（控制台）。
    ///
    /// # Errors
    /// 永不返回硬错误（配额缺失时返回空快照）。
    pub async fn quota_snapshot(
        &self,
        tenant_id: TenantId,
        agent_id: Option<Id>,
        session_id: &str,
    ) -> DomainResult<crate::quota::QuotaSnapshot> {
        let guard = self.quotas.read().await;
        match guard.as_ref() {
            Some(service) => service.snapshot(tenant_id, agent_id, session_id).await,
            None => Ok(crate::quota::QuotaSnapshot { entries: Vec::new(), degraded: true, at: Timestamp::now() }),
        }
    }
    /// 运行期自检报告（控制台「运行时防护」页）。
    ///
    /// 永不失败：内部各件读取失败时按"降级"处理并记入报告。
    pub async fn guard_report(&self) -> GuardReport {
        let engine = self.engine.read().await;
        let blocklist = self.blocklist.lock().await;
        let quotas = self.quotas.read().await;
        let mut check = SelfCheck::new(&engine, &blocklist, &self.audit, &self.config, self.config.tenant_id)
            .with_approvals(self.approvals.as_ref())
            .with_heartbeats(&self.heartbeats);
        if let Some(service) = quotas.as_ref() {
            check = check.with_quotas(service);
        }
        check.run()
    }
    /// 记录一条自定义拦截审计（供上层补充语义，如网关侧的模型路由决策）。
    ///
    /// # Errors
    /// 审计链锁中毒。
    pub fn record_interception(&self, record: InterceptionRecord) -> DomainResult<InterceptionRecord> {
        self.audit.append(record).map_err(DomainError::Internal)
    }
    /// 便捷：对原始响应文本做脱敏（不写审计）。
    #[must_use]
    pub fn redact_text(&self, text: &str) -> (String, usize) {
        let mut map = agf_core::redact::RedactionMap::new();
        let out = agf_core::redact::redact_text(text, self.proxy_builder.redaction_mode, &mut map);
        (out.text, map.len())
    }
    /// 便捷：对 JSON 做脱敏（入站/出站通用）。
    #[must_use]
    pub fn redact_json(&self, value: &serde_json::Value) -> (serde_json::Value, usize) {
        let mut map = agf_core::redact::RedactionMap::new();
        let out = agf_core::redact::redact_json(value, self.proxy_builder.redaction_mode, &mut map);
        (out, map.len())
    }
    /// 按当前策略与黑名单快照构造一个轻量 MCP 代理（热重载立即生效）。
    pub(crate) async fn snapshot_proxy(&self) -> McpProxy {
        // 保留已验证的快照、签名器与失败处理方式；不能构造默认空策略放行流量。
        let engine = self.engine.read().await.clone();
        let blocklist = self.blocklist.lock().await.clone();
        let quotas = {
            // 配额服务不可 Clone（内含 `Arc<dyn QuotaStore>`），这里按其配额定义重建一个
            // 指向同一存储的服务，保证计数共享。
            let guard = self.quotas.read().await;
            guard.as_ref().map(|s| QuotaService::new(s.quotas().to_vec(), Arc::clone(s.store())))
        };
        let mut proxy = McpProxy::new(engine, blocklist, Arc::clone(&self.audit))
            .with_redaction_mode(self.proxy_builder.redaction_mode)
            .with_approvals(Arc::clone(&self.approvals));
        if let Some(q) = quotas {
            proxy = proxy.with_quotas(q);
        }
        proxy
    }
}
