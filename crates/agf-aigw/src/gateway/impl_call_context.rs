//! 由 `gateway.rs` 拆分：`AiGateway`/`CallContext`/`EndpointView`/`GatewayResponse` 的实现（纯搬移，逻辑不变）。
use super::*;

impl CallContext {
    /// 新建（默认策略 CostFirst、不限制预算、允许降级）。
    #[must_use]
    pub fn new(tenant: TenantId) -> Self {
        Self {
            tenant,
            session_id: format!("sess-{}", agf_core::secret::generate_token()),
            agent_id: None,
            data_class: DataClass::Internal,
            allow_cache: false,
            disable_cache: false,
            strategy: RoutingStrategy::CostFirst,
            budget: BudgetGuard::unlimited(),
            timeout_secs: None,
            allow_fallback: true,
        }
    }

    /// 指定会话。
    #[must_use]
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = session_id.into();
        self
    }

    /// 指定 Agent。
    #[must_use]
    pub fn with_agent(mut self, agent_id: Id) -> Self {
        self.agent_id = Some(agent_id);
        self
    }

    /// 指定数据分级。
    #[must_use]
    pub fn with_data_class(mut self, class: DataClass) -> Self {
        self.data_class = class;
        self
    }

    /// 指定路由策略。
    #[must_use]
    pub fn with_strategy(mut self, strategy: RoutingStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// 指定预算守卫。
    #[must_use]
    pub fn with_budget(mut self, budget: BudgetGuard) -> Self {
        self.budget = budget;
        self
    }

    /// 允许缓存。
    #[must_use]
    pub const fn allow_cache(mut self, allow: bool) -> Self {
        self.allow_cache = allow;
        self
    }

    /// 禁止读取和写入缓存，用于需要当前模型结论的安全研判。
    #[must_use]
    pub const fn without_cache(mut self) -> Self {
        self.disable_cache = true;
        self
    }

    /// 禁止降级（只尝试链上第一个端点）。
    #[must_use]
    pub const fn no_fallback(mut self) -> Self {
        self.allow_fallback = false;
        self
    }

    /// 生成路由上下文。
    #[must_use]
    pub fn routing_context(&self, req: &ChatRequest) -> RoutingContext {
        RoutingContext {
            tenant: self.tenant,
            data_class: self.data_class,
            pinned_model: if req.model.trim().is_empty() { None } else { Some(req.model.clone()) },
            strategy: self.strategy,
            require_streaming: req.stream,
            require_tools: req.needs_tools(),
            require_vision: req.has_image(),
            allow_fallback: self.allow_fallback,
        }
    }
}

impl EndpointView {
    /// 人类可读的一行摘要。
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{}（{}/{}）{}",
            self.name,
            self.provider.as_str(),
            self.model,
            if self.usable { "可用" } else { "不可用" }
        )
    }
}

impl GatewayResponse {
    /// 实际产生上游费用的 token 数（缓存命中为 0）。
    #[must_use]
    pub const fn billed_tokens(&self) -> u64 {
        if self.cached { 0 } else { self.usage.total() }
    }

    /// 人类可读摘要（日志/审计）。
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "provider={} model={} cached={} mocked={} fallback={} tokens={}/{} cost={}微元 latency={}ms",
            self.provider.as_str(),
            self.model,
            self.cached,
            self.mocked,
            self.fallback_used,
            self.usage.prompt_tokens,
            self.usage.completion_tokens,
            self.cost_micro,
            self.latency_ms
        )
    }
}

impl std::fmt::Debug for AiGateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiGateway")
            .field("endpoints", &self.router.len())
            .field("has_redis_cache", &self.cache.has_redis())
            .field("mock_mode", &self.mock_mode())
            .field("prompts", &self.prompts.len())
            .finish_non_exhaustive()
    }
}

impl AiGateway {
    /// 用默认组件构造（NoopScreen、内存缓存、内存计量）。
    #[must_use]
    pub fn new(endpoints: Vec<ModelEndpoint>) -> Self {
        Self {
            router: Arc::new(ModelRouter::new(endpoints)),
            credentials: Arc::new(EnvCredentialResolver::new()),
            cache: Arc::new(ExactCache::memory()),
            meter: Arc::new(Meter::new()),
            screen: Arc::new(NoopScreen::new()),
            mock_mode_override: None,
            providers: parking_lot::Mutex::new(BTreeMap::new()),
            prompts: BTreeMap::new(),
            analysis_model: None,
            session_affinity: parking_lot::Mutex::new(BTreeMap::new()),
        }
    }
    /// 替换凭据解析器。
    #[must_use]
    pub fn with_credentials(mut self, resolver: Arc<dyn CredentialResolver>) -> Self {
        self.credentials = resolver;
        self
    }
    /// 替换语义缓存。
    #[must_use]
    pub fn with_cache(mut self, cache: Arc<ExactCache>) -> Self {
        self.cache = cache;
        self
    }
    /// 替换内容安全过滤器。
    #[must_use]
    pub fn with_screen(mut self, screen: Arc<dyn ContentScreen>) -> Self {
        self.screen = screen;
        self
    }
    /// 替换计量器。
    #[must_use]
    pub fn with_meter(mut self, meter: Arc<Meter>) -> Self {
        self.meter = meter;
        self
    }
    /// 显式设置 Mock 模式（覆盖 `AGF_MOCK_MODE`，测试与"离线演示"按钮用）。
    #[must_use]
    pub const fn with_mock_mode(mut self, mock: bool) -> Self {
        self.mock_mode_override = Some(mock);
        self
    }
    /// 注入 Prompt 模板（`analyze` 使用）。
    #[must_use]
    pub fn with_prompts(mut self, prompts: BTreeMap<String, String>) -> Self {
        self.prompts = prompts;
        self
    }
    /// 指定分析用模型。
    #[must_use]
    pub fn with_analysis_model(mut self, model: impl Into<String>) -> Self {
        self.analysis_model = Some(model.into());
        self
    }
    /// 是否处于 Mock 模式。
    #[must_use]
    pub fn mock_mode(&self) -> bool {
        self.mock_mode_override.unwrap_or_else(crate::mock_mode_enabled)
    }
    /// 路由表（只读）。
    #[must_use]
    pub fn router(&self) -> &ModelRouter {
        &self.router
    }
    /// 计量器（只读）。
    #[must_use]
    pub fn meter(&self) -> &Meter {
        &self.meter
    }
    /// 语义缓存（只读）。
    #[must_use]
    pub fn cache(&self) -> &ExactCache {
        &self.cache
    }
    /// 缓存统计。
    #[must_use]
    pub fn cache_stats(&self) -> CacheStats {
        CacheStats {
            hits: self.cache.hits(),
            misses: self.cache.misses(),
            saved_tokens: self.cache.saved_tokens(),
            saved_micro: self.cache.saved_micro(),
        }
    }
    // -----------------------------------------------------------------------
    // 提供商解析
    // -----------------------------------------------------------------------

    /// 该端点的凭据是否**真的解析得出**（不含 Mock 模式判断）。
    ///
    /// - 无 `credential_ref` → `false`（未配置）；
    /// - 有 `credential_ref` 但 [`CredentialResolver`] 返回空 → `false`
    ///   （凭据缺失或解密失败，应降级）；
    /// - 解析成功 → `true`。
    #[must_use]
    pub fn credential_available(&self, endpoint: &ModelEndpoint) -> bool {
        let Some(reference) = endpoint.credential_ref.as_ref() else {
            return false;
        };
        if endpoint.provider == LlmProvider::Bedrock {
            // Bedrock 也接受环境变量（AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY）
            return crate::provider::BedrockProvider::from_endpoint(endpoint, self.credentials.as_ref()).configured();
        }
        self.credentials.resolve_api_key(reference).is_some_and(|k| !k.trim().is_empty())
    }
    /// 端点是否应当走 Mock（**"无 Key 也能跑" 的判定中心**）。
    ///
    /// 为真的三种情形：全局 Mock 模式 / 端点本身就是 Mock / **凭据解析不出来**。
    /// 注意最后一种：端点"声明了"凭据引用但解析为空（未配置或解密失败）时，
    /// 网关必须降级而不是报错——这是 §11 阶段一验收准则 5 的实现点。
    #[must_use]
    pub fn endpoint_is_mock(&self, endpoint: &ModelEndpoint) -> bool {
        self.mock_mode() || endpoint.provider == LlmProvider::Mock || !self.credential_available(endpoint)
    }
    /// 解析端点对应的提供商（**无凭据 / Mock 模式一律返回 MockProvider**，不联网）。
    ///
    /// # Errors
    /// 目前不会返回错误（保留签名以便将来对"配置损坏"做显式失败）。
    pub fn provider_for(&self, endpoint: &ModelEndpoint) -> DomainResult<Arc<dyn ProviderAdapter>> {
        let key = endpoint.id.to_string();
        if let Some(found) = self.providers.lock().get(&key) {
            return Ok(found.clone());
        }
        let provider: Arc<dyn ProviderAdapter> = if self.endpoint_is_mock(endpoint) {
            Arc::new(MockProvider::new().with_model(endpoint.model.clone()))
        } else {
            match endpoint.provider {
                LlmProvider::Anthropic => {
                    Arc::new(AnthropicProvider::from_endpoint(endpoint, self.credentials.as_ref()))
                }
                LlmProvider::Gemini => Arc::new(GeminiProvider::from_endpoint(endpoint, self.credentials.as_ref())),
                LlmProvider::Bedrock => Arc::new(BedrockProvider::from_endpoint(endpoint, self.credentials.as_ref())),
                other if other.is_openai_compatible() => {
                    Arc::new(OpenAiCompatProvider::from_endpoint(endpoint, self.credentials.as_ref()))
                }
                other => {
                    warn!(provider = other.as_str(), "未识别的厂商，按 OpenAI 兼容协议处理");
                    Arc::new(OpenAiCompatProvider::from_endpoint(endpoint, self.credentials.as_ref()))
                }
            }
        };
        self.providers.lock().insert(key, provider.clone());
        Ok(provider)
    }
    /// 端点视图（控制台"接入管理"页）。
    ///
    /// # Errors
    /// 提供商解析失败（当前实现不会发生，保留签名以备扩展）。
    pub fn describe_endpoints(&self) -> DomainResult<Vec<EndpointView>> {
        let mut out = Vec::with_capacity(self.router.len());
        for endpoint in self.router.endpoints() {
            let mocked = self.endpoint_is_mock(endpoint);
            let configured = !mocked;
            let reason = if !endpoint.enabled {
                Some("端点已禁用".to_string())
            } else if self.mock_mode() {
                Some("AGF_MOCK_MODE=1：全部请求走 Mock".to_string())
            } else if mocked {
                Some(match endpoint.credential_ref {
                    Some(_) => {
                        "凭据引用存在但解析为空（未配置或解密失败）：运行时会自动降级到 MockProvider".to_string()
                    }
                    None => "未配置凭据：运行时会自动降级到 MockProvider（不报错）".to_string(),
                })
            } else {
                None
            };
            // 适配器名/协议名：Mock 与真实提供商分别取描述
            let (adapter, protocol) = if mocked {
                let d = MockProvider::new().provider_descriptor();
                (d.adapter.name, d.protocol)
            } else {
                let provider = self.provider_for(endpoint)?;
                let d: ProviderDescriptor = provider.provider_descriptor();
                (d.adapter.name, d.protocol)
            };
            out.push(EndpointView {
                id: endpoint.id,
                name: endpoint.name.clone(),
                provider: endpoint.provider,
                model: endpoint.model.clone(),
                protocol,
                adapter,
                enabled: endpoint.enabled,
                local_deployment: endpoint.local_deployment,
                max_data_class: endpoint.max_data_class,
                pricing: endpoint.pricing,
                credential_configured: configured,
                mocked,
                usable: endpoint.enabled,
                reason,
            });
        }
        Ok(out)
    }
    // -----------------------------------------------------------------------
    // chat
    // -----------------------------------------------------------------------

    /// 非流式对话（含预筛/路由/缓存/降级/后筛/计量/回写）。
    ///
    /// # Errors
    /// - 内容安全阻断 → `PolicyDenied`；
    /// - 无可用端点 → `Config`；
    /// - 预算超限 → `QuotaExceeded`；
    /// - 全部候选端点失败 → 最后一次失败的原始错误。
    pub async fn chat(&self, ctx: CallContext, req: ChatRequest) -> DomainResult<GatewayResponse> {
        let started = Instant::now();
        let prepared = self.prepare_request(&ctx, req)?;
        let mut active_ctx = ctx;
        // 预筛可能改写了请求内容：数据分级以改写后的 metadata 为准（保持一致）
        active_ctx.data_class = crate::cache::data_class_of(&prepared.request);
        self.chat_inner(active_ctx, prepared.request, prepared.screening, started, None).await
    }
    /// 预筛并决定是否改写请求。
    pub(crate) fn prepare_request(&self, ctx: &CallContext, mut req: ChatRequest) -> DomainResult<Prepared> {
        // 数据分级以 CallContext 为准（更可信），写入 metadata 供路由与缓存判定
        req.metadata.insert("data_class".into(), ctx.data_class.as_str().to_string());

        let mut screening = ScreeningSummary::default();
        if !self.screen.is_noop() {
            let outcome = self.screen.screen_request(&req);
            match &outcome.verdict {
                ScreenVerdict::Block { reason, rule } => {
                    warn!(rule = %rule.id, "内容安全预筛阻断请求（未触达厂商）");
                    return Err(DomainError::PolicyDenied {
                        policy: rule.id.clone(),
                        action: "deny".to_string(),
                        reason: reason.clone(),
                    });
                }
                ScreenVerdict::Redact(items) => {
                    screening.request_rules.push("redact".to_string());
                    screening.request_redactions = items.len();
                    screening.mutated = true;
                }
                ScreenVerdict::Allow => {}
            }
            if let Some(rewritten) = outcome.request {
                req = rewritten;
            }
        }
        req.ensure_anthropic_native_unchanged()?;
        Ok(Prepared { request: req, screening })
    }
}
