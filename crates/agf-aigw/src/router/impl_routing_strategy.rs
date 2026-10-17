//! 由 `router.rs` 拆分：`ModelRouter`/`RoutingContext`/`RoutingDecision`/`RoutingStrategy` 的实现（纯搬移，逻辑不变）。
use super::*;

impl RoutingStrategy {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::CostFirst => "cost-first",
            Self::LatencyFirst => "latency-first",
            Self::QualityFirst => "quality-first",
            Self::LocalFirst => "local-first",
            Self::RoundRobin => "round-robin",
        }
    }

    /// 全部策略。
    #[must_use]
    pub const fn all() -> [Self; 5] {
        [Self::CostFirst, Self::LatencyFirst, Self::QualityFirst, Self::LocalFirst, Self::RoundRobin]
    }

    /// 解析文本。
    ///
    /// # Errors
    /// 未知策略返回错误描述。
    pub fn parse(value: &str) -> Result<Self, String> {
        let v = value.to_ascii_lowercase().replace('_', "-");
        Self::all().into_iter().find(|s| s.as_str() == v).ok_or_else(|| format!("未知路由策略: {value}"))
    }

    /// 中文说明（控制台展示）。
    #[must_use]
    pub const fn display_zh(&self) -> &'static str {
        match self {
            Self::CostFirst => "成本优先",
            Self::LatencyFirst => "延迟优先",
            Self::QualityFirst => "质量优先",
            Self::LocalFirst => "本地优先",
            Self::RoundRobin => "轮询分摊",
        }
    }
}

impl Default for RoutingStrategy {
    /// 默认策略：成本优先。
    fn default() -> Self {
        Self::CostFirst
    }
}

impl RoutingContext {
    /// 新建（默认策略、无能力要求）。
    #[must_use]
    pub fn new(tenant: TenantId, data_class: DataClass) -> Self {
        Self {
            tenant,
            data_class,
            pinned_model: None,
            strategy: RoutingStrategy::CostFirst,
            require_streaming: false,
            require_tools: false,
            require_vision: false,
            allow_fallback: true,
        }
    }

    /// 指定策略。
    #[must_use]
    pub const fn with_strategy(mut self, strategy: RoutingStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// 锁定模型。
    #[must_use]
    pub fn pinned(mut self, model: impl Into<String>) -> Self {
        self.pinned_model = Some(model.into());
        self
    }

    /// 要求流式。
    #[must_use]
    pub const fn requiring_stream(mut self) -> Self {
        self.require_streaming = true;
        self
    }

    /// 要求工具调用。
    #[must_use]
    pub const fn requiring_tools(mut self) -> Self {
        self.require_tools = true;
        self
    }

    /// 要求视觉。
    #[must_use]
    pub const fn requiring_vision(mut self) -> Self {
        self.require_vision = true;
        self
    }

    /// 禁止降级。
    #[must_use]
    pub const fn without_fallback(mut self) -> Self {
        self.allow_fallback = false;
        self
    }
}

impl RoutingDecision {
    /// 决策的一句话摘要。
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "策略={} 分级={} 链路={} 排除={}",
            self.strategy.as_str(),
            self.data_class.as_str(),
            self.chain.join(" → "),
            self.excluded.len()
        )
    }
}

impl ModelRouter {
    /// 新建（端点顺序即登记顺序，选择时重新排序）。
    #[must_use]
    pub fn new(endpoints: Vec<ModelEndpoint>) -> Self {
        Self { endpoints, round_robin: AtomicUsize::new(0) }
    }

    /// 全部端点（登记顺序）。
    #[must_use]
    pub fn endpoints(&self) -> &[ModelEndpoint] {
        &self.endpoints
    }

    /// 端点数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    /// 是否没有任何端点。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    /// 启用端点数。
    #[must_use]
    pub fn enabled_count(&self) -> usize {
        self.endpoints.iter().filter(|e| e.enabled).count()
    }

    /// 按 id 查端点。
    #[must_use]
    pub fn get(&self, id: agf_core::ids::Id) -> Option<&ModelEndpoint> {
        self.endpoints.iter().find(|e| e.id == id)
    }

    /// 按模型名查端点。
    #[must_use]
    pub fn by_model(&self, model: &str) -> Option<&ModelEndpoint> {
        self.endpoints.iter().find(|e| e.model == model && e.enabled)
    }

    /// 选择有序降级链。
    ///
    /// # Errors
    /// 没有任何候选端点时返回 [`DomainError::Config`]（含"为什么都被排除"的提示）。
    pub fn select(&self, ctx: &RoutingContext) -> DomainResult<Vec<&ModelEndpoint>> {
        Ok(self.select_with_decision(ctx)?.0)
    }

    /// All endpoints that can receive this request, without advancing round-robin state.
    /// Preflight reservations must cover every possible endpoint, including a later fallback.
    pub fn eligible(&self, ctx: &RoutingContext) -> DomainResult<Vec<&ModelEndpoint>> {
        let mut probe = ctx.clone();
        probe.strategy = RoutingStrategy::CostFirst;
        probe.allow_fallback = true;
        self.select(&probe)
    }

    /// 选择并附带决策记录（审计/排障/覆盖终态）。
    ///
    /// # Errors
    /// 没有任何候选端点时返回 [`DomainError::Config`]。
    pub fn select_with_decision(&self, ctx: &RoutingContext) -> DomainResult<(Vec<&ModelEndpoint>, RoutingDecision)> {
        let mut candidates: Vec<&ModelEndpoint> = Vec::new();
        let mut excluded: Vec<Exclusion> = Vec::new();

        for endpoint in &self.endpoints {
            if let Some(reason) = self.exclude_reason(endpoint, ctx) {
                excluded.push(Exclusion { endpoint: endpoint.name.clone(), reason });
                continue;
            }
            candidates.push(endpoint);
        }

        if candidates.is_empty() {
            let detail =
                excluded.iter().map(|e| format!("{}（{}）", e.endpoint, e.reason)).collect::<Vec<_>>().join("；");
            return Err(DomainError::Config(format!(
                "无可用模型端点：共 {} 个端点，全部被排除。{}",
                self.endpoints.len(),
                if detail.is_empty() { String::new() } else { format!("原因：{detail}") }
            )));
        }

        self.sort(&mut candidates, ctx);
        if !ctx.allow_fallback {
            candidates.truncate(1);
        }
        let decision = RoutingDecision {
            strategy: ctx.strategy,
            data_class: ctx.data_class,
            chain: candidates.iter().map(|e| e.name.clone()).collect(),
            excluded,
        };
        Ok((candidates, decision))
    }

    /// 端点是否应当被排除（`None` = 通过）。
    // `&self` 为未来扩展（按端点标签/区域过滤）保留，当前实现不读实例状态
    #[allow(clippy::unused_self)]
    pub(crate) fn exclude_reason(&self, endpoint: &ModelEndpoint, ctx: &RoutingContext) -> Option<String> {
        if !endpoint.enabled {
            return Some("端点已禁用".to_string());
        }
        if endpoint.tenant_id != ctx.tenant && endpoint.tenant_id != TenantId::default_tenant() {
            return Some("租户不匹配".to_string());
        }
        if !endpoint.accepts_data_class(ctx.data_class) {
            return Some(if ctx.data_class.requires_local_inference() && !endpoint.local_deployment {
                format!("数据分级 {} 要求本地部署（数据不出域）", ctx.data_class.as_str())
            } else {
                format!("数据分级 {} 超过端点上限 {}", ctx.data_class.as_str(), endpoint.max_data_class.as_str())
            });
        }
        if ctx.require_streaming && !endpoint.supports_streaming {
            return Some("不支持流式".to_string());
        }
        if ctx.require_tools && !endpoint.supports_tools {
            return Some("不支持工具调用".to_string());
        }
        if ctx.require_vision && !endpoint.modalities.contains(&Modality::Vision) {
            return Some("不支持视觉输入".to_string());
        }
        if let Some(pinned) = &ctx.pinned_model {
            let matches = endpoint.model == *pinned || endpoint.id.to_string() == *pinned;
            if !matches {
                return Some(format!("与锁定模型 {pinned} 不匹配"));
            }
        }
        None
    }

    /// 排序（确定性）。
    pub(crate) fn sort(&self, candidates: &mut Vec<&ModelEndpoint>, ctx: &RoutingContext) {
        match ctx.strategy {
            RoutingStrategy::CostFirst => candidates.sort_by(|a, b| {
                cost_key(a)
                    .cmp(&cost_key(b))
                    .then(a.priority.cmp(&b.priority))
                    .then(a.id.as_uuid().cmp(&b.id.as_uuid()))
            }),
            RoutingStrategy::LatencyFirst => candidates.sort_by(|a, b| {
                a.priority
                    .cmp(&b.priority)
                    .then(b.context_window.unwrap_or(0).cmp(&a.context_window.unwrap_or(0)))
                    .then(a.id.as_uuid().cmp(&b.id.as_uuid()))
            }),
            RoutingStrategy::QualityFirst => candidates.sort_by(|a, b| {
                b.context_window
                    .unwrap_or(0)
                    .cmp(&a.context_window.unwrap_or(0))
                    .then(a.priority.cmp(&b.priority))
                    .then(a.id.as_uuid().cmp(&b.id.as_uuid()))
            }),
            RoutingStrategy::LocalFirst => candidates.sort_by(|a, b| {
                b.local_deployment
                    .cmp(&a.local_deployment)
                    .then(a.priority.cmp(&b.priority))
                    .then(a.id.as_uuid().cmp(&b.id.as_uuid()))
            }),
            RoutingStrategy::RoundRobin => {
                // 先按 priority 稳定排序，再按原子计数器轮转起点
                candidates.sort_by(|a, b| a.priority.cmp(&b.priority).then(a.id.as_uuid().cmp(&b.id.as_uuid())));
                if !candidates.is_empty() {
                    let offset = self.round_robin.fetch_add(1, Ordering::Relaxed) % candidates.len();
                    candidates.rotate_left(offset);
                }
            }
        }
    }

    /// 轮询计数器当前值（测试与排障）。
    #[must_use]
    pub fn round_robin_counter(&self) -> usize {
        self.round_robin.load(Ordering::Relaxed)
    }
}
