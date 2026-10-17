//! 由 `meter.rs` 拆分：`impl_CostBreakdown`/`breakdown` 等 8 项（纯搬移，逻辑不变）。
use super::*;

impl CostBreakdown {
    /// 合计是否与分项一致（自检用）。
    #[must_use]
    pub const fn is_consistent(&self) -> bool {
        self.prompt_micro
            .saturating_add(self.cached_prompt_micro)
            .saturating_add(self.cache_write_prompt_micro)
            .saturating_add(self.completion_micro)
            == self.total_micro
    }

    /// 折算为元（保留 6 位小数）。
    #[must_use]
    pub fn total_yuan(&self) -> f64 {
        self.total_micro as f64 / 1_000_000.0
    }
}

/// 按 [`ModelEndpoint::pricing`] 计算一次调用的成本明细（纯整数运算）。
///
/// 与 [`crate::cache::cost_micro`] 口径一致；本函数额外给出分项，便于控制台展示。
#[must_use]
pub fn breakdown(endpoint: &ModelEndpoint, usage: &Usage) -> CostBreakdown {
    let pricing = &endpoint.pricing;
    let cached = usage.cached_tokens.min(usage.prompt_tokens);
    let writes = usage.cache_write_tokens.min(usage.prompt_tokens.saturating_sub(cached));
    let one_hour = usage.cache_write_1h_tokens.min(writes);
    let normal = usage.prompt_tokens.saturating_sub(cached).saturating_sub(writes);
    let cached_rate = if pricing.cached_prompt_micro_per_1k == 0 {
        pricing.prompt_micro_per_1k
    } else {
        pricing.cached_prompt_micro_per_1k
    };
    let prompt_micro = u128::from(pricing.prompt_micro_per_1k) * u128::from(normal) / 1000;
    let base_rate = u128::from(pricing.prompt_micro_per_1k);
    let cache_write_prompt_micro = if endpoint.provider == LlmProvider::Anthropic {
        let five_minutes = writes.saturating_sub(one_hour);
        (base_rate.saturating_mul(u128::from(five_minutes)).saturating_mul(5) / 4000)
            .saturating_add(base_rate.saturating_mul(u128::from(one_hour)).saturating_mul(2) / 1000)
    } else {
        base_rate.saturating_mul(u128::from(writes)) / 1000
    };
    let cached_prompt_micro = u128::from(cached_rate) * u128::from(cached) / 1000;
    let completion_micro = u128::from(pricing.completion_micro_per_1k) * u128::from(usage.completion_tokens) / 1000;
    let total = prompt_micro
        .saturating_add(cached_prompt_micro)
        .saturating_add(cache_write_prompt_micro)
        .saturating_add(completion_micro);
    CostBreakdown {
        prompt_micro: u64::try_from(prompt_micro).unwrap_or(u64::MAX),
        cached_prompt_micro: u64::try_from(cached_prompt_micro).unwrap_or(u64::MAX),
        cache_write_prompt_micro: u64::try_from(cache_write_prompt_micro).unwrap_or(u64::MAX),
        completion_micro: u64::try_from(completion_micro).unwrap_or(u64::MAX),
        total_micro: u64::try_from(total).unwrap_or(u64::MAX),
    }
}

impl MeterKey {
    /// 文本形式（控制台分组展示用）。
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Tenant(t) => format!("tenant:{t}"),
            Self::Agent(t, a) => format!("agent:{t}/{a}"),
            Self::Session(t, s) => format!("session:{t}/{s}"),
        }
    }
}

impl MeterTotals {
    /// 总 token。
    #[must_use]
    pub const fn total_tokens(&self) -> u64 {
        self.prompt_tokens.saturating_add(self.completion_tokens)
    }

    /// 平均耗时（毫秒，无调用时为 0）。
    #[must_use]
    #[allow(clippy::manual_checked_ops)]
    pub const fn avg_latency_ms(&self) -> u64 {
        match self.latency_ms.checked_div(self.calls) {
            Some(v) => v,
            None => 0,
        }
    }

    /// 累加。
    pub fn accumulate(&mut self, other: &Self) {
        self.calls = self.calls.saturating_add(other.calls);
        self.cache_hits = self.cache_hits.saturating_add(other.cache_hits);
        self.mocked_calls = self.mocked_calls.saturating_add(other.mocked_calls);
        self.prompt_tokens = self.prompt_tokens.saturating_add(other.prompt_tokens);
        self.completion_tokens = self.completion_tokens.saturating_add(other.completion_tokens);
        self.cached_tokens = self.cached_tokens.saturating_add(other.cached_tokens);
        self.cache_write_tokens = self.cache_write_tokens.saturating_add(other.cache_write_tokens);
        self.cache_write_1h_tokens = self.cache_write_1h_tokens.saturating_add(other.cache_write_1h_tokens);
        self.cost_micro = self.cost_micro.saturating_add(other.cost_micro);
        self.latency_ms = self.latency_ms.saturating_add(other.latency_ms);
    }
}

impl MeterSnapshot {
    /// 总费用（微元）。
    #[must_use]
    pub const fn cost_micro(&self) -> u64 {
        self.total.cost_micro
    }

    /// 总费用（元）。
    #[must_use]
    pub fn cost_yuan(&self) -> f64 {
        self.total.cost_micro as f64 / 1_000_000.0
    }
}

impl Meter {
    /// 内存中保留的最近记录条数上限。
    pub const MAX_RECENT: usize = 512;

    /// 新建。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录一次调用，返回生成的 [`UsageRecord`]。
    ///
    /// 本条记录只计算聊天提供商费用；精确缓存命中和 Mock 均没有付费聊天调用，费用记 0。
    /// 调用次数和逻辑 token 保留。未来付费 embedding 必须单独计价，不能用整体缓存标记清零。
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        tenant: TenantId,
        session_id: &str,
        agent_id: Option<Id>,
        endpoint: &ModelEndpoint,
        usage: Usage,
        cache_hit: bool,
        mocked: bool,
        latency_ms: u64,
    ) -> UsageRecord {
        let record = Self::construct_record(UsageInput {
            id: Id::new(),
            tenant,
            session_id,
            agent_id,
            endpoint,
            usage,
            cache_hit,
            mocked,
            latency_ms,
        });
        self.absorb(&record);
        record
    }

    /// Hydrate a committed usage row once. A conflicting duplicate is rejected safely.
    pub fn absorb(&self, record: &UsageRecord) {
        if let Err(error) = self.absorb_once(record) {
            tracing::warn!(%error, "Committed meter projection rejected a conflicting usage identity");
        }
    }

    /// 快照（控制台展示）。
    #[must_use]
    pub fn snapshot(&self) -> MeterSnapshot {
        let guard = self.inner.lock();
        MeterSnapshot {
            committed_projection_incomplete: guard.committed_projection_incomplete,
            committed_groups_merged: guard
                .committed
                .values()
                .any(super::projection::CommittedMeterProjection::groups_merged),
            total: guard.total,
            by_tenant: guard.by_tenant.clone(),
            by_agent: guard.by_agent.clone(),
            by_session: guard.by_session.clone(),
            by_provider: guard.by_provider.clone(),
            by_model: guard.by_model.clone(),
            generated_at: Some(Timestamp::now()),
        }
    }

    /// 某个租户的累计值。
    #[must_use]
    pub fn tenant_totals(&self, tenant: TenantId) -> MeterTotals {
        self.inner.lock().by_tenant.get(&tenant.to_string()).copied().unwrap_or_default()
    }

    /// 某个会话的累计值。
    #[must_use]
    pub fn session_totals(&self, session_id: &str) -> MeterTotals {
        self.inner.lock().by_session.get(session_id).copied().unwrap_or_default()
    }

    /// 某个 Agent 的累计值。
    #[must_use]
    pub fn agent_totals(&self, agent_id: Id) -> MeterTotals {
        self.inner.lock().by_agent.get(&agent_id.to_string()).copied().unwrap_or_default()
    }

    /// 最近记录（倒序，最新在前）。
    #[must_use]
    pub fn recent(&self, limit: usize) -> Vec<UsageRecord> {
        let guard = self.inner.lock();
        guard.recent.iter().rev().take(limit).cloned().collect()
    }

    /// 清空（测试用）。
    pub fn reset(&self) {
        *self.inner.lock() = MeterInner::default();
    }
}

impl Default for BudgetGuard {
    /// 默认不限预算（与 [`BudgetGuard::unlimited`] 等价）。
    fn default() -> Self {
        Self::unlimited()
    }
}

fn cache_write_ttl(body: &serde_json::Value) -> u8 {
    fn marker(value: &serde_json::Value) -> u8 {
        match value.get("cache_control").and_then(serde_json::Value::as_object) {
            Some(control) if control.get("ttl").and_then(serde_json::Value::as_str) == Some("1h") => 2,
            Some(_) => 1,
            None => 0,
        }
    }

    fn content(value: &serde_json::Value) -> u8 {
        value.as_array().map_or(0, |blocks| {
            blocks.iter().map(|block| marker(block).max(content(&block["content"]))).max().unwrap_or(0)
        })
    }

    marker(body)
        .max(content(&body["system"]))
        .max(body["tools"].as_array().map_or(0, |tools| tools.iter().map(marker).max().unwrap_or(0)))
        .max(
            body["messages"]
                .as_array()
                .map_or(0, |messages| messages.iter().map(|message| content(&message["content"])).max().unwrap_or(0)),
        )
}

impl BudgetGuard {
    /// 不限预算。
    #[must_use]
    pub const fn unlimited() -> Self {
        Self { max_single_micro: 0, max_total_micro: 0 }
    }

    /// 指定单次上限。
    #[must_use]
    pub const fn single(max_single_micro: u64) -> Self {
        Self { max_single_micro, max_total_micro: 0 }
    }

    /// 指定单次 + 累计上限。
    #[must_use]
    pub const fn new(max_single_micro: u64, max_total_micro: u64) -> Self {
        Self { max_single_micro, max_total_micro }
    }

    /// 预估本次调用的费用（按 `max_tokens` 上限保守估计输出，避免低估）。
    #[must_use]
    pub fn projected_micro(endpoint: &ModelEndpoint, prompt_tokens: u64, max_completion_tokens: u64) -> u64 {
        breakdown(endpoint, &Usage::new(prompt_tokens, max_completion_tokens, 0)).total_micro
    }

    /// Conservatively reserve the most expensive possible input category for a request.
    /// A cache breakpoint can write the whole prompt; a later call can read it instead.
    #[must_use]
    pub fn projected_micro_for_request(endpoint: &ModelEndpoint, request: &crate::wire::ChatRequest) -> u64 {
        let prompt = request.estimate_prompt_tokens();
        let completion = u64::from(request.max_tokens.unwrap_or(1024));
        let normal = Self::projected_micro(endpoint, prompt, completion);
        let cached = breakdown(endpoint, &Usage::new(prompt, completion, prompt)).total_micro;
        let mut projected = normal.max(cached);
        if endpoint.provider == LlmProvider::Anthropic {
            let ttl = request.anthropic_native.as_ref().map_or(0, |native| cache_write_ttl(&native.body));
            if ttl > 0 {
                let write = Usage {
                    prompt_tokens: prompt,
                    completion_tokens: completion,
                    cache_write_tokens: prompt,
                    cache_write_1h_tokens: if ttl == 2 { prompt } else { 0 },
                    ..Usage::default()
                };
                projected = projected.max(breakdown(endpoint, &write).total_micro);
            }
        }
        projected
    }

    /// Apply the same budget limits to the cache-aware reservation.
    pub fn ensure_within_budget_for_request(
        &self,
        scope: &str,
        endpoint: &ModelEndpoint,
        request: &crate::wire::ChatRequest,
        already_spent_micro: u64,
    ) -> DomainResult<u64> {
        self.ensure_projected(scope, Self::projected_micro_for_request(endpoint, request), already_spent_micro)
    }

    /// 检查是否允许调用。
    ///
    /// # Errors
    /// 超出单次或累计上限时返回 `DomainError::QuotaExceeded`。
    pub fn ensure_within_budget(
        &self,
        scope: &str,
        endpoint: &ModelEndpoint,
        prompt_tokens: u64,
        max_completion_tokens: u64,
        already_spent_micro: u64,
    ) -> DomainResult<u64> {
        let projected = Self::projected_micro(endpoint, prompt_tokens, max_completion_tokens);
        self.ensure_projected(scope, projected, already_spent_micro)
    }

    fn ensure_projected(&self, scope: &str, projected: u64, already_spent_micro: u64) -> DomainResult<u64> {
        if self.max_single_micro > 0 && projected > self.max_single_micro {
            return Err(DomainError::QuotaExceeded {
                scope: format!("{scope}/single"),
                dimension: "cost".to_string(),
                used: i64::try_from(projected).unwrap_or(i64::MAX),
                limit: i64::try_from(self.max_single_micro).unwrap_or(i64::MAX),
            });
        }
        if self.max_total_micro > 0 {
            let after = already_spent_micro.saturating_add(projected);
            if after > self.max_total_micro {
                return Err(DomainError::QuotaExceeded {
                    scope: format!("{scope}/total"),
                    dimension: "cost".to_string(),
                    used: i64::try_from(after).unwrap_or(i64::MAX),
                    limit: i64::try_from(self.max_total_micro).unwrap_or(i64::MAX),
                });
            }
        }
        Ok(projected)
    }

    /// 是否设置了任何上限。
    #[must_use]
    pub const fn is_limited(&self) -> bool {
        self.max_single_micro > 0 || self.max_total_micro > 0
    }
}
