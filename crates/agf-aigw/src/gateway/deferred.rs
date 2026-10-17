//! API-owned nonstream attempts: stable pure usage, original budget and post-commit cache only.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

#[async_trait::async_trait]
pub trait SettlementGuard: Send + Sync {
    async fn validate(&self) -> DomainResult<()>;
}

pub struct DeferredCall {
    usage_id: Id,
    endpoint_id: Id,
    deadline: tokio::time::Instant,
    guard: Arc<dyn SettlementGuard>,
    started: AtomicBool,
    entered: AtomicBool,
    cache: parking_lot::Mutex<Option<CacheAfterCommit>>,
    journal: super::deferred_components::ComponentJournal,
    response_blocked: parking_lot::Mutex<Vec<String>>,
}

impl std::fmt::Debug for DeferredCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeferredCall")
            .field("usage_id", &self.usage_id)
            .field("endpoint_id", &self.endpoint_id)
            .finish_non_exhaustive()
    }
}

// Ephemeral only; never Serialize/Debug and never put prompt or model output into settlement facts.
struct CacheAfterCommit {
    context: CallContext,
    request: ChatRequest,
    endpoint: ModelEndpoint,
    response: ChatResponse,
}

impl DeferredCall {
    /// Only an authenticated atomic admission may provide the stable usage UUID.
    /// # Errors
    /// Nil identity or an expired original deadline is rejected without dispatch.
    pub fn new(
        usage_id: Id,
        endpoint_id: Id,
        deadline: tokio::time::Instant,
        guard: Arc<dyn SettlementGuard>,
    ) -> DomainResult<Self> {
        Self::new_chain(vec![DeferredComponentAnchor { usage_id, endpoint_id }], deadline, guard)
    }

    /// Bind the server-reserved ordered chain without selecting round-robin a second time.
    /// # Errors
    /// Invalid, duplicate, excessive or expired immutable anchors are rejected before dispatch.
    pub fn new_chain(
        anchors: Vec<DeferredComponentAnchor>,
        deadline: tokio::time::Instant,
        guard: Arc<dyn SettlementGuard>,
    ) -> DomainResult<Self> {
        let first = anchors.first().copied().ok_or_else(|| DomainError::Config("Empty paid chain".into()))?;
        if tokio::time::Instant::now() >= deadline {
            return Err(DomainError::Validation("Deferred model attempt has no live authenticated anchor".into()));
        }
        Ok(Self {
            usage_id: first.usage_id,
            endpoint_id: first.endpoint_id,
            deadline,
            guard,
            started: AtomicBool::new(false),
            entered: AtomicBool::new(false),
            cache: parking_lot::Mutex::new(None),
            journal: super::deferred_components::ComponentJournal::new(anchors)?,
            response_blocked: parking_lot::Mutex::new(Vec::new()),
        })
    }

    #[must_use]
    pub const fn usage_id(&self) -> Id {
        self.usage_id
    }

    #[must_use]
    pub fn provider_entered(&self) -> bool {
        self.entered.load(Ordering::Acquire)
    }

    /// Actual observed usage survives response-screen failures without storing response text.
    #[must_use]
    pub fn observed_usage(&self) -> Option<UsageRecord> {
        self.journal.selected_usage(self.endpoint_id)
    }

    pub(crate) fn observe_usage(&self, input: crate::meter::UsageInput<'_>) -> DomainResult<()> {
        self.journal.observe(input, true)
    }

    pub(crate) fn observe_partial(&self, input: crate::meter::UsageInput<'_>) -> DomainResult<()> {
        self.journal.observe(input, false)
    }

    /// Read safe evidence even if the stream, caller or response-screen has ended early.
    #[must_use]
    pub fn component_outcomes(&self) -> Vec<DeferredComponentOutcome> {
        self.journal.snapshot()
    }

    #[must_use]
    pub fn blocked_rules(&self) -> Vec<String> {
        self.response_blocked.lock().clone()
    }

    pub(crate) fn block_response(&self, rule: &str) {
        let mut rules = self.response_blocked.lock();
        if rules.len() < 32 && !rules.iter().any(|old| old == rule) {
            rules.push(rule.into());
        }
    }

    pub(crate) fn observed_for(&self, endpoint: Id) -> Option<UsageRecord> {
        self.journal.selected_usage(endpoint)
    }

    pub(crate) const fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }
    /// The original server-owned execution window; observing it grants no renewal or dispatch.
    #[must_use]
    pub const fn original_deadline(&self) -> tokio::time::Instant {
        self.deadline
    }

    pub(crate) fn selected(&self, chain: &[&ModelEndpoint]) -> DomainResult<()> {
        let anchors = self.journal.anchors();
        if chain.len() != anchors.len()
            || chain.iter().zip(&anchors).any(|(endpoint, anchor)| endpoint.id != anchor.endpoint_id)
        {
            return Err(DomainError::Conflict("Model selection differs from the immutable paid reservation".into()));
        }
        Ok(())
    }

    pub(crate) fn entered(&self, endpoint: Id) -> DomainResult<()> {
        self.journal.entered(endpoint)?;
        self.entered.store(true, Ordering::Release);
        Ok(())
    }

    pub(crate) fn chain<'a>(
        &self,
        gateway: &'a AiGateway,
        ctx: &CallContext,
        req: &ChatRequest,
    ) -> DomainResult<Vec<&'a ModelEndpoint>> {
        let eligible = gateway.router().eligible(&ctx.routing_context(req))?;
        self.journal
            .anchors()
            .iter()
            .map(|anchor| {
                eligible
                    .iter()
                    .find(|endpoint| endpoint.id == anchor.endpoint_id)
                    .copied()
                    .ok_or_else(|| DomainError::Conflict("Admitted candidate is no longer eligible".into()))
            })
            .collect()
    }

    pub(crate) fn start(&self) -> DomainResult<()> {
        if self.started.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return Err(DomainError::Conflict("Admitted model attempt cannot start twice".into()));
        }
        Ok(())
    }

    pub(crate) async fn check(&self) -> DomainResult<()> {
        if tokio::time::Instant::now() >= self.deadline {
            return Err(DomainError::Timeout("Model attempt exhausted its original execution budget".into()));
        }
        tokio::time::timeout_at(self.deadline, self.guard.validate())
            .await
            .map_err(|_| DomainError::Timeout("Model attempt authority check exhausted its original budget".into()))?
    }

    pub(crate) fn hold_cache(
        &self,
        context: CallContext,
        request: ChatRequest,
        endpoint: ModelEndpoint,
        response: ChatResponse,
    ) {
        *self.cache.lock() = Some(CacheAfterCommit { context, request, endpoint, response });
    }

    /// Invoke only after the original attempt and all its observed usage rows commit atomically.
    /// The primary UUID identifies that original attempt even when only a fallback has known usage.
    /// # Errors
    /// Current authority/source or the original deadline can prevent optional cache publication.
    pub async fn commit_cache(&self, gateway: &AiGateway, committed_usage_id: Id) -> DomainResult<()> {
        if committed_usage_id != self.usage_id || !self.started.load(Ordering::Acquire) {
            return Err(DomainError::Conflict(
                "Cache publication does not belong to this admitted model attempt".into(),
            ));
        }
        self.check().await?;
        let cache = self.cache.lock().take();
        if let Some(cache) = cache {
            tokio::time::timeout_at(
                self.deadline,
                gateway.write_cache(&cache.context, &cache.request, &cache.endpoint, &cache.response),
            )
            .await
            .map_err(|_| {
                DomainError::Timeout("Optional committed cache publication exceeded the original budget".into())
            })?;
        }
        Ok(())
    }
}

impl AiGateway {
    /// A service-validated semantic response still passes current authority and all output rules.
    /// Its original logical usage is preserved; only this chat component has zero new cost.
    /// # Errors
    /// Reuse, source/model mismatch, streaming or current authorization may reject delivery.
    pub async fn chat_deferred_cached(
        &self,
        mut ctx: CallContext,
        req: ChatRequest,
        mut response: ChatResponse,
        call: &DeferredCall,
    ) -> DomainResult<GatewayResponse> {
        if req.stream || call.started.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return Err(DomainError::Conflict("Admitted semantic reply cannot execute twice".into()));
        }
        ctx.budget.max_total_micro = 0;
        call.check().await?;
        let prepared = self.prepare_request(&ctx, req)?;
        let chain = self.router().eligible(&ctx.routing_context(&prepared.request))?;
        call.selected(&chain)?;
        let endpoint = chain.first().ok_or_else(|| DomainError::Config("Semantic reply has no endpoint".into()))?;
        if response.model != endpoint.model
            || response.raw.is_some()
            || response.finish_reason != crate::wire::FinishReason::Stop
        {
            return Err(DomainError::Validation("Semantic reply is not complete for the admitted model".into()));
        }
        let mocked = self.endpoint_is_mock(endpoint);
        let usage = response.usage;
        call.observe_usage(crate::meter::UsageInput {
            id: call.usage_id(),
            tenant: ctx.tenant,
            session_id: &ctx.session_id,
            agent_id: ctx.agent_id,
            endpoint,
            usage,
            cache_hit: true,
            mocked,
            latency_ms: 0,
        })?;
        let screening = self.process_response(
            &mut response,
            prepared.screening,
            u64::from(prepared.request.max_tokens.unwrap_or(1024)),
        )?;
        call.check().await?;
        let usage_record =
            call.observed_usage().ok_or_else(|| DomainError::Internal("Semantic reply usage missing".into()))?;
        Ok(GatewayResponse {
            response,
            endpoint_id: endpoint.id,
            provider: endpoint.provider,
            model: endpoint.model.clone(),
            usage,
            cost_micro: 0,
            cost: CostBreakdown::default(),
            cached: true,
            mocked,
            fallback_used: false,
            latency_ms: 0,
            screening,
            usage_record,
        })
    }

    /// API-owned deferred metering. Default chat and legacy streaming retain immediate behavior.
    /// # Errors
    /// Reusing this attempt, streaming, authority, screening or provider errors are rejected.
    pub async fn chat_deferred(
        &self,
        mut ctx: CallContext,
        req: ChatRequest,
        call: &DeferredCall,
    ) -> DomainResult<GatewayResponse> {
        if req.stream || call.started.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return Err(DomainError::Conflict(
                "This admitted model attempt cannot be started twice or as a stream".into(),
            ));
        }
        // Durable atomic admission checked cumulative budget; the uncommitted memory projection is not its authority.
        ctx.budget.max_total_micro = 0;
        call.check().await?;
        let started = Instant::now();
        let prepared = self.prepare_request(&ctx, req)?;
        ctx.data_class = std::cmp::max(ctx.data_class, crate::cache::data_class_of(&prepared.request));
        tokio::time::timeout_at(
            call.deadline,
            self.chat_inner(ctx, prepared.request, prepared.screening, started, Some(call)),
        )
        .await
        .map_err(|_| DomainError::Timeout("Model attempt exhausted its original execution budget".into()))?
    }

    pub(crate) fn record_usage(
        &self,
        deferred: Option<&DeferredCall>,
        input: crate::meter::UsageInput<'_>,
    ) -> DomainResult<UsageRecord> {
        if let Some(call) = deferred {
            return call
                .observed_for(input.endpoint.id)
                .ok_or_else(|| DomainError::Internal("Deferred known usage was not captured".into()));
        }
        Ok(self.meter.record(
            input.tenant,
            input.session_id,
            input.agent_id,
            input.endpoint,
            input.usage,
            input.cache_hit,
            input.mocked,
            input.latency_ms,
        ))
    }
}

impl AiGateway {
    pub(crate) fn deferred_provider(
        &self,
        endpoint: &ModelEndpoint,
    ) -> DomainResult<Arc<dyn crate::provider::ProviderAdapter>> {
        if self.endpoint_is_mock(endpoint) {
            return self.provider_for(endpoint);
        }
        let key = format!("atomic:{}", endpoint.id);
        let mut providers = self.providers.lock();
        if let Some(provider) = providers.get(&key) {
            return Ok(provider.clone());
        }
        let provider = crate::provider::single_dispatch(endpoint, self.credentials.as_ref())?;
        providers.insert(key, provider.clone());
        Ok(provider)
    }
}
