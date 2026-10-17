//! Pure deferred usage creation and committed-only idempotent memory projection.
use super::*;

pub struct UsageInput<'a> {
    pub id: Id,
    pub tenant: TenantId,
    pub session_id: &'a str,
    pub agent_id: Option<Id>,
    pub endpoint: &'a ModelEndpoint,
    pub usage: Usage,
    pub cache_hit: bool,
    pub mocked: bool,
    pub latency_ms: u64,
}

impl std::fmt::Debug for UsageInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsageInput")
            .field("id", &self.id)
            .field("tenant", &self.tenant)
            .field("cache_hit", &self.cache_hit)
            .field("mocked", &self.mocked)
            .finish_non_exhaustive()
    }
}

impl Meter {
    /// Build a stable server-owned row without touching totals, recent rows or counters.
    /// # Errors
    /// A nil usage identity cannot anchor an atomic settlement.
    pub fn record_deferred(input: UsageInput<'_>) -> DomainResult<UsageRecord> {
        if input.id.is_nil() || input.tenant.as_uuid().is_nil() || input.endpoint.tenant_id != input.tenant {
            return Err(DomainError::Validation("Deferred usage requires a non-nil same-tenant identity".into()));
        }
        Ok(Self::construct_record(input))
    }

    pub(super) fn construct_record(input: UsageInput<'_>) -> UsageRecord {
        let UsageInput { tenant, session_id, agent_id, endpoint, usage, cache_hit, mocked, latency_ms, id } = input;
        let cost = if cache_hit || mocked { CostBreakdown::default() } else { breakdown(endpoint, &usage) };
        UsageRecord {
            id,
            tenant_id: tenant,
            session_id: session_id.to_string(),
            agent_id,
            endpoint_id: endpoint.id,
            provider: endpoint.provider,
            model: endpoint.model.clone(),
            prompt_tokens: usage.prompt_tokens,
            completion_tokens: usage.completion_tokens,
            cached_tokens: usage.cached_tokens,
            cache_write_tokens: usage.cache_write_tokens,
            cache_write_1h_tokens: usage.cache_write_1h_tokens,
            cache_hit,
            cost_micro: cost.total_micro,
            mocked,
            latency_ms,
            at: Timestamp::now(),
        }
    }

    /// Only call after authoritative publication, or when hydrating durable committed rows.
    /// # Errors
    /// Reusing a committed usage UUID with another body is rejected without changing totals.
    pub fn absorb_once(&self, record: &UsageRecord) -> DomainResult<bool> {
        if record.id.is_nil() || record.tenant_id.as_uuid().is_nil() {
            return Err(DomainError::Validation("Committed usage identity is invalid".into()));
        }
        let digest = agf_core::secret::content_hash(&serde_json::to_string(record)?);
        let key = (record.tenant_id, record.id);
        let mut guard = self.inner.lock();
        if let Some(existing) = guard.seen.get(&key) {
            if existing != &digest {
                return Err(DomainError::Conflict("Meter usage identity has a different immutable body".into()));
            }
            return Ok(false);
        }
        // API atomic settlement uses durable revision checkpoints instead of this map.
        // Legacy opt-in callers get an explicit refusal; no old UUID is evicted/recharged.
        if guard.seen.len() >= 65_536 {
            guard.committed_projection_incomplete = true;
            return Err(DomainError::PreconditionFailed(
                "Legacy committed Meter UUID capacity reached; use durable checkpoints".into(),
            ));
        }
        guard.seen.insert(key, digest);
        let one = MeterTotals {
            calls: 1,
            cache_hits: u64::from(record.cache_hit),
            mocked_calls: u64::from(record.mocked),
            prompt_tokens: record.prompt_tokens,
            completion_tokens: record.completion_tokens,
            cached_tokens: record.cached_tokens,
            cache_write_tokens: record.cache_write_tokens,
            cache_write_1h_tokens: record.cache_write_1h_tokens,
            cost_micro: record.cost_micro,
            latency_ms: record.latency_ms,
        };
        guard.total.accumulate(&one);
        let tenant_key = record.tenant_id.to_string();
        guard.by_tenant.entry(tenant_key).or_default().accumulate(&one);
        if let Some(agent) = record.agent_id {
            guard.by_agent.entry(agent.to_string()).or_default().accumulate(&one);
        }
        guard.by_session.entry(record.session_id.clone()).or_default().accumulate(&one);
        guard.by_provider.entry(record.provider.as_str().to_string()).or_default().accumulate(&one);
        guard.by_model.entry(record.model.clone()).or_default().accumulate(&one);

        guard.recent.push(record.clone());
        if guard.recent.len() > Self::MAX_RECENT {
            let overflow = guard.recent.len() - Self::MAX_RECENT;
            guard.recent.drain(..overflow);
        }
        Ok(true)
    }
}
