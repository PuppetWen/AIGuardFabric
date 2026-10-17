//! An embedding is a separately paid, immutable component of one logical model request.
use super::{records::*, store};
use agf_aigw::provider::embedding::{EmbeddingAttempt, EmbeddingDispatch};
use agf_core::{
    enums::LlmProvider,
    error::DomainResult,
    ids::{Id, deterministic_id},
    model::UsageRecord,
    time::Timestamp,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct EmbeddingAnchor {
    pub(super) usage_id: Id,
    pub(super) endpoint: Id,
    pub(super) version: u64,
    pub(super) provider: LlmProvider,
    pub(super) model: String,
    pub(super) model_revision: String,
    pub(super) tokens: u64,
    pub(super) cost: u64,
    pub(super) price_per_1k: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct ComponentOutcome {
    pub(super) usage_id: Id,
    pub(super) evidence: Evidence,
    pub(super) usage: Option<UsageRecord>,
}

pub(super) fn embedding_id(tenant: agf_core::ids::TenantId, attempt: Id) -> Id {
    deterministic_id("agf.gateway-embedding-usage.atomic.v1", &format!("{tenant}:{attempt}"))
}

/// Internal service spelling differs from the enum's persisted serde spelling.
/// Accept only the exact service-owned canonical value; never normalize an untrusted alias.
pub(super) fn service_provider(value: &str) -> DomainResult<LlmProvider> {
    let provider = LlmProvider::parse(value).map_err(|_| store::missing())?;
    if provider.as_str() != value {
        return Err(store::missing());
    }
    Ok(provider)
}

impl EmbeddingAnchor {
    pub(super) fn capture(
        attempt: &AuthenticatedAttempt,
        live: &crate::gateway_semantic_profile::LiveEmbedding,
    ) -> DomainResult<Self> {
        let c = &live.configuration;
        if c.tenant_id != attempt.origin.tenant || c.endpoint_id.is_nil() || c.configuration_version == 0 {
            return Err(store::missing());
        }
        let cost = price(live.input_tokens_bound, c.input_micro_per_1k)?;
        if cost != live.estimated_cost_micro || live.input_tokens_bound == 0 {
            return Err(store::missing());
        }
        Ok(Self {
            usage_id: embedding_id(attempt.origin.tenant, attempt.id),
            endpoint: c.endpoint_id,
            version: c.configuration_version,
            provider: service_provider(&c.provider)?,
            model: c.model.clone(),
            model_revision: c.model_revision.clone(),
            tokens: live.input_tokens_bound,
            cost,
            price_per_1k: c.input_micro_per_1k,
        })
    }

    pub(super) fn not_sent(&self) -> ComponentOutcome {
        ComponentOutcome { usage_id: self.usage_id, evidence: Evidence::NotSent, usage: None }
    }

    // Called immediately after D returns, before any further await. Vector failure cannot erase usage.
    pub(super) fn known(
        &self,
        fact: &Fact,
        attempt: &EmbeddingAttempt,
        latency_ms: u64,
    ) -> DomainResult<ComponentOutcome> {
        if attempt.tenant_id != fact.origin.tenant
            || attempt.endpoint_id != self.endpoint
            || attempt.configuration_version != self.version
            || attempt.model != self.model
            || attempt.model_revision != self.model_revision
            || attempt.reservation.reserved_tokens != self.tokens
            || attempt.reservation.reserved_cost_micro != self.cost
            || service_provider(&attempt.provider)? != self.provider
        {
            return Err(store::missing());
        }
        let Some(usage) = attempt.usage else {
            return Ok(ComponentOutcome {
                usage_id: self.usage_id,
                evidence: if attempt.dispatch == EmbeddingDispatch::NotSent {
                    Evidence::NotSent
                } else {
                    Evidence::SentUsageUnknown
                },
                usage: None,
            });
        };
        let cost = price(usage.total_tokens, self.price_per_1k)?;
        if attempt.dispatch == EmbeddingDispatch::NotSent
            || usage.prompt_tokens == 0
            || usage.prompt_tokens != usage.total_tokens
            || attempt.configured_cost_micro != Some(cost)
        {
            return Err(store::missing());
        }
        let charge = fact.charge.as_ref().ok_or_else(store::missing)?;
        Ok(ComponentOutcome {
            usage_id: self.usage_id,
            evidence: Evidence::SentUsageKnown,
            usage: Some(UsageRecord {
                id: self.usage_id,
                tenant_id: fact.origin.tenant,
                agent_id: if charge.gateway.agent == "unassigned" {
                    None
                } else {
                    Some(Id::parse(&charge.gateway.agent)?)
                },
                session_id: charge.session.clone(),
                endpoint_id: self.endpoint,
                provider: self.provider,
                model: self.model.clone(),
                prompt_tokens: usage.prompt_tokens,
                completion_tokens: 0,
                cached_tokens: 0,
                cache_write_tokens: 0,
                cache_write_1h_tokens: 0,
                cache_hit: false,
                cost_micro: cost,
                mocked: false,
                latency_ms,
                at: Timestamp::now(),
            }),
        })
    }
}

pub(super) fn validate(fact: &Fact, pending: &Pending) -> DomainResult<()> {
    super::chat_components::validate(fact, pending)?;
    let anchor = fact.charge.as_ref().and_then(|charge| charge.embedding.as_ref());
    let components = &pending.outcome.components;
    let Some(anchor) = anchor else {
        return if fact.charge.as_ref().is_some_and(|charge| !charge.chats.is_empty()) || components.is_empty() {
            Ok(())
        } else {
            Err(store::missing())
        };
    };
    if fact.charge.as_ref().is_none_or(|charge| charge.chats.is_empty()) && components.len() != 1 {
        return Err(store::missing());
    }
    let component = components.iter().find(|row| row.usage_id == anchor.usage_id).ok_or_else(store::missing)?;
    let charge = fact.charge.as_ref().ok_or_else(store::missing)?;
    if anchor.usage_id != embedding_id(fact.origin.tenant, fact.attempt)
        || anchor.usage_id == fact.usage_id
        || component.usage_id != anchor.usage_id
        || anchor.tokens > charge.gateway.tokens
        || anchor.cost > charge.gateway.cost
        || price(anchor.tokens, anchor.price_per_1k)? != anchor.cost
        || matches!(component.evidence, Evidence::LocalReply | Evidence::SentUsagePartial)
    {
        return Err(store::missing());
    }
    if let Some(row) = &component.usage {
        if component.evidence != Evidence::SentUsageKnown
            || row.id != anchor.usage_id
            || row.tenant_id != fact.origin.tenant
            || row.endpoint_id != anchor.endpoint
            || row.provider != anchor.provider
            || row.model != anchor.model
            || row.session_id != charge.session
            || row.agent_id.map_or_else(|| "unassigned".into(), |id| id.to_string()) != charge.gateway.agent
            || row.cache_hit
            || row.mocked
            || row.completion_tokens != 0
            || row.prompt_tokens == 0
            || row.cached_tokens != 0
            || row.cache_write_tokens != 0
            || row.cache_write_1h_tokens != 0
            || price(row.prompt_tokens, anchor.price_per_1k)? != row.cost_micro
        {
            return Err(store::missing());
        }
    } else if component.evidence == Evidence::SentUsageKnown {
        return Err(store::missing());
    }
    Ok(())
}

pub(super) fn usage_rows(outcome: &KnownOutcome) -> impl Iterator<Item = &UsageRecord> {
    outcome.usage.iter().chain(outcome.components.iter().filter_map(|component| component.usage.as_ref()))
}

pub(super) fn price(tokens: u64, per_1k: u64) -> DomainResult<u64> {
    u64::try_from((u128::from(tokens) * u128::from(per_1k)).div_ceil(1000)).map_err(|_| store::missing())
}

/// Classification spans every consumed component; the main chat evidence stays independent.
pub(super) fn dispatch_evidence(chat: Evidence, components: &[ComponentOutcome]) -> Evidence {
    if chat != Evidence::NotSent {
        return chat;
    }
    components
        .iter()
        .find_map(|component| match component.evidence {
            Evidence::SentUsageKnown | Evidence::SentUsagePartial | Evidence::SentUsageUnknown => {
                Some(component.evidence)
            }
            Evidence::NotSent | Evidence::LocalReply => None,
        })
        .unwrap_or(Evidence::NotSent)
}
