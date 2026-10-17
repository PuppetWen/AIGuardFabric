//! Original ordered chat anchors and conservative partial/unknown settlement; no endpoint secrets.
use super::{components::ComponentOutcome, records::*, store};
use crate::gateway_quota::settlement::{Charged, Plan};
use agf_aigw::{
    AiGateway,
    gateway::{CallContext, DeferredCall, DeferredComponentAnchor, DeferredEvidence},
    wire::ChatRequest,
};
use agf_core::{
    enums::LlmProvider,
    error::DomainResult,
    ids::{Id, TenantId, deterministic_id},
    model::{ModelPricing, UsageRecord},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct ChatAnchor {
    pub(super) usage_id: Id,
    pub(super) endpoint: Id,
    pub(super) provider: LlmProvider,
    pub(super) model: String,
    pub(super) pricing: ModelPricing,
    pub(super) mocked: bool,
    pub(super) tokens: u64,
    pub(super) cost: u64,
}

pub(super) fn usage_id(tenant: TenantId, attempt: Id, ordinal: usize) -> Id {
    if ordinal == 0 {
        super::records::usage_id(tenant, attempt)
    } else {
        deterministic_id("agf.gateway-fallback-usage.atomic.v1", &format!("{tenant}:{attempt}:{ordinal}"))
    }
}

pub(super) fn capture(
    attempt: &AuthenticatedAttempt,
    context: &CallContext,
    gateway: &AiGateway,
    request: &ChatRequest,
    route: Option<&crate::store::ModelRoutePolicy>,
) -> DomainResult<(Plan, Vec<ChatAnchor>)> {
    // Select exactly once: round-robin is not restarted after the reservation transaction.
    let chain = gateway.router().select(&context.routing_context(request))?;
    if chain.is_empty() || chain.len() > agf_aigw::gateway::MAX_CHAT_COMPONENTS {
        return Err(store::missing());
    }
    let prompt = request.estimate_prompt_tokens();
    let completion = u64::from(request.max_tokens.unwrap_or(1024));
    let tokens = prompt.checked_add(completion).ok_or_else(store::missing)?;
    let anchors = chain
        .iter()
        .enumerate()
        .map(|(ordinal, endpoint)| {
            let mocked = gateway.endpoint_is_mock(endpoint);
            // Reserve the highest configured input tariff, including Anthropic's 1h cache write.
            let input_rate = endpoint.pricing.prompt_micro_per_1k.max(endpoint.pricing.cached_prompt_micro_per_1k);
            let input_rate = if endpoint.provider == LlmProvider::Anthropic {
                input_rate.checked_mul(2).ok_or_else(store::missing)?
            } else {
                input_rate
            };
            let cost = if mocked {
                0
            } else {
                let value = (u128::from(prompt) * u128::from(input_rate))
                    .div_ceil(1000)
                    .checked_add(
                        (u128::from(completion) * u128::from(endpoint.pricing.completion_micro_per_1k)).div_ceil(1000),
                    )
                    .ok_or_else(store::missing)?;
                u64::try_from(value).map_err(|_| store::missing())?
            };
            Ok(ChatAnchor {
                usage_id: usage_id(attempt.origin.tenant, attempt.id, ordinal),
                endpoint: endpoint.id,
                provider: endpoint.provider,
                model: endpoint.model.clone(),
                pricing: endpoint.pricing,
                mocked,
                tokens,
                cost,
            })
        })
        .collect::<DomainResult<Vec<_>>>()?;
    let budget = route.map_or(0.0, |row| row.budget_cny_per_day);
    if !budget.is_finite() || !(0.0..=1_000_000.0).contains(&budget) {
        return Err(store::missing());
    }
    let plan = Plan {
        endpoint: anchors[0].endpoint,
        tokens: anchors.iter().try_fold(0_u64, |sum, row| sum.checked_add(row.tokens).ok_or_else(store::missing))?,
        cost: anchors.iter().try_fold(0_u64, |sum, row| sum.checked_add(row.cost).ok_or_else(store::missing))?,
        agent: context.agent_id,
        route: route.map_or_else(String::new, |row| row.id.to_string()),
        route_budget: (budget * 1_000_000.0).round().to_string().parse().map_err(|_| store::missing())?,
        max_total: context.budget.max_total_micro,
    };
    Ok((plan, anchors))
}

pub(super) fn deferred_anchors(fact: &Fact) -> DomainResult<Vec<DeferredComponentAnchor>> {
    let charge = fact.charge.as_ref().ok_or_else(store::missing)?;
    if charge.chats.is_empty() {
        return Ok(vec![DeferredComponentAnchor { usage_id: fact.usage_id, endpoint_id: charge.endpoint }]);
    }
    Ok(charge
        .chats
        .iter()
        .map(|row| DeferredComponentAnchor { usage_id: row.usage_id, endpoint_id: row.endpoint })
        .collect())
}

pub(super) fn snapshot(call: &DeferredCall) -> DomainResult<Vec<ComponentOutcome>> {
    call.component_outcomes()
        .into_iter()
        .map(|row| {
            Ok(ComponentOutcome {
                usage_id: row.anchor.usage_id,
                evidence: match row.evidence {
                    DeferredEvidence::NotSent => Evidence::NotSent,
                    DeferredEvidence::LocalReply => Evidence::LocalReply,
                    DeferredEvidence::SentUsageKnown => Evidence::SentUsageKnown,
                    DeferredEvidence::SentUsagePartial => Evidence::SentUsagePartial,
                    DeferredEvidence::SentUsageUnknown => Evidence::SentUsageUnknown,
                },
                usage: row.usage,
            })
        })
        .collect()
}

pub(super) fn validate(fact: &Fact, pending: &Pending) -> DomainResult<()> {
    let Some(charge) = &fact.charge else { return Ok(()) };
    if charge.chats.is_empty() {
        return Ok(());
    }
    if charge.chats.len() > 8 || charge.chats[0].endpoint != charge.endpoint {
        return Err(store::missing());
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut endpoints = std::collections::BTreeSet::new();
    let mut reserved = Charged::default();
    for (ordinal, anchor) in charge.chats.iter().enumerate() {
        if anchor.usage_id != usage_id(fact.origin.tenant, fact.attempt, ordinal)
            || !ids.insert(anchor.usage_id)
            || anchor.endpoint.is_nil()
            || !endpoints.insert(anchor.endpoint)
            || anchor.model.len() > 256
            || anchor.tokens == 0
            || anchor.mocked && anchor.cost != 0
        {
            return Err(store::missing());
        }
        reserved.tokens = reserved.tokens.checked_add(anchor.tokens).ok_or_else(store::missing)?;
        reserved.cost = reserved.cost.checked_add(anchor.cost).ok_or_else(store::missing)?;
        let (evidence, row) = outcome(pending, anchor, ordinal)?;
        validate_usage(fact, charge, anchor, evidence, row)?;
    }
    reserved.tokens = reserved
        .tokens
        .checked_add(charge.embedding.as_ref().map_or(0, |row| row.tokens))
        .ok_or_else(store::missing)?;
    reserved.cost =
        reserved.cost.checked_add(charge.embedding.as_ref().map_or(0, |row| row.cost)).ok_or_else(store::missing)?;
    if (reserved.tokens, reserved.cost) != (charge.gateway.tokens, charge.gateway.cost)
        || pending.outcome.components.len() != charge.chats.len() - 1 + usize::from(charge.embedding.is_some())
    {
        return Err(store::missing());
    }
    let allowed: std::collections::BTreeSet<_> = charge
        .chats
        .iter()
        .skip(1)
        .map(|row| row.usage_id)
        .chain(charge.embedding.iter().map(|row| row.usage_id))
        .collect();
    let actual: std::collections::BTreeSet<_> = pending.outcome.components.iter().map(|row| row.usage_id).collect();
    if allowed != actual {
        return Err(store::missing());
    }
    Ok(())
}

fn outcome<'a>(
    pending: &'a Pending,
    anchor: &ChatAnchor,
    ordinal: usize,
) -> DomainResult<(Evidence, Option<&'a UsageRecord>)> {
    if ordinal == 0 {
        return Ok((pending.outcome.evidence, pending.outcome.usage.as_ref()));
    }
    let row =
        pending.outcome.components.iter().find(|row| row.usage_id == anchor.usage_id).ok_or_else(store::missing)?;
    Ok((row.evidence, row.usage.as_ref()))
}

fn validate_usage(
    fact: &Fact,
    charge: &ChargeSnapshot,
    anchor: &ChatAnchor,
    evidence: Evidence,
    usage: Option<&UsageRecord>,
) -> DomainResult<()> {
    let Some(row) = usage else {
        return if matches!(evidence, Evidence::NotSent | Evidence::SentUsageUnknown) {
            Ok(())
        } else {
            Err(store::missing())
        };
    };
    if !matches!(evidence, Evidence::LocalReply | Evidence::SentUsageKnown | Evidence::SentUsagePartial)
        || row.id != anchor.usage_id
        || row.tenant_id != fact.origin.tenant
        || row.endpoint_id != anchor.endpoint
        || row.provider != anchor.provider
        || row.model != anchor.model
        || row.session_id != charge.session
        || row.agent_id.map_or_else(|| "unassigned".into(), |id| id.to_string()) != charge.gateway.agent
        || row.mocked != anchor.mocked && !row.cache_hit
        || row.cache_hit != (evidence == Evidence::LocalReply)
        || (row.cache_hit || row.mocked) && row.cost_micro != 0
        || row.prompt_tokens.checked_add(row.completion_tokens).is_none()
    {
        return Err(store::missing());
    }
    if !row.cache_hit && !row.mocked && usage_cost(anchor, row)? != row.cost_micro {
        return Err(store::missing());
    }
    Ok(())
}

pub(super) fn charges(snapshot: &ChargeSnapshot, pending: &Pending) -> DomainResult<Charged> {
    snapshot.chats.iter().enumerate().try_fold(Charged::default(), |sum, (ordinal, anchor)| {
        let (evidence, usage) = outcome(pending, anchor, ordinal)?;
        let actual = usage
            .map(|row| {
                Ok::<_, agf_core::error::DomainError>((
                    row.prompt_tokens.checked_add(row.completion_tokens).ok_or_else(store::missing)?,
                    row.cost_micro,
                ))
            })
            .transpose()?
            .unwrap_or((0, 0));
        let value = match evidence {
            Evidence::NotSent => (0, 0),
            Evidence::LocalReply | Evidence::SentUsageKnown => actual,
            Evidence::SentUsagePartial => (anchor.tokens.max(actual.0), anchor.cost.max(actual.1)),
            Evidence::SentUsageUnknown => (anchor.tokens, anchor.cost),
        };
        Ok(Charged {
            tokens: sum.tokens.checked_add(value.0).ok_or_else(store::missing)?,
            cost: sum.cost.checked_add(value.1).ok_or_else(store::missing)?,
        })
    })
}

fn usage_cost(anchor: &ChatAnchor, row: &UsageRecord) -> DomainResult<u64> {
    let cached = row.cached_tokens.min(row.prompt_tokens);
    let writes = row.cache_write_tokens.min(row.prompt_tokens - cached);
    let hour = row.cache_write_1h_tokens.min(writes);
    let normal = row.prompt_tokens - cached - writes;
    let prompt = u128::from(anchor.pricing.prompt_micro_per_1k);
    let cached_rate = if anchor.pricing.cached_prompt_micro_per_1k == 0 {
        prompt
    } else {
        u128::from(anchor.pricing.cached_prompt_micro_per_1k)
    };
    let writes = if anchor.provider == LlmProvider::Anthropic {
        let short =
            prompt.checked_mul(u128::from(writes - hour)).and_then(|v| v.checked_mul(5)).ok_or_else(store::missing)?
                / 4000;
        let long =
            prompt.checked_mul(u128::from(hour)).and_then(|v| v.checked_mul(2)).ok_or_else(store::missing)? / 1000;
        short.checked_add(long).ok_or_else(store::missing)?
    } else {
        prompt * u128::from(writes) / 1000
    };
    let value = (prompt * u128::from(normal) / 1000)
        .checked_add(cached_rate * u128::from(cached) / 1000)
        .and_then(|v| v.checked_add(writes))
        .and_then(|v| {
            v.checked_add(u128::from(anchor.pricing.completion_micro_per_1k) * u128::from(row.completion_tokens) / 1000)
        })
        .ok_or_else(store::missing)?;
    u64::try_from(value).map_err(|_| store::missing())
}
