//! Pure owner reducers consume the original immutable bucket snapshot, never a later window.
use super::{codec, records::*, store};
use crate::{gateway_quota::settlement as gateway, runtime_quota::settlement as runtime};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, deterministic_id},
    quota::QuotaConsumption,
};
use serde_json::Value;

pub(super) struct Candidate {
    pub(super) fact: Fact,
    pub(super) gateway: Option<Value>,
    pub(super) runtime: Option<Value>,
}
pub(super) enum Decision {
    Unchanged,
    Write(Box<Candidate>),
}

pub(super) fn reduce(
    fact: &Fact,
    pending: &Pending,
    gateway: Option<Value>,
    runtime: Option<Value>,
    now: i64,
) -> DomainResult<Decision> {
    validate(fact, pending)?;
    let hash = codec::hash(&pending.outcome)?;
    if let Phase::Settled { outcome_hash, .. } = &fact.phase {
        return if *outcome_hash == hash {
            Ok(Decision::Unchanged)
        } else {
            Err(DomainError::Conflict("This attempt already has another immutable terminal outcome".into()))
        };
    }
    let mut next = fact.clone();
    let mut changed_gateway = None;
    let mut changed_runtime = None;
    if let Some(snapshot) = &mut next.charge {
        if snapshot.state == ChargeState::Actual {
            return Err(store::missing());
        }
        let (charged, consumption) = actual(snapshot, pending)?;
        let desired = runtime::charges(&snapshot.runtime, Some(&consumption));
        changed_gateway = Some(gateway::settle(
            gateway.ok_or_else(store::missing)?,
            &snapshot.gateway,
            snapshot.gateway_charged,
            charged,
            snapshot.state == ChargeState::Reserved,
            now,
        )?);
        changed_runtime = Some(runtime::settle(
            runtime.ok_or_else(store::missing)?,
            &snapshot.runtime,
            &snapshot.runtime_charged,
            &desired,
            snapshot.state == ChargeState::Reserved,
            now,
        )?);
        snapshot.gateway_charged = charged;
        snapshot.runtime_charged = desired;
        snapshot.state = if std::iter::once(pending.outcome.evidence)
            .chain(pending.outcome.components.iter().map(|row| row.evidence))
            .any(|evidence| matches!(evidence, Evidence::SentUsageUnknown | Evidence::SentUsagePartial))
        {
            ChargeState::Conservative
        } else {
            ChargeState::Actual
        };
    } else if pending.outcome.evidence != Evidence::NotSent || pending.outcome.rejection.is_none() {
        return Err(store::missing());
    }
    next.phase = Phase::Settled { outcome_hash: hash, audit_id: audit_id(fact) };
    Ok(Decision::Write(Box::new(Candidate { fact: next, gateway: changed_gateway, runtime: changed_runtime })))
}

pub(super) fn conservative(fact: &Fact, gateway: Value, runtime: Value, now: i64) -> DomainResult<Decision> {
    if fact.usage_id != usage_id(fact.origin.tenant, fact.attempt)
        || !valid_execution_window(fact.submitted_at, fact.execute_before)
    {
        return Err(store::missing());
    }
    let mut next = fact.clone();
    let snapshot = next.charge.as_mut().ok_or_else(store::missing)?;
    if snapshot.gateway.attempt != fact.attempt
        || snapshot.runtime.reservation != fact.attempt
        || snapshot.gateway.expires != snapshot.runtime.expires
        || snapshot.gateway.expires != snapshot.expires_at.unix_secs()
    {
        return Err(store::missing());
    }
    if snapshot.state != ChargeState::Reserved {
        return Ok(Decision::Unchanged);
    }
    if now < snapshot.expires_at.unix_secs() || !matches!(fact.phase, Phase::AwaitingSettlement) {
        return Err(store::missing());
    }
    let charged = gateway::Charged { tokens: snapshot.gateway.tokens, cost: snapshot.gateway.cost };
    let desired = runtime::charges(&snapshot.runtime, None);
    let gateway = gateway::settle(gateway, &snapshot.gateway, snapshot.gateway_charged, charged, true, now)?;
    let runtime = runtime::settle(runtime, &snapshot.runtime, &snapshot.runtime_charged, &desired, true, now)?;
    snapshot.gateway_charged = charged;
    snapshot.runtime_charged = desired;
    snapshot.state = ChargeState::Conservative;
    Ok(Decision::Write(Box::new(Candidate { fact: next, gateway: Some(gateway), runtime: Some(runtime) })))
}

pub(super) fn audit_id(fact: &Fact) -> Id {
    deterministic_id("agf.gateway-settlement.audit.v1", &format!("{}:{}", fact.origin.tenant, fact.attempt))
}
pub(super) fn validate(fact: &Fact, pending: &Pending) -> DomainResult<()> {
    if fact.attempt != pending.attempt
        || fact.origin != pending.origin
        || fact.usage_id != usage_id(fact.origin.tenant, fact.attempt)
        || !valid_execution_window(fact.submitted_at, fact.execute_before)
    {
        return Err(store::missing());
    }
    if let Some(charge) = &fact.charge {
        let admitted = charge.gateway.expires.checked_sub(900).ok_or_else(store::missing)?;
        if charge.gateway.attempt != fact.attempt
            || charge.runtime.reservation != fact.attempt
            || charge.expires_at.unix_secs() != charge.gateway.expires
            || charge.gateway.expires != charge.runtime.expires
            || charge.gateway.day != admitted / 86400
            || charge.gateway.hour != admitted / 3600
        {
            return Err(store::missing());
        }
    }
    super::components::validate(fact, pending)?;
    let outcome = &pending.outcome;
    if let Some(cache) = &outcome.semantic {
        if outcome.rejection.is_some() || !matches!(outcome.evidence, Evidence::SentUsageKnown | Evidence::LocalReply) {
            return Err(store::missing());
        }
        cache.validate(fact)?;
    }
    if let Some(row) = &outcome.usage {
        if row.id != fact.usage_id
            || row.tenant_id != fact.origin.tenant
            || row.endpoint_id.is_nil()
            || row.cache_hit != (outcome.evidence == Evidence::LocalReply)
            || ((row.cache_hit || row.mocked) && row.cost_micro != 0)
            || row.prompt_tokens.checked_add(row.completion_tokens).is_none()
            || !matches!(outcome.evidence, Evidence::LocalReply | Evidence::SentUsageKnown | Evidence::SentUsagePartial)
        {
            return Err(store::missing());
        }
        let snapshot = fact.charge.as_ref().ok_or_else(store::missing)?;
        if row.endpoint_id != snapshot.endpoint || row.session_id != snapshot.session {
            return Err(store::missing());
        }
        if row.agent_id.map_or_else(|| "unassigned".into(), |id| id.to_string()) != snapshot.gateway.agent {
            return Err(store::missing());
        }
    } else if matches!(outcome.evidence, Evidence::LocalReply | Evidence::SentUsageKnown | Evidence::SentUsagePartial) {
        return Err(store::missing());
    }
    if let Some(rejection) = &outcome.rejection {
        if rejection.rule_ids.len() > 32
            || rejection.rule_ids.iter().any(|id| !super::rejection::safe_rule_id(id))
            || (rejection.reason == Reason::Permission
                && super::components::dispatch_evidence(outcome.evidence, &outcome.components) != Evidence::NotSent)
        {
            return Err(store::missing());
        }
    }
    Ok(())
}
fn actual(snapshot: &ChargeSnapshot, pending: &Pending) -> DomainResult<(gateway::Charged, QuotaConsumption)> {
    let outcome = &pending.outcome;
    let mut charged = if snapshot.chats.is_empty() {
        match outcome.evidence {
            Evidence::NotSent => gateway::Charged::default(),
            Evidence::LocalReply | Evidence::SentUsageKnown => {
                let usage = outcome.usage.as_ref().ok_or_else(store::missing)?;
                gateway::Charged {
                    tokens: usage.prompt_tokens.checked_add(usage.completion_tokens).ok_or_else(store::missing)?,
                    cost: usage.cost_micro,
                }
            }
            Evidence::SentUsageUnknown => gateway::Charged {
                tokens: snapshot
                    .gateway
                    .tokens
                    .checked_sub(snapshot.embedding.as_ref().map_or(0, |row| row.tokens))
                    .ok_or_else(store::missing)?,
                cost: snapshot
                    .gateway
                    .cost
                    .checked_sub(snapshot.embedding.as_ref().map_or(0, |row| row.cost))
                    .ok_or_else(store::missing)?,
            },
            Evidence::SentUsagePartial => return Err(store::missing()),
        }
    } else {
        super::chat_components::charges(snapshot, pending)?
    };
    if let Some(anchor) = &snapshot.embedding {
        let component =
            outcome.components.iter().find(|row| row.usage_id == anchor.usage_id).ok_or_else(store::missing)?;
        let (tokens, cost) = match component.evidence {
            Evidence::NotSent => (0, 0),
            Evidence::SentUsageKnown => {
                let usage = component.usage.as_ref().ok_or_else(store::missing)?;
                (usage.prompt_tokens, usage.cost_micro)
            }
            Evidence::SentUsageUnknown => (anchor.tokens, anchor.cost),
            Evidence::LocalReply | Evidence::SentUsagePartial => return Err(store::missing()),
        };
        charged.tokens = charged.tokens.checked_add(tokens).ok_or_else(store::missing)?;
        charged.cost = charged.cost.checked_add(cost).ok_or_else(store::missing)?;
    }
    Ok((
        charged,
        QuotaConsumption {
            tokens: i64::try_from(charged.tokens).map_err(|_| store::missing())?,
            cost_micro: i64::try_from(charged.cost).map_err(|_| store::missing())?,
            requests: i64::from(
                outcome.evidence != Evidence::NotSent
                    || outcome.components.iter().any(|row| row.evidence != Evidence::NotSent),
            ),
            concurrency: 0,
        },
    ))
}
