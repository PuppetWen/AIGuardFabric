//! Quota-owner pure candidates. Private legacy ledger models stay owned by this module.
use super::*;
use agf_core::error::{DomainError, DomainResult};
use serde_json::Value;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Anchor {
    pub attempt: Id,
    pub day: i64,
    pub hour: i64,
    pub expires: i64,
    pub tokens: u64,
    pub cost: u64,
    pub agent: String,
    pub route: String,
}

pub(crate) struct Plan {
    pub tokens: u64,
    pub cost: u64,
    pub endpoint: Id,
    pub agent: Option<Id>,
    pub route: String,
    pub route_budget: u64,
    pub max_total: u64,
}

#[derive(Clone, Copy, Default, Serialize, Deserialize)]
pub(crate) struct Charged {
    pub tokens: u64,
    pub cost: u64,
}

pub(crate) fn reserve(
    original: Option<Value>,
    limits: &Limits,
    plan: &Plan,
    attempt: Id,
    now: i64,
) -> DomainResult<(Value, Anchor)> {
    if attempt.is_nil() || plan.route.len() > 64 {
        return Err(invalid());
    }
    let mut ledger: Ledger = original.map(serde_json::from_value).transpose()?.unwrap_or_default();
    ledger.roll(now);
    if ledger.reservations.contains_key(&attempt.to_string()) {
        return Err(DomainError::Conflict("Attempt was already reserved".into()));
    }
    if ledger.reservations.len() >= 512 {
        return Err(DomainError::PreconditionFailed("Gateway reservation capacity reached".into()));
    }
    let agent = plan.agent.map_or_else(|| "unassigned".into(), |id| id.to_string());
    let day = now / 86400;
    let hour = now / 3600;
    let pending = ledger
        .reservations
        .values()
        .filter(|row| row.atomic_day.is_none_or(|value| value == day))
        .try_fold(0_u64, |sum, row| sum.checked_add(row.tokens).ok_or_else(invalid))?;
    let pending_agent = ledger
        .reservations
        .values()
        .filter(|row| row.agent == agent && row.atomic_hour.is_none_or(|value| value == hour))
        .try_fold(0_u64, |sum, row| sum.checked_add(row.tokens).ok_or_else(invalid))?;
    let pending_cost = ledger
        .reservations
        .values()
        .filter(|row| row.route == plan.route && row.atomic_day.is_none_or(|value| value == day))
        .try_fold(0_u64, |sum, row| sum.checked_add(row.cost).ok_or_else(invalid))?;
    let all_cost = ledger
        .reservations
        .values()
        .filter(|row| row.atomic_day.is_none_or(|value| value == day))
        .try_fold(0_u64, |sum, row| sum.checked_add(row.cost).ok_or_else(invalid))?;
    ensure("session-turn-tokens", 0, plan.tokens, limits.session_tokens_per_turn)?;
    ensure(
        "tenant-day-tokens",
        ledger.totals.tokens.checked_add(pending).ok_or_else(invalid)?,
        plan.tokens,
        limits.tenant_tokens_per_day,
    )?;
    ensure(
        "agent-hour-tokens",
        ledger.agents.get(&agent).copied().unwrap_or(0).checked_add(pending_agent).ok_or_else(invalid)?,
        plan.tokens,
        limits.agent_tokens_per_hour,
    )?;
    ensure(
        "concurrent-sessions",
        u64::try_from(ledger.reservations.len()).map_err(|_| invalid())?,
        1,
        limits.max_concurrent_sessions,
    )?;
    ensure(
        "route-day-budget",
        ledger.routes.get(&plan.route).copied().unwrap_or(0).checked_add(pending_cost).ok_or_else(invalid)?,
        plan.cost,
        plan.route_budget,
    )?;
    ensure(
        "tenant-cumulative-budget",
        ledger.totals.cost.checked_add(all_cost).ok_or_else(invalid)?,
        plan.cost,
        plan.max_total,
    )?;
    let anchor = Anchor {
        attempt,
        day,
        hour,
        expires: now.checked_add(LEASE_SECS).ok_or_else(invalid)?,
        tokens: plan.tokens,
        cost: plan.cost,
        agent: agent.clone(),
        route: plan.route.clone(),
    };
    ledger.reservations.insert(
        attempt.to_string(),
        Reservation {
            expires: now.checked_add(LEASE_SECS).ok_or_else(invalid)?,
            tokens: plan.tokens,
            cost: plan.cost,
            agent,
            route: plan.route.clone(),
            atomic_day: Some(day),
            atomic_hour: Some(hour),
        },
    );
    Ok((serde_json::to_value(ledger)?, anchor))
}

/// Adjust only the exact original current bucket. An expired bucket's per-attempt correction
/// is authoritative in the encrypted Anchor; this never returns credits to a newer bucket.
pub(crate) fn settle(
    original: Value,
    anchor: &Anchor,
    previous: Charged,
    actual: Charged,
    reserved: bool,
    now: i64,
) -> DomainResult<Value> {
    let mut ledger: Ledger = serde_json::from_value(original)?;
    ledger.roll(now);
    let row = ledger.reservations.get(&anchor.attempt.to_string());
    if reserved {
        let row = row.ok_or_else(invalid)?;
        if (row.tokens, row.cost, row.agent.as_str(), row.route.as_str(), row.atomic_day, row.atomic_hour, row.expires)
            != (
                anchor.tokens,
                anchor.cost,
                anchor.agent.as_str(),
                anchor.route.as_str(),
                Some(anchor.day),
                Some(anchor.hour),
                anchor.expires,
            )
        {
            return Err(invalid());
        }
    } else if row.is_some() {
        return Err(invalid());
    }
    if ledger.day == anchor.day {
        ledger.totals.tokens = adjust(ledger.totals.tokens, previous.tokens, actual.tokens)?;
        ledger.totals.cost = adjust(ledger.totals.cost, previous.cost, actual.cost)?;
        let route = ledger.routes.entry(anchor.route.clone()).or_default();
        *route = adjust(*route, previous.cost, actual.cost)?;
    }
    if ledger.hour == anchor.hour {
        let agent = ledger.agents.entry(anchor.agent.clone()).or_default();
        *agent = adjust(*agent, previous.tokens, actual.tokens)?;
    }
    ledger.reservations.remove(&anchor.attempt.to_string());
    Ok(serde_json::to_value(ledger)?)
}

fn adjust(value: u64, previous: u64, actual: u64) -> DomainResult<u64> {
    value.checked_sub(previous).and_then(|value| value.checked_add(actual)).ok_or_else(invalid)
}
fn invalid() -> DomainError {
    DomainError::PreconditionFailed("Gateway atomic quota anchor is inconsistent or exceeds exact bounds".into())
}
