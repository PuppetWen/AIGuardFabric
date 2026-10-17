//! Owner-only pure reservation and original charge snapshots; legacy MCP semantics stay intact.
use super::*;
use serde_json::Value;

pub(crate) const OWNER: &str = "gateway-atomic-v1";

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct ChargeAnchor {
    pub key: String,
    pub quota: Id,
    pub dimension: QuotaDimension,
    pub amount: i64,
    pub expires: Option<i64>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Anchor {
    pub reservation: Id,
    pub expires: i64,
    pub charges: Vec<ChargeAnchor>,
}

pub(crate) struct Reserve<'a> {
    pub tenant: TenantId,
    pub agent: Option<Id>,
    pub session: &'a str,
    pub reservation: Id,
    pub now: Timestamp,
    pub estimated: &'a QuotaConsumption,
    pub quotas: &'a [Quota],
}

pub(crate) fn reserve(original: Option<Value>, input: &Reserve<'_>) -> DomainResult<(Value, Anchor)> {
    if input.reservation.is_nil() || input.session.len() > 256 || input.quotas.len() > 100 {
        return Err(invalid());
    }
    let mut ledger: Ledger = original.map(serde_json::from_value).transpose()?.unwrap_or_default();
    ledger.roll(input.now.unix_secs());
    if ledger.reservations.contains_key(&input.reservation) {
        return Err(DomainError::Conflict("Attempt already has a runtime reservation".into()));
    }
    if ledger.reservations.len() >= 10000 {
        return Err(invalid());
    }
    let mut anchors = Vec::new();
    let mut charges = Vec::new();
    for quota in input.quotas.iter().filter(|quota| quota.enabled && quota.limit > 0) {
        if quota.tenant_id != input.tenant || quota.id.is_nil() {
            return Err(invalid());
        }
        let Some(key) = counter_key(quota, input.agent, input.session, input.now) else { continue };
        if anchors.iter().any(|anchor: &ChargeAnchor| anchor.key == key) {
            return Err(invalid());
        }
        let amount = input.estimated.value(quota.dimension);
        if amount < 0 {
            return Err(invalid());
        }
        let expires = if quota.dimension == QuotaDimension::Concurrency {
            None
        } else {
            quota
                .window
                .seconds()
                .map(|seconds| {
                    input
                        .now
                        .unix_secs()
                        .checked_add(seconds)
                        .and_then(|at| at.checked_add(LEASE_SECS))
                        .ok_or_else(invalid)
                })
                .transpose()?
        };
        let counter =
            ledger.counters.entry(key.clone()).or_insert_with(|| Counter { quota: Some(quota.id), used: 0, expires });
        if counter.quota != Some(quota.id) {
            return Err(invalid());
        }
        let next = counter.used.checked_add(amount).ok_or_else(invalid)?;
        if next > quota.limit
            && !matches!(quota.on_exceed, agf_core::enums::PolicyAction::Allow | agf_core::enums::PolicyAction::Audit)
        {
            return Err(DomainError::QuotaExceeded {
                scope: quota.scope.as_str().into(),
                dimension: quota.dimension.as_str().into(),
                used: next,
                limit: quota.limit,
            });
        }
        counter.used = next;
        anchors.push(ChargeAnchor {
            key: key.clone(),
            quota: quota.id,
            dimension: quota.dimension,
            amount,
            expires: counter.expires,
        });
        charges.push(Charge { key, dimension: quota.dimension, amount });
    }
    ledger.reservations.insert(
        input.reservation,
        Reservation {
            expires: input.now.unix_secs().checked_add(LEASE_SECS).ok_or_else(invalid)?,
            owner: OWNER.into(),
            charges,
        },
    );
    Ok((
        serde_json::to_value(ledger)?,
        Anchor {
            reservation: input.reservation,
            expires: input.now.unix_secs().checked_add(LEASE_SECS).ok_or_else(invalid)?,
            charges: anchors,
        },
    ))
}

pub(crate) fn charges(anchor: &Anchor, actual: Option<&QuotaConsumption>) -> Vec<i64> {
    anchor
        .charges
        .iter()
        .map(|charge| {
            if charge.dimension == QuotaDimension::Concurrency {
                0
            } else {
                actual.map_or(charge.amount, |actual| actual.value(charge.dimension))
            }
        })
        .collect()
}

/// Missing cold counters are accounted in the authenticated stable charge snapshot. Current
/// counters with the exact original key may change; no newer bucket receives an old refund.
pub(crate) fn settle(
    original: Value,
    anchor: &Anchor,
    previous: &[i64],
    desired: &[i64],
    reserved: bool,
    now: i64,
) -> DomainResult<Value> {
    if previous.len() != anchor.charges.len() || desired.len() != anchor.charges.len() {
        return Err(invalid());
    }
    let mut ledger: Ledger = serde_json::from_value(original)?;
    let row = ledger.reservations.get(&anchor.reservation);
    if reserved {
        let row = row.filter(|row| row.owner == OWNER).ok_or_else(invalid)?;
        if row.expires != anchor.expires
            || row.charges.len() != anchor.charges.len()
            || row.charges.iter().zip(&anchor.charges).any(|(row, anchor)| {
                row.key != anchor.key || row.dimension != anchor.dimension || row.amount != anchor.amount
            })
        {
            return Err(invalid());
        }
    } else if row.is_some() {
        return Err(invalid());
    }
    for ((charge, previous), desired) in anchor.charges.iter().zip(previous).zip(desired) {
        if *previous < 0 || *desired < 0 || (charge.dimension == QuotaDimension::Concurrency && *desired != 0) {
            return Err(invalid());
        }
        if charge.expires.is_some_and(|expires| expires <= now) {
            continue;
        }
        let counter = ledger.counters.get_mut(&charge.key).ok_or_else(invalid)?;
        if counter.quota != Some(charge.quota) || counter.expires != charge.expires {
            return Err(invalid());
        }
        counter.used = counter
            .used
            .checked_sub(*previous)
            .and_then(|used| used.checked_add(*desired))
            .filter(|used| *used >= 0)
            .ok_or_else(invalid)?;
    }
    ledger.reservations.remove(&anchor.reservation);
    ledger.roll(now);
    Ok(serde_json::to_value(ledger)?)
}

fn invalid() -> DomainError {
    DomainError::PreconditionFailed("Runtime atomic quota snapshot is inconsistent or exceeds bounds".into())
}
