//! Bounded durable checkpoints. The publisher, not this memory cache, owns permanent Usage identity.
use super::*;
use std::collections::BTreeSet;

const GROUPS: usize = 32;
const RECENT: usize = 16;
const MAX_ENCODED: usize = 48 * 1024;
const TENANTS: usize = 512;
const OTHER: &str = "[other committed groups]";

#[derive(Clone, Serialize, Deserialize)]
pub struct CommittedMeterProjection {
    tenant: TenantId,
    revision: u64,
    total: MeterTotals,
    by_agent: BTreeMap<String, MeterTotals>,
    by_session: BTreeMap<String, MeterTotals>,
    by_provider: BTreeMap<String, MeterTotals>,
    by_model: BTreeMap<String, MeterTotals>,
    recent: Vec<UsageRecord>,
    grouped: bool,
}
impl std::fmt::Debug for CommittedMeterProjection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommittedMeterProjection")
            .field("tenant", &self.tenant)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}
impl CommittedMeterProjection {
    /// New trusted tenant checkpoint. Admission or authentication is not granted by this constructor.
    /// # Errors
    /// Nil tenant is rejected.
    pub fn new(tenant: TenantId) -> DomainResult<Self> {
        if tenant.as_id().is_nil() {
            return Err(invalid());
        }
        Ok(Self {
            tenant,
            revision: 0,
            total: MeterTotals::default(),
            by_agent: BTreeMap::new(),
            by_session: BTreeMap::new(),
            by_provider: BTreeMap::new(),
            by_model: BTreeMap::new(),
            recent: Vec::new(),
            grouped: false,
        })
    }
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub(super) const fn groups_merged(&self) -> bool {
        self.grouped
    }
    /// Caller must append only when immutable authoritative Fact changes to its first terminal state.
    /// # Errors
    /// Foreign rows, invalid identifiers or arithmetic overflow do not produce a new checkpoint.
    pub fn append(&self, rows: &[UsageRecord]) -> DomainResult<Self> {
        self.validate()?;
        if rows.len() > 2
            || rows.iter().any(|row| row.tenant_id != self.tenant || row.id.is_nil())
            || rows.iter().map(|row| row.id).collect::<BTreeSet<_>>().len() != rows.len()
        {
            return Err(invalid());
        }
        let mut next = self.clone();
        next.revision = next.revision.checked_add(1).ok_or_else(invalid)?;
        for row in rows {
            let one = totals(row);
            next.total = replace(next.total, MeterTotals::default(), one)?;
            if let Some(agent) = row.agent_id {
                group(&mut next.by_agent, &agent.to_string(), one, &mut next.grouped)?;
            }
            group(&mut next.by_session, &row.session_id, one, &mut next.grouped)?;
            group(&mut next.by_provider, row.provider.as_str(), one, &mut next.grouped)?;
            group(&mut next.by_model, &row.model, one, &mut next.grouped)?;
            next.recent.push(row.clone());
            if next.recent.len() > RECENT {
                next.recent.remove(0);
            }
        }
        next.compact_display()?;
        next.validate()?;
        Ok(next)
    }
    // Only display detail is collapsed. Durable Usage rows and exact totals stay unchanged.
    fn compact_display(&mut self) -> DomainResult<()> {
        while serde_json::to_vec(self)?.len() > MAX_ENCODED {
            let maps = [&mut self.by_agent, &mut self.by_session, &mut self.by_provider, &mut self.by_model];
            let selected = maps
                .iter()
                .enumerate()
                .flat_map(|(index, map)| {
                    map.keys().filter(|key| key.as_str() != OTHER).map(move |key| (key.len(), index, key.clone()))
                })
                .max();
            if let Some((_, index, key)) = selected {
                let map = maps.into_iter().nth(index).ok_or_else(invalid)?;
                let amount = map.remove(&key).ok_or_else(invalid)?;
                let merged = replace(map.get(OTHER).copied().unwrap_or_default(), MeterTotals::default(), amount)?;
                map.insert(OTHER.into(), merged);
                self.grouped = true;
            } else if !self.recent.is_empty() {
                self.recent.remove(0);
                self.grouped = true;
            } else {
                return Err(invalid());
            }
        }
        Ok(())
    }
    fn validate(&self) -> DomainResult<()> {
        if self.tenant.as_id().is_nil()
            || self.recent.len() > RECENT
            || [&self.by_agent, &self.by_session, &self.by_provider, &self.by_model]
                .iter()
                .any(|map| map.len() > GROUPS + 1 || map.keys().any(|key| key.len() > 256))
            || self.recent.iter().any(|row| {
                row.tenant_id != self.tenant || row.id.is_nil() || row.model.len() > 256 || row.session_id.len() > 256
            })
            || serde_json::to_vec(self)?.len() > MAX_ENCODED
        {
            return Err(invalid());
        }
        for map in [&self.by_session, &self.by_provider, &self.by_model] {
            let sum = map
                .values()
                .try_fold(MeterTotals::default(), |total, row| replace(total, MeterTotals::default(), *row))?;
            if sum != self.total {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
fn group(map: &mut BTreeMap<String, MeterTotals>, key: &str, one: MeterTotals, grouped: &mut bool) -> DomainResult<()> {
    let key = if key.len() > 256 || key == OTHER || !map.contains_key(key) && map.len() >= GROUPS {
        *grouped = true;
        OTHER
    } else {
        key
    };
    let total = replace(map.get(key).copied().unwrap_or_default(), MeterTotals::default(), one)?;
    map.insert(key.into(), total);
    Ok(())
}
fn invalid() -> DomainError {
    DomainError::PreconditionFailed("Committed Meter checkpoint is invalid or exceeds its fixed bound".into())
}
fn totals(row: &UsageRecord) -> MeterTotals {
    MeterTotals {
        calls: 1,
        cache_hits: u64::from(row.cache_hit),
        mocked_calls: u64::from(row.mocked),
        prompt_tokens: row.prompt_tokens,
        completion_tokens: row.completion_tokens,
        cached_tokens: row.cached_tokens,
        cache_write_tokens: row.cache_write_tokens,
        cache_write_1h_tokens: row.cache_write_1h_tokens,
        cost_micro: row.cost_micro,
        latency_ms: row.latency_ms,
    }
}
fn replace(current: MeterTotals, old: MeterTotals, new: MeterTotals) -> DomainResult<MeterTotals> {
    macro_rules! field {
        ($name:ident) => {
            current.$name.checked_sub(old.$name).and_then(|base| base.checked_add(new.$name)).ok_or_else(invalid)?
        };
    }
    Ok(MeterTotals {
        calls: field!(calls),
        cache_hits: field!(cache_hits),
        mocked_calls: field!(mocked_calls),
        prompt_tokens: field!(prompt_tokens),
        completion_tokens: field!(completion_tokens),
        cached_tokens: field!(cached_tokens),
        cache_write_tokens: field!(cache_write_tokens),
        cache_write_1h_tokens: field!(cache_write_1h_tokens),
        cost_micro: field!(cost_micro),
        latency_ms: field!(latency_ms),
    })
}
fn changes(
    current: &BTreeMap<String, MeterTotals>,
    old: &BTreeMap<String, MeterTotals>,
    new: &BTreeMap<String, MeterTotals>,
) -> DomainResult<Vec<(String, MeterTotals)>> {
    old.keys()
        .chain(new.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|key| {
            Ok((
                key.clone(),
                replace(
                    current.get(key).copied().unwrap_or_default(),
                    old.get(key).copied().unwrap_or_default(),
                    new.get(key).copied().unwrap_or_default(),
                )?,
            ))
        })
        .collect()
}
fn apply(map: &mut BTreeMap<String, MeterTotals>, changes: Vec<(String, MeterTotals)>) {
    for (key, value) in changes {
        if value == MeterTotals::default() {
            map.remove(&key);
        } else {
            map.insert(key, value);
        }
    }
}
impl Meter {
    /// Mark a failed authoritative checkpoint refresh; memory totals are then explicitly incomplete.
    pub fn mark_committed_projection_incomplete(&self) {
        self.inner.lock().committed_projection_incomplete = true;
    }

    /// Replace this tenant's committed contribution by a verified durable monotonic checkpoint.
    /// # Errors
    /// Same-revision conflicts, overflow, corrupt totals or node tenant capacity are explicit errors.
    /// No UUID eviction occurs, and stale checkpoint replay cannot add totals a second time.
    pub fn absorb_committed_projection(&self, projection: &CommittedMeterProjection) -> DomainResult<bool> {
        projection.validate()?;
        let mut inner = self.inner.lock();
        let old = inner.committed.get(&projection.tenant).cloned();
        if let Some(old) = &old {
            if old.revision > projection.revision {
                return Ok(false);
            }
            if old.revision == projection.revision {
                return if serde_json::to_vec(old)? == serde_json::to_vec(projection)? {
                    Ok(false)
                } else {
                    Err(DomainError::Conflict("Meter checkpoint revision has another immutable body".into()))
                };
            }
        } else if inner.committed.len() >= TENANTS {
            inner.committed_projection_incomplete = true;
            return Err(invalid());
        }
        let old = old.unwrap_or(CommittedMeterProjection::new(projection.tenant)?);
        let total = replace(inner.total, old.total, projection.total)?;
        let tenant_key = projection.tenant.to_string();
        let tenant =
            replace(inner.by_tenant.get(&tenant_key).copied().unwrap_or_default(), old.total, projection.total)?;
        let agent = changes(&inner.by_agent, &old.by_agent, &projection.by_agent)?;
        let session = changes(&inner.by_session, &old.by_session, &projection.by_session)?;
        let provider = changes(&inner.by_provider, &old.by_provider, &projection.by_provider)?;
        let model = changes(&inner.by_model, &old.by_model, &projection.by_model)?;
        inner.total = total;
        inner.by_tenant.insert(tenant_key, tenant);
        apply(&mut inner.by_agent, agent);
        apply(&mut inner.by_session, session);
        apply(&mut inner.by_provider, provider);
        apply(&mut inner.by_model, model);
        let previous = old.recent.iter().map(|row| row.id).collect::<BTreeSet<_>>();
        inner.recent.retain(|row| !previous.contains(&row.id));
        inner.recent.extend(projection.recent.iter().cloned());
        if inner.recent.len() > Self::MAX_RECENT {
            let overflow = inner.recent.len() - Self::MAX_RECENT;
            inner.recent.drain(..overflow);
        }
        inner.committed.insert(projection.tenant, projection.clone());
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
