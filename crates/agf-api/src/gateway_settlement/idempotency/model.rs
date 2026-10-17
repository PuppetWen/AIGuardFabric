//! Immutable key identity and original admission evidence; no model response body is stored here.
use super::{Binding, MAX_KEYS, identity};
use crate::gateway_settlement::records::{Fact, Origin, usage_id, valid_execution_window};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    tenant: TenantId,
    id: Id,
    namespace: String,
    input: String,
    owner: Origin,
    attempt: Id,
    usage: Id,
    submitted: Timestamp,
    execute_before: Timestamp,
}
impl Entry {
    pub(super) fn new(binding: &Binding, fact: &Fact) -> DomainResult<Self> {
        let entry = Self {
            tenant: fact.origin.tenant,
            id: binding.id,
            namespace: binding.namespace.clone(),
            input: binding.input.clone(),
            owner: fact.origin.clone(),
            attempt: fact.attempt,
            usage: fact.usage_id,
            submitted: fact.submitted_at,
            execute_before: fact.execute_before,
        };
        entry.validate(binding.id, &binding.namespace)?;
        entry.fact(fact)?;
        Ok(entry)
    }
    pub(super) fn validate(&self, id: Id, namespace: &str) -> DomainResult<()> {
        if self.id != id
            || identity::id(&self.namespace)? != id
            || self.namespace != namespace
            || self.tenant != self.owner.tenant
            || self.tenant.as_uuid().is_nil()
            || self.owner.subject.is_nil()
            || self.owner.identity_tenant.as_uuid().is_nil()
            || self.attempt.is_nil()
            || self.usage != usage_id(self.tenant, self.attempt)
            || !identity::digest(&self.input)
            || !valid_execution_window(self.submitted, self.execute_before)
        {
            return Err(identity::corrupt());
        }
        Ok(())
    }
    pub(super) fn fact(&self, fact: &Fact) -> DomainResult<()> {
        let owner_matches = fact.origin == self.owner;
        if !owner_matches
            || fact.attempt != self.attempt
            || fact.usage_id != self.usage
            || fact.submitted_at != self.submitted
            || fact.execute_before != self.execute_before
        {
            return Err(identity::corrupt());
        }
        Ok(())
    }
    pub(super) const fn attempt(&self) -> Id {
        self.attempt
    }
    pub(super) fn owner(&self) -> &Origin {
        &self.owner
    }
    pub(super) fn matches(&self, binding: &Binding) -> bool {
        self.input == binding.input
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Capacity {
    tenant: TenantId,
    used: u32,
}
impl Capacity {
    pub(super) fn next(current: Option<Self>, tenant: TenantId, actual: u32) -> DomainResult<Self> {
        let used = match current {
            Some(row) if row.tenant == tenant && row.used == actual => row.used,
            None if actual == 0 => 0,
            _ => return Err(identity::corrupt()),
        };
        if used >= MAX_KEYS {
            return Err(DomainError::RateLimited("Permanent gateway admission key capacity is full".into()));
        }
        Ok(Self { tenant, used: used.checked_add(1).ok_or_else(identity::corrupt)? })
    }
}
