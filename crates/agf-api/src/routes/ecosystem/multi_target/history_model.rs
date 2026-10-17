//! Authenticated capacity and bounded owner index; neither grants dispatch.
use super::{
    records::{self, Envelope},
    types::hash,
};
use crate::{AppState, soar_workflow::Actor};
use agf_core::{
    error::DomainResult,
    ids::{Id, TenantId, deterministic_id},
};
use agf_storage::crypto::FieldCipher;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub(super) const OWNER_KIND: &str = "redteam-multi-target-owner-index";
pub(super) const PERMANENT: u64 = 16_384;
pub(super) const RECENT: usize = 256;
pub(super) const ACTIVE: usize = 128;
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Capacity {
    pub tenant: TenantId,
    pub claimed: u64,
    pub active: Vec<Id>,
}
impl Capacity {
    pub(super) fn validate(&self, tenant: TenantId, count: u64) -> DomainResult<()> {
        if self.tenant != tenant
            || self.claimed != count
            || count > PERMANENT
            || self.active.len() > ACTIVE
            || self.active.len() as u64 > count
            || self.active.iter().any(Id::is_nil)
            || self.active.iter().copied().collect::<std::collections::BTreeSet<_>>().len() != self.active.len()
        {
            return Err(records::corrupt());
        }
        Ok(())
    }
    pub(super) fn admit(&mut self, id: Id) -> DomainResult<()> {
        if self.claimed >= PERMANENT {
            return Err(agf_core::error::DomainError::PreconditionFailed(
                "16,384 permanent UUIDs retained; archive cannot reopen UUID capacity".into(),
            ));
        }
        if self.active.len() >= ACTIVE {
            return Err(agf_core::error::DomainError::PreconditionFailed(
                "128 retained run bodies; review and archive a completed original run".into(),
            ));
        }
        if id.is_nil() || self.active.contains(&id) {
            return Err(records::corrupt());
        }
        self.claimed = self.claimed.checked_add(1).ok_or_else(records::corrupt)?;
        self.active.push(id);
        Ok(())
    }
    pub(super) fn archive(&mut self, id: Id) -> DomainResult<()> {
        let slot = self.active.iter().position(|value| *value == id).ok_or_else(records::corrupt)?;
        self.active.remove(slot);
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct OwnerIndex {
    pub tenant: TenantId,
    pub owner: Actor,
    pub claimed: u64,
    pub recent: Vec<Id>,
}
impl OwnerIndex {
    pub(super) fn validate(&self, tenant: TenantId, owner: &Actor) -> DomainResult<()> {
        if self.tenant != tenant
            || owner_id(tenant, &self.owner)? != owner_id(tenant, owner)?
            || self.claimed > PERMANENT
            || self.recent.len() > RECENT
            || self.recent.len() as u64 > self.claimed
            || self.recent.iter().any(Id::is_nil)
            || self.recent.iter().copied().collect::<std::collections::BTreeSet<_>>().len() != self.recent.len()
        {
            return Err(records::corrupt());
        }
        Ok(())
    }
    pub(super) fn admit(&mut self, id: Id) -> DomainResult<()> {
        if id.is_nil() || self.recent.contains(&id) {
            return Err(records::corrupt());
        }
        self.claimed = self.claimed.checked_add(1).filter(|value| *value <= PERMANENT).ok_or_else(records::corrupt)?;
        self.recent.insert(0, id);
        self.recent.truncate(RECENT);
        Ok(())
    }
}
pub(super) fn owner_id(tenant: TenantId, owner: &Actor) -> DomainResult<Id> {
    let identity = hash(&serde_json::json!([owner.id, owner.kind, owner.identity_tenant]))?;
    Ok(deterministic_id("agf.redteam.multi.owner-index", &format!("{tenant}:{identity}")))
}
pub(super) fn seal<T: Serialize>(state: &AppState, tenant: TenantId, id: Id, value: &T) -> DomainResult<Envelope> {
    let raw = serde_json::to_string(value)?;
    if raw.len() > 32 * 1024 {
        return Err(records::corrupt());
    }
    Ok(Envelope { tenant, id, body: crate::model_gateway::encrypt(state, tenant, id, raw)? })
}
pub(super) fn restore<T: DeserializeOwned>(
    state: &AppState,
    tenant: TenantId,
    id: Id,
    row: Envelope,
) -> DomainResult<T> {
    if row.tenant != tenant || row.id != id || row.body.aad.as_deref() != Some(&FieldCipher::make_aad(&tenant, &id)) {
        return Err(records::corrupt());
    }
    let raw = crate::model_gateway::cipher(state)?.decrypt(&row.body)?;
    if raw.expose_secret().len() > 32 * 1024 {
        return Err(records::corrupt());
    }
    serde_json::from_str(raw.expose_secret()).map_err(|_| records::corrupt())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn archive_frees_body_only_and_permanent_limit_never_reopens() -> DomainResult<()> {
        let tenant = TenantId::default();
        let id = Id::new();
        let mut capacity = Capacity { tenant, claimed: PERMANENT - 1, active: vec![] };
        capacity.admit(id)?;
        capacity.archive(id)?;
        assert!(capacity.active.is_empty() && capacity.claimed == PERMANENT);
        assert!(capacity.admit(Id::new()).is_err());
        assert!(capacity.archive(id).is_err());
        Ok(())
    }
    #[test]
    fn bounded_recent_eviction_retains_permanent_capacity_and_exact_owner() -> DomainResult<()> {
        let tenant = TenantId::default();
        let owner =
            Actor { id: Id::new(), kind: agf_core::rbac::SubjectKind::User, identity_tenant: tenant, source_ip: None };
        let mut index = OwnerIndex { tenant, owner: owner.clone(), claimed: 0, recent: vec![] };
        for _ in 0..300 {
            index.admit(Id::new())?;
        }
        index.validate(tenant, &owner)?;
        assert!(index.recent.len() == RECENT && index.claimed == 300);
        let mut foreign = owner;
        foreign.id = Id::new();
        assert!(index.validate(tenant, &foreign).is_err());
        Ok(())
    }
}
