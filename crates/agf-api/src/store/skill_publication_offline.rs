//! ConfigStore -> ApiStore lock order; no async calls or authorizer reentry under Memory.
use super::*;
use crate::Principal;
use agf_core::rbac::SubjectKind;
use serde_json::Value;

/// Keys and bound agents live in this mutex. User/role stores retain their separate proof boundary.
pub(crate) struct Identity {
    tenant: TenantId,
    key: Option<(Id, Value)>,
    agent: Option<(TenantId, Id, Value)>,
}
impl Identity {
    fn check(&self, memory: &Memory) -> DomainResult<()> {
        if let Some((id, expected)) = &self.key {
            let current = memory.api_keys.iter().find(|key| {
                key.tenant_id == self.tenant
                    && key.id == *id
                    && !key.revoked
                    && key.expires_at.is_none_or(|at| at > Timestamp::now())
            });
            if current.map(serde_json::to_value).transpose()?.as_ref() != Some(expected) {
                return Err(DomainError::Forbidden("治理提交期间 API Key 已变化或失效".into()));
            }
        }
        if let Some((tenant, id, expected)) = &self.agent {
            let current = memory.assets.get(&(*tenant, *id)).filter(|asset| asset.deleted_at.is_none());
            if current.map(serde_json::to_value).transpose()?.as_ref() != Some(expected) {
                return Err(DomainError::Forbidden("治理提交期间绑定 Agent 已变化".into()));
            }
        }
        Ok(())
    }
}

impl ApiStore {
    pub(crate) fn governance_identity(&self, principal: &Principal) -> DomainResult<Identity> {
        let memory = self.lock()?;
        let key = if principal.subject_kind == SubjectKind::ApiKey {
            let id = principal.subject_id.ok_or_else(|| DomainError::Forbidden("治理提交缺少身份".into()))?;
            let key = memory
                .api_keys
                .iter()
                .find(|key| {
                    key.tenant_id == principal.identity_tenant
                        && key.id == id
                        && !key.revoked
                        && key.expires_at.is_none_or(|at| at > Timestamp::now())
                })
                .ok_or_else(|| DomainError::Forbidden("治理提交的 API Key 已失效".into()))?;
            Some((id, serde_json::to_value(key)?))
        } else {
            None
        };
        let agent = principal
            .agent_id
            .map(|id| {
                let asset = memory
                    .assets
                    .get(&(principal.tenant, id))
                    .filter(|asset| asset.deleted_at.is_none())
                    .ok_or_else(|| DomainError::Forbidden("治理提交的绑定 Agent 不存在".into()))?;
                Ok::<_, DomainError>((principal.tenant, id, serde_json::to_value(asset)?))
            })
            .transpose()?;
        Ok(Identity { tenant: principal.identity_tenant, key, agent })
    }

    pub(crate) fn governance_audit_append<F>(
        &self,
        audit: AuditLog,
        identity: &Identity,
        budget: F,
    ) -> DomainResult<AuditLog>
    where
        F: FnOnce() -> DomainResult<()>,
    {
        if self.database.is_some() {
            return Err(offline_only());
        }
        let mut memory = self.lock()?;
        identity.check(&memory)?;
        let sealed = seal(&memory, audit)?;
        budget()?;
        memory.audits.entry(sealed.tenant_id).or_default().push(sealed.clone());
        Ok(sealed)
    }

    /// Every fallible check, including audit sealing, precedes asset/history/audit insertion.
    pub(crate) fn publish_skill_offline<F, A, B>(
        &self,
        tenant: TenantId,
        id: Id,
        identity: &Identity,
        apply: F,
        audit: A,
        budget: B,
    ) -> DomainResult<Asset>
    where
        F: FnOnce(Option<Asset>) -> DomainResult<(Asset, Option<AssetChange>)>,
        A: FnOnce(&Asset) -> AuditLog,
        B: FnOnce() -> DomainResult<()>,
    {
        if self.database.is_some() {
            return Err(offline_only());
        }
        let mut memory = self.lock()?;
        identity.check(&memory)?;
        let (asset, change) = apply(memory.assets.get(&(tenant, id)).cloned())?;
        validate(tenant, id, &asset, change.as_ref())?;
        if memory
            .assets
            .values()
            .any(|row| row.tenant_id == tenant && row.id != id && row.fingerprint == asset.fingerprint)
        {
            return Err(DomainError::Conflict("Asset fingerprint belongs to a different canonical ID".into()));
        }
        let log = audit(&asset);
        if log.tenant_id != tenant {
            return Err(DomainError::Validation("Skill audit tenant changed".into()));
        }
        let sealed = seal(&memory, log)?;
        budget()?;
        memory.assets.insert((tenant, id), asset.clone());
        if let Some(change) = change {
            memory.changes.push(change);
        }
        memory.audits.entry(tenant).or_default().push(sealed);
        Ok(asset)
    }
}

pub(crate) fn validate(tenant: TenantId, id: Id, asset: &Asset, change: Option<&AssetChange>) -> DomainResult<()> {
    if (asset.tenant_id, asset.id) != (tenant, id)
        || change.is_some_and(|change| (change.tenant_id, change.asset_id) != (tenant, id))
    {
        return Err(DomainError::Validation("Skill mutation or history changed its identity".into()));
    }
    Ok(())
}
fn seal(memory: &Memory, mut audit: AuditLog) -> DomainResult<AuditLog> {
    let last = memory.audits.get(&audit.tenant_id).and_then(|chain| chain.last());
    audit.sequence = last
        .map_or(Some(1), |entry| entry.sequence.checked_add(1))
        .ok_or_else(|| DomainError::PreconditionFailed("审计序列达到上限".into()))?;
    audit.prev_hash = last.map_or_else(|| GENESIS_HASH.into(), |entry| entry.entry_hash.clone());
    audit.entry_hash.clear();
    audit.seal();
    if !audit.verify() {
        return Err(DomainError::Crypto("治理审计候选无法校验".into()));
    }
    Ok(audit)
}
fn offline_only() -> DomainError {
    DomainError::PreconditionFailed("Offline governance cannot use a database".into())
}

#[cfg(test)]
mod tests;
