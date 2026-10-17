//! Current and historical signed revisions retain their original identity.
use super::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct Registry {
    pub initialized: bool,
    pub entries: BTreeMap<Id, Policy>,
    pub history: BTreeMap<Id, Vec<Policy>>,
}

impl Registry {
    pub(super) fn initialize(
        &mut self,
        tenant: TenantId,
        original: Vec<Policy>,
        signer: &PolicySigner,
    ) -> DomainResult<()> {
        if self.initialized {
            return self.validate(tenant, signer);
        }
        if !self.entries.is_empty() || !self.history.is_empty() {
            return Err(DomainError::Crypto("未初始化策略记录包含不可信内容".into()));
        }
        for mut row in original {
            if row.tenant_id != tenant || row.id.is_nil() || row.version == 0 {
                return Err(identity_error());
            }
            row.content_hash = row.compute_hash();
            row.signature = signer.sign(&row);
            if self.entries.insert(row.id, row).is_some() {
                return Err(identity_error());
            }
        }
        self.initialized = true;
        self.validate(tenant, signer)
    }

    pub(super) fn validate(&self, tenant: TenantId, signer: &PolicySigner) -> DomainResult<()> {
        let mut names = BTreeSet::new();
        for (id, row) in &self.entries {
            validate_row(tenant, *id, row, signer)?;
            if row.deleted_at.is_none() && !names.insert(&row.name) {
                return Err(identity_error());
            }
        }
        for (id, versions) in &self.history {
            let current = self.entries.get(id).ok_or_else(identity_error)?;
            if versions.len() > 100 {
                return Err(identity_error());
            }
            let mut previous = 0;
            for row in versions {
                validate_row(tenant, *id, row, signer)?;
                if row.version <= previous || row.version >= current.version || row.name != current.name {
                    return Err(identity_error());
                }
                previous = row.version;
            }
        }
        Ok(())
    }

    pub(super) fn previous(&self, id: Id) -> DomainResult<&Policy> {
        self.entries.get(&id).ok_or_else(|| DomainError::NotFound { entity: "policy", id: id.to_string() })
    }

    pub(super) fn remember(&mut self, row: Policy) {
        let history = self.history.entry(row.id).or_default();
        history.push(row);
        if history.len() > 100 {
            history.remove(0);
        }
    }
}

fn validate_row(tenant: TenantId, id: Id, row: &Policy, signer: &PolicySigner) -> DomainResult<()> {
    if (row.tenant_id, row.id) != (tenant, id)
        || id.is_nil()
        || row.version == 0
        || row.content_hash != row.compute_hash()
    {
        return Err(identity_error());
    }
    signer.verify(row)
}

fn identity_error() -> DomainError {
    DomainError::Crypto("策略当前版本或历史的租户、身份、版本或签名绑定不一致".into())
}
