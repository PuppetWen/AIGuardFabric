//! API Key state and its success audit publish together, including explicit offline mode.
use super::*;
use agf_core::audit::{AuditAction, AuditOutcome};
use agf_storage::{ApiKeyRepo, AuditRepo};

fn validate(tenant: TenantId, id: Id, audit: &AuditLog) -> DomainResult<()> {
    if audit.tenant_id != tenant {
        return Err(DomainError::TenantViolation { tenant: audit.tenant_id.to_string(), resource: "api-key".into() });
    }
    if audit.action != AuditAction::Grant
        || audit.outcome != AuditOutcome::Success
        || audit.target.kind != "api-key"
        || audit.target.id.as_deref() != Some(id.to_string().as_str())
    {
        return Err(DomainError::Validation("API Key audit does not match the tenant's key mutation".into()));
    }
    Ok(())
}

fn seal_offline(memory: &Memory, mut audit: AuditLog) -> DomainResult<AuditLog> {
    let previous = memory.audits.get(&audit.tenant_id).and_then(|chain| chain.last());
    audit.sequence = match previous {
        Some(entry) => {
            entry.sequence.checked_add(1).ok_or_else(|| DomainError::Validation("Audit sequence overflow".into()))?
        }
        None => 1,
    };
    audit.prev_hash = previous.map_or_else(|| GENESIS_HASH.to_owned(), |entry| entry.entry_hash.clone());
    audit.entry_hash.clear();
    audit.seal();
    Ok(audit)
}

impl ApiStore {
    /// Commit issuance and its success audit before the one-time plaintext response is returned.
    pub async fn api_key_create_audited(&self, key: &ApiKey, audit: AuditLog) -> DomainResult<()> {
        validate(key.tenant_id, key.id, &audit)?;
        if let Some(db) = self.database() {
            let mut tx = db.db().begin_tenant(key.tenant_id).await?;
            ApiKeyRepo::insert(&mut tx, key).await?;
            let sealed = AuditRepo::append_log(&mut tx, audit).await?;
            tx.commit().await?;
            self.refresh_key_audit(key, Some(&sealed));
        } else {
            let mut memory = self.lock()?;
            let slot = memory.api_keys.iter().position(|saved| saved.id == key.id);
            if slot.is_some_and(|index| memory.api_keys[index].tenant_id != key.tenant_id) {
                return Err(DomainError::TenantViolation {
                    tenant: key.tenant_id.to_string(),
                    resource: "api-key".into(),
                });
            }
            let sealed = seal_offline(&memory, audit)?;
            match slot {
                Some(index) => memory.api_keys[index] = key.clone(),
                None => memory.api_keys.push(key.clone()),
            }
            memory.audits.entry(key.tenant_id).or_default().push(sealed);
        }
        Ok(())
    }

    /// Revoke once and append one success audit; a repeated request remains successful and unchanged.
    pub async fn api_key_revoke_audited(&self, tenant: TenantId, id: Id, audit: AuditLog) -> DomainResult<()> {
        validate(tenant, id, &audit)?;
        if let Some(db) = self.database() {
            let mut tx = db.db().begin_tenant(tenant).await?;
            let (key, changed) = ApiKeyRepo::revoke_once(&mut tx, id).await?;
            let sealed = if changed { Some(AuditRepo::append_log(&mut tx, audit).await?) } else { None };
            tx.commit().await?;
            self.refresh_key_audit(&key, sealed.as_ref());
        } else {
            let mut memory = self.lock()?;
            let index = memory
                .api_keys
                .iter()
                .position(|key| key.id == id && key.tenant_id == tenant)
                .ok_or_else(|| DomainError::NotFound { entity: "api-key", id: id.to_string() })?;
            if memory.api_keys[index].revoked {
                return Ok(());
            }
            let sealed = seal_offline(&memory, audit)?;
            memory.api_keys[index].revoked = true;
            memory.audits.entry(tenant).or_default().push(sealed);
        }
        Ok(())
    }

    fn refresh_key_audit(&self, key: &ApiKey, sealed: Option<&AuditLog>) {
        if let Err(error) = self.hydrate_api_key(key) {
            tracing::warn!(%error, "Committed API Key memory projection failed");
        }
        if let Some(sealed) = sealed {
            if let Err(error) = self.hydrate_audit(sealed) {
                tracing::warn!(%error, "Committed API Key audit memory projection failed");
            }
        }
    }
}
