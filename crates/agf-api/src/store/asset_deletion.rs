use super::asset_transaction::AssetTransaction;
use super::*;
use agf_core::asset::ChangeKind;
use agf_core::enums::LifecycleState;

impl ApiStore {
    /// Hide a reviewed terminal asset while retaining history and its stable identity.
    pub async fn asset_remove_durable(
        &self,
        tenant: TenantId,
        id: Id,
        expected_updated_at: Timestamp,
        confirm_name: &str,
        reason: &str,
        actor: &str,
        audit: AuditLog,
    ) -> DomainResult<()> {
        if let Some(db) = &self.database {
            let backend = AssetTransaction::begin(db, tenant).await?;
            let asset = backend.find(tenant, id).await?.ok_or_else(|| not_found(id))?;
            let change = removal_change(&asset, expected_updated_at, confirm_name, reason, actor)?;
            backend.soft_delete(tenant, &asset).await?;
            backend.record_change(tenant, &change).await?;
            backend.audit(audit).await?;
            return backend.commit(self).await;
        }
        {
            let mut memory = self.lock()?;
            let asset = memory.assets.get(&(tenant, id)).ok_or_else(|| not_found(id))?.clone();
            let change = removal_change(&asset, expected_updated_at, confirm_name, reason, actor)?;
            memory.assets.remove(&(tenant, id));
            memory.changes.push(change);
        }
        self.audit_append_durable(audit).await?;
        Ok(())
    }
}

fn not_found(id: Id) -> DomainError {
    DomainError::NotFound { entity: "asset", id: id.to_string() }
}

fn removal_change(
    asset: &Asset,
    expected: Timestamp,
    confirmed_name: &str,
    reason: &str,
    actor: &str,
) -> DomainResult<AssetChange> {
    if asset.updated_at != expected {
        return Err(DomainError::Conflict(
            "Asset changed since this form was opened; refresh before removing it".into(),
        ));
    }
    if !matches!(asset.lifecycle, LifecycleState::Archived | LifecycleState::Rejected) {
        return Err(DomainError::PreconditionFailed(
            "Archive or reject the asset before removing it from inventory".into(),
        ));
    }
    if confirmed_name != asset.name {
        return Err(DomainError::Validation("Confirmed asset name does not match the current record".into()));
    }
    let reason = reason.trim();
    if reason.is_empty()
        || reason.len() > 1024
        || reason.chars().any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(DomainError::Validation(
            "Removal reason must contain 1–1024 bytes without control characters".into(),
        ));
    }
    Ok(AssetChange {
        id: Id::new(),
        tenant_id: asset.tenant_id,
        asset_id: asset.id,
        kind: asset.kind,
        change_kind: ChangeKind::Removed,
        field: Some("inventory".into()),
        old_value: Some(serde_json::json!(asset.name)),
        new_value: None,
        risky: false,
        risk_note: Some(format!("{actor}: {reason}")),
        domain: None,
        detected_at: Timestamp::now(),
    })
}
