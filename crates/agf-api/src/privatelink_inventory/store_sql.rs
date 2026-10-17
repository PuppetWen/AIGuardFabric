//! One guarded SQL transaction changes the local inventory ledger; network calls never hold it.
use super::{
    KIND,
    contract::{Record, Scope},
    scope, store,
};
use crate::{cloud_store, integration_store::Stored, state::AppState, store::asset_transaction::AssetTransaction};
use agf_core::{audit::AuditLog, error::DomainResult, ids::TenantId};

pub(super) async fn guarded(
    tx: &AssetTransaction<'_>,
    state: &AppState,
    tenant: TenantId,
    expected: &Scope,
) -> DomainResult<()> {
    tx.tenant_enabled().await?;
    tx.configuration_lock(cloud_store::KIND, expected.cloud_id).await?;
    let row = tx
        .configuration::<Stored>(cloud_store::KIND, expected.cloud_id)
        .await?
        .filter(|row| row.enabled)
        .ok_or_else(scope::stale)?;
    if scope::from_row(state, tenant, &row)? != *expected {
        return Err(scope::stale());
    }
    Ok(())
}

pub(super) async fn mutate<F>(
    state: &AppState,
    tenant: TenantId,
    expected: Option<&Scope>,
    apply: F,
) -> DomainResult<Record>
where
    F: FnOnce(&mut Record) -> DomainResult<Option<AuditLog>> + Send,
{
    let db = state.store.database().ok_or_else(scope::stale)?;
    let tx = AssetTransaction::begin(db, tenant).await?;
    tx.tenant_enabled().await?;
    if let Some(expected) = expected {
        guarded(&tx, state, tenant, expected).await?;
    }
    let id = crate::integration_store::id(tenant, super::NAME);
    tx.configuration_lock(KIND, id).await?;
    let mut row = tx.configuration::<Record>(KIND, id).await?.unwrap_or_default();
    let before = serde_json::to_vec(&row)?;
    let audit = apply(&mut row)?;
    let after = store::bounded(&row)?;
    if before != after {
        tx.configure(KIND, id, Some(serde_json::from_slice(&after)?)).await?;
        if let Some(audit) = audit {
            tx.audit(audit).await?;
        }
    }
    tx.commit(&state.store).await?;
    Ok(row)
}
