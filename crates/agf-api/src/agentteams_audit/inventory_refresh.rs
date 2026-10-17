//! A compatible inventory refresh preserves collector bindings; identity changes require review.
use super::binding::{self, Binding, KIND, Resources};
use crate::{cloud_inventory::Snapshot, state::AppState, store::asset_transaction::AssetTransaction};
use agf_core::{error::DomainResult, ids::TenantId, time::Timestamp};

fn compatible(row: &Binding, tenant: TenantId, snapshot: &Snapshot, resources: &Resources) -> bool {
    let same_cloud_revision = row.cloud_version == snapshot.version;
    row.enabled
        && row.version > 0
        && same_cloud_revision
        && row.mocked == snapshot.mocked
        && row.scope_id == binding::scope(tenant, snapshot)
        && row.members == resources.members
        && row.teams == resources.teams
}

pub(crate) async fn in_transaction(
    tx: &AssetTransaction<'_>,
    tenant: TenantId,
    snapshot: &Snapshot,
    previous: Option<Timestamp>,
) -> DomainResult<usize> {
    let Ok(resources) = binding::resources(snapshot) else {
        return Ok(0);
    };
    // Cloud row is already exclusively locked by inventory publication. Lock all bindings before
    // the caller appends the single inventory audit, avoiding disable-vs-audit lock inversion.
    let records = tx.configurations::<Binding>(KIND).await?;
    let mut refreshed = 0;
    for (id, mut row) in records {
        if id != row.source_id
            || previous != Some(row.inventory_updated_at)
            || !compatible(&row, tenant, snapshot, &resources)
        {
            continue;
        }
        row.inventory_updated_at = snapshot.checked_at;
        row.version = row.version.checked_add(1).ok_or_else(super::stale)?;
        tx.configure(KIND, id, Some(serde_json::to_value(&row)?)).await?;
        refreshed += 1;
    }
    Ok(refreshed)
}

pub(crate) async fn offline(
    state: &AppState,
    tenant: TenantId,
    snapshot: &Snapshot,
    previous: Option<Timestamp>,
) -> DomainResult<usize> {
    let Ok(resources) = binding::resources(snapshot) else {
        return Ok(0);
    };
    let rows: Vec<Binding> = state.configurations.list(tenant, KIND).await?;
    let mut refreshed = 0;
    for old in rows {
        if previous != Some(old.inventory_updated_at) || !compatible(&old, tenant, snapshot, &resources) {
            continue;
        }
        let mut changed = false;
        state
            .configurations
            .mutate::<Binding, _>(tenant, KIND, old.source_id, |row| {
                if row.version == old.version
                    && row.binding_id == old.binding_id
                    && previous == Some(row.inventory_updated_at)
                    && compatible(row, tenant, snapshot, &resources)
                {
                    row.inventory_updated_at = snapshot.checked_at;
                    row.version = row.version.checked_add(1).ok_or_else(super::stale)?;
                    changed = true;
                }
                Ok(())
            })
            .await?;
        refreshed += usize::from(changed);
    }
    Ok(refreshed)
}
