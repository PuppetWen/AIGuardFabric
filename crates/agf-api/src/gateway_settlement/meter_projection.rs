//! The durable revision counter commits with first Fact publication, UsageRows, ledgers and audit.
use super::{codec, components, meter_coverage, records::*, store};
use crate::{AppState, model_routes::tenant_record_id, store::asset_transaction::AssetTransaction};
use agf_aigw::meter::CommittedMeterProjection;
use agf_core::{
    error::DomainResult,
    ids::{Id, TenantId},
};
use serde_json::Value;
use std::collections::BTreeMap;

const KIND: &str = "gateway-meter-checkpoint-v1";

pub(super) async fn append(
    state: &AppState,
    tx: &AssetTransaction<'_>,
    pending: &Pending,
    writes: &mut BTreeMap<(&'static str, Id), Value>,
) -> DomainResult<()> {
    let tenant = pending.origin.tenant;
    let id = tenant_record_id(tenant);
    let original = store::read(tx, KIND, id).await?;
    let projection: CommittedMeterProjection = if let Some(value) = original {
        store::decode(state, tenant, id, KIND, value)?
    } else {
        CommittedMeterProjection::new(tenant)?
    };
    if projection.tenant() != tenant {
        return Err(store::missing());
    }
    let rows = components::usage_rows(&pending.outcome).cloned().collect::<Vec<_>>();
    let next = projection.append(&rows)?;
    writes.insert((KIND, id), store::encoded(state, tenant, id, KIND, &next)?);
    Ok(())
}

// Read the latest checkpoint rather than the recovered request's possibly older revision.
// No initialization or writes occur. Stale replica responses are ignored by Meter revision checks.
pub(super) async fn hydrate(state: &AppState, tenant: TenantId) -> DomainResult<()> {
    let id = tenant_record_id(tenant);
    let result = async {
        let witness = meter_coverage::read(state, tenant, id, KIND).await?;
        let Some(stored) = &witness.checkpoint else {
            return meter_coverage::absent(state, tenant, &witness); // Never initialize a zero row.
        };
        let projection: CommittedMeterProjection = codec::decode(state, tenant, id, KIND, stored)?;
        if projection.tenant() != tenant {
            return Err(store::missing());
        }
        // Preserve verified committed subtotals even if legacy coverage cannot be proven.
        // They are explicitly incomplete and never retroactively used to change ledger charges.
        state.meter.absorb_committed_projection(&projection)?;
        meter_coverage::verify(state, tenant, &projection, &witness)?;
        Ok(())
    }
    .await;
    if result.is_err() {
        state.meter.mark_committed_projection_incomplete();
    }
    result
}
