use super::*;
use crate::{
    integration_store::Stored,
    policy_store::{AuthorizedSubmission, authorize_publication},
    store::asset_transaction::AssetTransaction,
};
use agf_asset::service::AssetBackend;

pub(super) async fn publish(
    state: &AppState,
    submission: &AuthorizedSubmission<'_>,
    team: &str,
    input: &model::Input,
) -> DomainResult<model::Intent> {
    let principal = submission.principal;
    let actor = principal.subject_id.ok_or_else(denied)?;
    let database = state.store.database().ok_or_else(denied)?;
    let tx = AssetTransaction::begin(database, principal.tenant).await?;
    tx.tenant_enabled().await?;
    let cloud_id = crate::integration_store::id(principal.tenant, crate::cloud_inventory::NAME);
    // Same order as inventory and role governance; never acquire audit first.
    tx.configuration_lock(crate::cloud_store::KIND, cloud_id).await?;
    let cfg = tx.configuration::<Stored>(crate::cloud_store::KIND, cloud_id).await?;
    tx.configuration_lock("cloud-inventory", cloud_id).await?;
    let snapshot = tx.configuration::<Stored>("cloud-inventory", cloud_id).await?;
    tx.configuration_lock(KIND, record_id(principal.tenant)).await?;
    let saved = tx.configuration::<model::Envelope>(KIND, record_id(principal.tenant)).await?;
    let mut rows = codec::open(state, principal.tenant, saved.as_ref())?;
    if let Some(fact) = reducer::replay(&rows, actor, team, input)? {
        authorize_publication(state, submission).await?;
        return Ok(fact);
    }
    let current =
        source::capture(state, principal.tenant, team, &cfg.ok_or_else(denied)?, &snapshot.ok_or_else(denied)?)?;
    for id in &current.assets {
        source::live_asset(principal.tenant, *id, tx.find(principal.tenant, *id).await?.as_ref())?;
    }
    let fact = reducer::commit(&mut rows, &current, actor, input)?;
    let envelope = codec::seal(state, principal.tenant, &rows)?;
    authorize_publication(state, submission).await?;
    tx.configure(KIND, record_id(principal.tenant), Some(serde_json::to_value(envelope)?)).await?;
    tx.audit(write::audit(principal, &fact)).await?;
    // Tenant/source/inventory/governance locks remain held; recheck original session/current roles after audit wait.
    authorize_publication(state, submission).await?;
    for id in &current.assets {
        source::live_asset(principal.tenant, *id, tx.find(principal.tenant, *id).await?.as_ref())?;
    }
    tx.commit(&state.store).await?;
    Ok(fact)
}
