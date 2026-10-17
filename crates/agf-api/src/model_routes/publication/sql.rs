use super::*;
use crate::store::asset_transaction::AssetTransaction;

pub(super) async fn save(
    state: &AppState,
    submission: &Submission,
    policy: &ModelRoutePolicy,
    expected: u64,
    seed: Option<&ModelRoutePolicy>,
) -> DomainResult<()> {
    let db = state.store.database().ok_or_else(corrupt)?;
    // Existing endpoint save/remove also take this actual asset-governance lock before their row locks.
    let tx = AssetTransaction::begin(db, policy.tenant_id).await?;
    tx.tenant_enabled().await?;
    let mut keys = validation::keys(policy)?;
    keys.push((super::super::KIND.into(), policy.id));
    keys.sort();
    let mut rows = Rows::new();
    for (kind, id) in keys {
        tx.configuration_lock(&kind, id).await?;
        rows.insert((kind.clone(), id), tx.configuration::<Value>(&kind, id).await?);
    }
    let current: Option<ModelRoutePolicy> = rows
        .get(&(super::super::KIND.into(), policy.id))
        .cloned()
        .flatten()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| corrupt())?;
    if let Some(row) = &current {
        validation::identity(row, policy.tenant_id, policy.id)?;
    }
    compare(current.as_ref(), seed, expected)?;
    validation::references(policy, &rows)?;
    let log = audit(submission, policy);
    serialized_budget(policy, &log)?;
    submission.authorize(state).await?;
    tx.configure(super::super::KIND, policy.id, Some(serde_json::to_value(policy)?)).await?;
    tx.audit(log).await?;
    // Original JWT/session, current Key/roles, tenant and deadline are checked after the audit-tail wait.
    submission.authorize(state).await?;
    validation::references(policy, &rows)?;
    submission.budget()?;
    tx.commit(&state.store).await
}
