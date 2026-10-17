//! SQL locks asset governance, tenant, dependencies, policy registry, then the audit chain.
use super::*;
use crate::store::asset_transaction::AssetTransaction;
use agf_asset::service::AssetBackend;
use serde_json::Value;

pub(super) async fn execute(
    state: &AppState,
    submission: mutation::Submission<'_>,
    change: change::Change,
) -> DomainResult<Policy> {
    let tenant = submission.tenant;
    let db = state.store.database().ok_or_else(|| DomainError::Internal("策略SQL提交缺少数据库".into()))?;
    let tx = AssetTransaction::begin(db, tenant).await?;
    tx.tenant_enabled().await?;
    let mut dependencies = validation::GuardValues::new();
    for key in validation::guards(change.candidate(), tenant) {
        tx.configuration_lock(key.kind, key.id).await?;
        dependencies.insert((key.kind.into(), key.id), tx.configuration::<Value>(key.kind, key.id).await?);
    }
    tx.configuration_lock(KIND, tenant_record_id(tenant)).await?;
    let mut rows = tx.configuration::<registry::Registry>(KIND, tenant_record_id(tenant)).await?.unwrap_or_default();
    let signer = signer(state)?;
    rows.initialize(tenant, state.store.policy_list(tenant)?, &signer)?;
    if let Some(policy) = change.candidate() {
        validation::dependencies(policy, tenant, &dependencies)?;
        let mut ids = policy.scope_agent_ids.clone();
        ids.sort();
        for id in ids {
            validation::agent(tenant, id, tx.find(tenant, id).await?.as_ref())?;
        }
    }
    let action = change.action();
    let (saved, audit) = change.apply(&mut rows, tenant, &signer, submission.actor())?;
    let payload = serde_json::to_value(&rows)?;
    submission.authorize(state, action).await?;
    tx.configure(KIND, tenant_record_id(tenant), Some(payload)).await?;
    tx.audit(audit).await?;
    // Audit insertion can wait behind another writer. Recheck the original session and current key/roles after that wait.
    submission.authorize(state, action).await?;
    tx.commit(&state.store).await?;
    Ok(saved)
}
