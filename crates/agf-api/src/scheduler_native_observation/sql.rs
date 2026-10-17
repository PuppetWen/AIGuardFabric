//! SQL always locks journal before sorted related records, even when an encrypted observation is the main payload.
use super::{
    records::Values,
    scope,
    store::{self, Mutation, Plan},
    util,
};
use crate::{state::AppState, store::asset_transaction::AssetTransaction};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use serde_json::Value;

pub(super) async fn mutate<T, F>(state: &AppState, options: Mutation<'_>, apply: F) -> DomainResult<T>
where
    T: Send,
    F: FnOnce(&Values) -> DomainResult<(T, Option<Plan>)> + Send,
{
    store::validate_options(&options)?;
    let tenant = options.submission.principal.tenant;
    let db = state.store.database().ok_or_else(|| DomainError::Internal("Scheduler SQL 缺少数据库".into()))?;
    let tx = AssetTransaction::begin(db, tenant).await?;
    tx.tenant_enabled().await?;
    let cloud = if let Some(source) = options.source {
        lock_read(&tx, crate::cloud_store::KIND, source.configuration_id).await?
    } else {
        None
    };
    if let Some(source) = options.source {
        scope::validate_locked(state, source, cloud.as_ref())?;
    }
    let journal = util::state_key(tenant);
    let mut snapshot = Values::new();
    snapshot.insert(journal.clone(), lock_read(&tx, &journal.0, journal.1).await?);
    let mut keys = options.declared.clone();
    keys.sort();
    for (kind, id) in keys {
        if (kind.as_str(), id) == (journal.0.as_str(), journal.1) {
            continue;
        }
        snapshot.insert((kind.clone(), id), lock_read(&tx, &kind, id).await?);
    }
    options.submission.authorize(state).await?;
    let (output, plan) = apply(&snapshot)?;
    let Some(plan) = plan else {
        tx.commit(&state.store).await?;
        return Ok(output);
    };
    store::validate_plan(&options, &snapshot, &plan)?;
    for ((kind, id), value) in plan.writes {
        tx.configure(&kind, id, value).await?;
    }
    tx.audit(*plan.audit).await?;
    // Audit tail waits may outlive a permission, original JWT or deadline.
    options.submission.authorize(state).await?;
    if let Some(source) = options.source {
        scope::validate_locked(state, source, cloud.as_ref())?;
    }
    options.submission.budget()?;
    tx.commit(&state.store).await?;
    Ok(output)
}
async fn lock_read(tx: &AssetTransaction<'_>, kind: &str, id: Id) -> DomainResult<Option<Value>> {
    tx.configuration_lock(kind, id).await?;
    tx.configuration::<Value>(kind, id).await
}
