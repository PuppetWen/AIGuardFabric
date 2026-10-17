use super::{
    model::Values,
    source,
    store::{self, Mutation, Plan},
    util,
};
use crate::{state::AppState, store::asset_transaction::AssetTransaction};
use agf_core::error::DomainResult;

pub(super) async fn mutate<T: Send, F>(state: &AppState, options: Mutation<'_>, apply: F) -> DomainResult<T>
where
    F: FnOnce(&Values) -> DomainResult<(T, Option<Plan>)> + Send,
{
    store::validate(&options)?;
    let tenant = options.submission.principal.tenant;
    let tx = AssetTransaction::begin(state.store.database().ok_or_else(util::corrupt)?, tenant).await?;
    tx.tenant_enabled().await?;
    let cloud = if let Some(s) = options.source {
        tx.configuration_lock(crate::cloud_store::KIND, s.id).await?;
        tx.configuration::<serde_json::Value>(crate::cloud_store::KIND, s.id).await?
    } else {
        None
    };
    if let Some(s) = options.source {
        source::locked(state, s, cloud.as_ref())?;
    }
    let main = util::state_key(tenant);
    tx.configuration_lock(&main.0, main.1).await?;
    let mut snapshot = Values::new();
    snapshot.insert(main.clone(), tx.configuration(&main.0, main.1).await?);
    let mut keys = options.keys.clone();
    keys.sort();
    for (kind, id) in keys {
        if (kind.as_str(), id) == (main.0.as_str(), main.1) {
            continue;
        }
        tx.configuration_lock(&kind, id).await?;
        snapshot.insert((kind.clone(), id), tx.configuration(&kind, id).await?);
    }
    options.submission.authorize(state).await?;
    let (result, plan) = apply(&snapshot)?;
    if let Some(plan) = plan {
        store::validate_plan(state, &options, &snapshot, &plan)?;
        for ((kind, id), value) in plan.writes {
            tx.configure(&kind, id, value).await?;
        }
        tx.audit(*plan.audit).await?;
        options.submission.authorize(state).await?;
        if let Some(s) = options.source {
            source::locked(state, s, cloud.as_ref())?;
        }
        options.submission.budget()?;
    }
    tx.commit(&state.store).await?;
    Ok(result)
}
