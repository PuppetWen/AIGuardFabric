//! Asset governance -> tenant -> cloud -> dependencies -> signed registry -> main -> related -> audit.
use super::{
    dependencies,
    records::{Main, POLICY, STATE, Values},
    store::{self, Decision, Mutation, Snapshot},
    util,
};
use crate::{model_routes::tenant_record_id, state::AppState, store::asset_transaction::AssetTransaction};
use agf_asset::service::AssetBackend;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use agf_storage::configuration::ConfigurationGuard;
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) async fn mutate<F>(state: &AppState, options: Mutation<'_>, apply: F) -> DomainResult<Main>
where
    F: FnOnce(&mut Main, &Snapshot) -> DomainResult<Decision> + Send,
{
    let tenant = options.submission.principal.tenant;
    let database = state.store.database().ok_or_else(|| DomainError::Internal("发布SQL缺少数据库".into()))?;
    let tx = AssetTransaction::begin(database, tenant).await?;
    tx.tenant_enabled().await?;
    let mut guards = Values::new();
    if let Some(scope) = options.scope {
        lock_read(
            &tx,
            ConfigurationGuard { kind: crate::cloud_store::KIND, id: scope.target.configuration_id },
            &mut guards,
        )
        .await?;
    }
    let mut assets = BTreeMap::new();
    if let Some(selection) = options.selection {
        for key in &selection.guards {
            lock_read(&tx, ConfigurationGuard { kind: key.kind, id: key.id }, &mut guards).await?;
        }
        lock_read(&tx, ConfigurationGuard { kind: POLICY, id: tenant_record_id(tenant) }, &mut guards).await?;
        for id in &selection.agent_ids {
            if let Some(asset) = tx.find(tenant, *id).await? {
                assets.insert(*id, asset);
            }
        }
    }
    if let Some(scope) = options.scope {
        dependencies::validate_locked(state, scope, options.fence, options.source, &guards, &assets)?;
    }
    let main_id = util::main_id(tenant);
    tx.configuration_lock(STATE, main_id).await?;
    let mut main = tx.configuration::<Main>(STATE, main_id).await?.unwrap_or_default();
    let original = main.clone();
    util::initialize(&mut main, tenant)?;
    let mut related =
        options.related.iter().map(|key| ConfigurationGuard { kind: key.kind, id: key.id }).collect::<Vec<_>>();
    related.sort_by_key(|key| (key.kind, key.id));
    let mut originals = Values::new();
    for key in related {
        lock_read(&tx, key, &mut originals).await?;
    }
    options.submission.authorize(state).await?;
    let Decision::Write { related, audit } = apply(&mut main, &Snapshot { related: originals.clone() })? else {
        tx.commit(&state.store).await?;
        return Ok(original);
    };
    store::validate_write(&mut main, tenant, &originals, &related, &audit)?;
    util::batch_bound(tenant, &main, &related, &audit, 8 * 1024 * 1024)?;
    tx.configure(STATE, main_id, Some(serde_json::to_value(&main)?)).await?;
    for ((kind, id), payload) in related {
        tx.configure(&kind, id, payload).await?;
    }
    tx.audit(*audit).await?;
    // The audit tail may be held for a long time. Authority and the original JWT are checked after that wait.
    options.submission.authorize(state).await?;
    if let Some(scope) = options.scope {
        dependencies::validate_locked(state, scope, options.fence, options.source, &guards, &assets)?;
    }
    tx.commit(&state.store).await?;
    Ok(main)
}

async fn lock_read(tx: &AssetTransaction<'_>, key: ConfigurationGuard<'_>, values: &mut Values) -> DomainResult<()> {
    tx.configuration_lock(key.kind, key.id).await?;
    let value = tx.configuration::<Value>(key.kind, key.id).await?;
    values.insert((key.kind.to_owned(), key.id), value);
    Ok(())
}

pub(super) fn key(kind: &'static str, id: Id) -> ConfigurationGuard<'static> {
    ConfigurationGuard { kind, id }
}
