//! Internal known-result retention grants no dispatch or successful business audit.
use super::{
    ATTEMPT, ITEM, PENDING, codec,
    model::{Attempt, Item, Outcome, Pending, Phase},
    provider, records, store, util,
};
use crate::{state::AppState, store::asset_transaction::AssetTransaction};
use agf_core::error::{DomainError, DomainResult};

pub(super) async fn persist(state: &AppState, original: &Attempt, outcome: Outcome) -> DomainResult<()> {
    tokio::time::timeout(std::time::Duration::from_secs(15), Box::pin(inner(state, original, outcome))).await.map_err(
        |_| DomainError::Timeout("CMS local result retention expired; never resend the original claim".into()),
    )?
}
async fn inner(state: &AppState, original: &Attempt, outcome: Outcome) -> DomainResult<()> {
    if original.phase != Phase::Started || original.source.mode == "mock" {
        return Err(util::corrupt());
    }
    let tenant = original.tenant;
    let tx = AssetTransaction::begin(state.store.database().ok_or_else(util::corrupt)?, tenant).await?;
    let main = util::state_key(tenant);
    tx.configuration_lock(&main.0, main.1).await?;
    let item_key = util::key(ITEM, original.item_id);
    let attempt_key = util::key(ATTEMPT, original.id);
    let pending_key = util::key(PENDING, original.id);
    let mut keys = vec![item_key.clone(), attempt_key.clone(), pending_key.clone()];
    keys.sort();
    for (kind, id) in keys {
        tx.configuration_lock(&kind, id).await?;
    }
    let item: Item = codec::decode(
        state,
        tenant,
        &item_key,
        &tx.configuration(&item_key.0, item_key.1).await?.ok_or_else(util::corrupt)?,
    )?;
    records::item(&item, tenant, item.id)?;
    let current: Attempt = codec::decode(
        state,
        tenant,
        &attempt_key,
        &tx.configuration(&attempt_key.0, attempt_key.1).await?.ok_or_else(util::corrupt)?,
    )?;
    records::attempt(&current, &item)?;
    if !provider::same_claim(&current, original)? {
        return Err(util::conflict());
    }
    if current.phase == Phase::Complete {
        return Ok(());
    }
    if current.phase != Phase::Started || item.archived_at.is_some() || item.attempts.last() != Some(&original.id) {
        return Err(util::corrupt());
    }
    let pending = Pending { attempt: original.clone(), outcome };
    validate(&pending, &current, &item)?;
    if let Some(value) = tx.configuration(&pending_key.0, pending_key.1).await? {
        let old: Pending = codec::decode(state, tenant, &pending_key, &value)?;
        validate(&old, &current, &item)?;
        if util::fingerprint(&old)? != util::fingerprint(&pending)? {
            return Err(util::conflict());
        }
    } else {
        tx.configure(&pending_key.0, pending_key.1, Some(codec::encode(state, tenant, &pending_key, &pending)?))
            .await?;
    }
    tx.commit(&state.store).await?;
    Ok(())
}
pub(super) fn validate(pending: &Pending, row: &Attempt, item: &Item) -> DomainResult<()> {
    records::attempt(&pending.attempt, item)?;
    if pending.attempt.phase != Phase::Started || !provider::same_claim(row, &pending.attempt)? {
        return Err(util::corrupt());
    }
    let mut complete = row.clone();
    complete.phase = Phase::Complete;
    complete.outcome = Some(pending.outcome.clone());
    records::attempt(&complete, item)
}
pub(super) async fn read(state: &AppState, row: &Attempt, item: &Item) -> DomainResult<Option<Pending>> {
    let pending = store::get::<Pending>(state, row.tenant, &util::key(PENDING, row.id)).await?;
    if let Some(pending) = &pending {
        validate(pending, row, item)?;
    }
    Ok(pending)
}
