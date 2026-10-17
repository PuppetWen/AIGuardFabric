//! A local retained result carries no new cloud authorization or successful business audit.
use super::{
    FACT, PENDING, codec,
    model::{Fact, Pending, Phase, ResultData},
    records, util,
};
use crate::{state::AppState, store::asset_transaction::AssetTransaction};
use agf_core::error::{DomainError, DomainResult};
pub(super) async fn persist(state: &AppState, original: &Fact, outcome: ResultData) -> DomainResult<()> {
    tokio::time::timeout(std::time::Duration::from_secs(15), Box::pin(inner(state, original, outcome))).await.map_err(
        |_| {
            DomainError::Timeout(
                "PrivateLink local result retention expired; never re-dispatch the original UUID".into(),
            )
        },
    )?
}
async fn inner(state: &AppState, original: &Fact, outcome: ResultData) -> DomainResult<()> {
    if original.phase != Phase::Started || original.source.as_ref().is_none_or(|s| s.mode == "mock") {
        return Err(util::corrupt());
    }
    let tenant = original.tenant;
    let tx = AssetTransaction::begin(state.store.database().ok_or_else(util::corrupt)?, tenant).await?;
    let main = util::state_key(tenant);
    tx.configuration_lock(&main.0, main.1).await?;
    let fact = util::key(FACT, original.id);
    let key = util::key(PENDING, original.id);
    let mut keys = vec![fact.clone(), key.clone()];
    keys.sort();
    for (k, id) in keys {
        tx.configuration_lock(&k, id).await?;
    }
    let current: Fact =
        codec::decode(state, tenant, &fact, &tx.configuration(&fact.0, fact.1).await?.ok_or_else(util::corrupt)?)?;
    records::validate(&current, tenant, current.id)?;
    if records::claim_hash(&current)? != records::claim_hash(original)? {
        return Err(util::conflict());
    }
    if current.phase == Phase::Complete {
        return Ok(());
    }
    if current.phase != Phase::Started || current.archived_at.is_some() {
        return Err(util::conflict());
    }
    let pending = Pending { tenant, fact_id: original.id, claim_hash: records::claim_hash(original)?, outcome };
    validate(&pending, &current)?;
    if let Some(value) = tx.configuration(&key.0, key.1).await? {
        let old: Pending = codec::decode(state, tenant, &key, &value)?;
        validate(&old, &current)?;
        if util::fingerprint(&old)? != util::fingerprint(&pending)? {
            return Err(util::conflict());
        }
    } else {
        tx.configure(&key.0, key.1, Some(codec::encode(state, tenant, &key, &pending)?)).await?;
    }
    tx.commit(&state.store).await?;
    Ok(())
}
pub(super) fn validate(pending: &Pending, row: &Fact) -> DomainResult<()> {
    let fact_matches = pending.fact_id == row.id;
    if pending.tenant != row.tenant || !fact_matches || pending.claim_hash != records::claim_hash(row)? {
        return Err(util::corrupt());
    }
    let mut copy = row.clone();
    copy.phase = Phase::Complete;
    copy.result = Some(pending.outcome.clone());
    records::validate(&copy, copy.tenant, copy.id)
}
