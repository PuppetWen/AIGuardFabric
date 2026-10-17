//! Known local results are durable before the terminal audit and never grant another execution.
use super::super::{authority::Submission, util};
use super::{
    current, evidence, identity,
    input::Outcome,
    model::{Fact, Pending, State},
};
use crate::{state::AppState, store::asset_transaction::AssetTransaction};
use agf_core::{error::DomainResult, ids::TenantId, time::Timestamp};
use agf_storage::crypto::FieldCipher;
use serde::{Deserialize, Serialize};

const DOMAIN: &str = "agf.scheduler.callback.known-outcome.v1";
const MAX_STAGE: usize = 64 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Known {
    pub domain: String,
    pub original: Fact,
    pub outcome: Outcome,
    pub staged_at: Timestamp,
}
pub(super) fn original(row: &Fact) -> Fact {
    let mut original = row.clone();
    original.state = State::Running;
    original.finished_at = None;
    original.outcome = None;
    original.outcome_hash = None;
    original.seal = None;
    original
}
pub(super) fn validate(known: &Known, row: &Fact) -> DomainResult<()> {
    known.original.validate(row.context.tenant, row.id)?;
    known.outcome.validate().map_err(|_| util::corrupt())?;
    if known.domain != DOMAIN
        || !same_original(&known.original, row)?
        || known.original.state != State::Running
        || known.original.started_at.is_none_or(|at| known.staged_at < at)
        || known.staged_at > Timestamp::now().offset_secs(30)
    {
        return Err(util::corrupt());
    }
    util::bound(known, MAX_STAGE / 2)?;
    Ok(())
}
pub(super) fn same_original(left: &Fact, right: &Fact) -> DomainResult<bool> {
    Ok(serde_json::to_value(original(left))? == serde_json::to_value(original(right))?)
}
pub(super) fn decode(state: &AppState, row: &Fact, pending: &Pending) -> DomainResult<Known> {
    decode_with_cipher(&crate::model_gateway::cipher(state)?, row, pending)
}
pub(super) fn decode_with_cipher(cipher: &FieldCipher, row: &Fact, pending: &Pending) -> DomainResult<Known> {
    if (pending.tenant, pending.fact_id, pending.claim_id) != (row.context.tenant, row.id, row.claim_id)
        || !util::digest(&pending.hash)
    {
        return Err(util::corrupt());
    }
    util::bound(pending, MAX_STAGE)?;
    let key = identity::pending_key(row.id);
    let known: Known =
        serde_json::from_value(util::decode_secret(cipher, row.context.tenant, key.1, &pending.secret, &pending.hash)?)
            .map_err(|_| util::corrupt())?;
    validate(&known, row)?;
    Ok(known)
}
pub(super) async fn persist(
    state: &AppState,
    submission: &Submission,
    row: &Fact,
    outcome: Outcome,
) -> DomainResult<Known> {
    super::super::authority::bounded(submission.deadline, Box::pin(persist_inner(state, submission, row, outcome)))
        .await
}
async fn persist_inner(state: &AppState, submission: &Submission, row: &Fact, outcome: Outcome) -> DomainResult<Known> {
    current::owner(state, submission, &row.context.owner).await?;
    let tenant = row.context.tenant;
    let db = state.store.database().ok_or_else(current::unqualified)?;
    let tx = AssetTransaction::begin(db, tenant).await?;
    tx.tenant_enabled().await?;
    let journal = util::state_key(tenant);
    tx.configuration_lock(&journal.0, journal.1).await?;
    let key = identity::pending_key(row.id);
    let mut keys = vec![identity::fact_key(row.id), key.clone()];
    keys.sort();
    for (kind, id) in keys {
        tx.configuration_lock(&kind, id).await?;
    }
    let fact: Fact = tx.configuration(super::model::EXECUTION, row.id).await?.ok_or_else(util::corrupt)?;
    if fact.context.tenant != tenant || fact.id != row.id {
        return Err(util::corrupt());
    }
    evidence::verify_fact(state, &fact)?;
    current::owner(state, submission, &fact.context.owner).await?;
    if fact.claim_id != row.claim_id || !same_original(&fact, row)? {
        return Err(current::conflict());
    }
    if fact.started_at.is_none() {
        return Err(current::unqualified());
    }
    let pending: Option<Pending> = tx.configuration(&key.0, key.1).await?;
    let known = if let Some(pending) = pending {
        let known = decode(state, &fact, &pending)?;
        if known.outcome != outcome {
            return Err(current::conflict());
        }
        known
    } else {
        if fact.state != State::Running {
            return Err(util::corrupt());
        }
        let known = Known { domain: DOMAIN.into(), original: original(&fact), outcome, staged_at: Timestamp::now() };
        validate(&known, &fact)?;
        let (secret, hash) = util::encrypt_json(state, tenant, key.1, &serde_json::to_value(&known)?)?;
        let pending = Pending { tenant, fact_id: fact.id, claim_id: fact.claim_id, hash, secret };
        util::bound(&pending, MAX_STAGE)?;
        tx.configure(&key.0, key.1, Some(serde_json::to_value(pending)?)).await?;
        known
    };
    current::owner(state, submission, &fact.context.owner).await?;
    submission.budget()?;
    tx.commit(&state.store).await?;
    Ok(known)
}
pub(super) async fn read(state: &AppState, tenant: TenantId, row: &Fact) -> DomainResult<Option<Known>> {
    let pending = super::super::store::get::<Pending>(state, tenant, &identity::pending_key(row.id)).await?;
    pending.as_ref().map(|value| decode(state, row, value)).transpose()
}
