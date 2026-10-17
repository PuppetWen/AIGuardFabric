//! An internal immutable claim can retain a known ACK after authority changes; it grants no execution.
use super::super::util;
use super::{
    codec, current,
    model::{Known, Operation, State},
};
use crate::{state::AppState, store::asset_transaction::AssetTransaction};
use agf_alicloud::schedulerx3::managed_jobs::{Readback, WriteEvidence};
use agf_core::{
    error::{DomainError, DomainResult},
    time::Timestamp,
};

pub(super) async fn persist(
    state: &AppState,
    original: &Operation,
    write: WriteEvidence,
    readback: Readback,
) -> DomainResult<Option<Known>> {
    // This short local-only deadline never authorizes or renews a provider call.
    tokio::time::timeout(std::time::Duration::from_secs(15), persist_inner(state, original, write, readback))
        .await
        .map_err(|_| DomainError::Timeout("本地结果封存超时；请读取原编号，禁止重派".into()))?
}
async fn persist_inner(
    state: &AppState,
    original: &Operation,
    write: WriteEvidence,
    readback: Readback,
) -> DomainResult<Option<Known>> {
    codec::operation(original, original.tenant, original.request_id)?;
    if original.target.mocked || original.state != State::Started {
        return Err(util::corrupt());
    }
    let db = state.store.database().ok_or_else(util::corrupt)?;
    let tenant = original.tenant;
    let tx = AssetTransaction::begin(db, tenant).await?;
    let native = util::state_key(tenant);
    tx.configuration_lock(&native.0, native.1).await?;
    let operation_key = codec::key(tenant, original.request_id, super::model::OPERATION);
    let pending_key = codec::key(tenant, original.request_id, super::model::PENDING);
    let mut keys = vec![codec::state_key(tenant), operation_key.clone(), pending_key.clone()];
    keys.sort();
    for (kind, id) in keys {
        tx.configuration_lock(&kind, id).await?;
    }
    let value = tx.configuration(&operation_key.0, operation_key.1).await?.ok_or_else(util::corrupt)?;
    let row: Operation = codec::decode(state, tenant, &operation_key, &value)?;
    codec::operation(&row, tenant, original.request_id)?;
    if !current::same_claim(&row, original)? {
        return Err(super::conflict());
    }
    if row.state == State::Complete {
        return Ok(None);
    }
    let journal_key = codec::state_key(tenant);
    let value = tx.configuration(&journal_key.0, journal_key.1).await?.ok_or_else(util::corrupt)?;
    let journal: super::model::Journal = codec::decode(state, tenant, &journal_key, &value)?;
    super::model::validate_journal(&journal, tenant)?;
    if !journal.operations.contains(&row.request_id)
        || journal
            .active
            .as_ref()
            .is_none_or(|active| (active.request_id, active.claim_id) != (row.request_id, row.claim_id))
    {
        return Err(util::corrupt());
    }
    let known = if let Some(value) = tx.configuration(&pending_key.0, pending_key.1).await? {
        let known: Known = codec::decode(state, tenant, &pending_key, &value)?;
        codec::known(&known, &row)?;
        if known.write != write || known.readback != readback {
            return Err(super::conflict());
        }
        known
    } else {
        let known = Known {
            domain: "agf.scheduler.managed.known.v1".into(),
            tenant,
            request_id: row.request_id,
            claim_id: row.claim_id,
            input_hash: row.input_hash.clone(),
            write,
            readback,
            job_id: row.job_id.clone(),
            staged_at: Timestamp::now(),
        };
        codec::known(&known, &row)?;
        tx.configure(&pending_key.0, pending_key.1, Some(codec::seal(state, tenant, &pending_key, &known)?)).await?;
        known
    };
    // Original facts and the claim/body hash are AEAD verified; no authorization or successful audit is invented here.
    tx.commit(&state.store).await?;
    Ok(Some(known))
}
pub(super) async fn read(state: &AppState, row: &Operation) -> DomainResult<Option<Known>> {
    let key = codec::key(row.tenant, row.request_id, super::model::PENDING);
    let known = codec::load::<Known>(state, row.tenant, &key).await?;
    if let Some(known) = &known {
        codec::known(known, row)?;
    }
    Ok(known)
}
