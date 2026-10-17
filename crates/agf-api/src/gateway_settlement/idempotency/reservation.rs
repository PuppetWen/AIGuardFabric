//! Index and lifetime capacity commit with the existing quota/Facts admission transaction.
use super::{
    Binding, CAPACITY, Duplicate, INDEX, identity,
    model::{Capacity, Entry},
};
use crate::{
    gateway_settlement::{
        authority::Submission,
        records::{FACT, Fact},
        store,
    },
    model_routes::tenant_record_id,
    state::AppState,
    store::asset_transaction::AssetTransaction,
};
use agf_core::{
    error::DomainResult,
    ids::{Id, TenantId},
};
use serde_json::Value;
use std::collections::BTreeMap;

pub(in crate::gateway_settlement) async fn existing(
    state: &AppState,
    tx: &AssetTransaction<'_>,
    submission: &Submission<'_>,
    binding: &Binding,
) -> DomainResult<Option<Duplicate>> {
    let tenant = submission.principal.tenant;
    let Some(raw) = tx.admission_key_record(INDEX, binding.id).await? else { return Ok(None) };
    let entry: Entry = store::decode(state, tenant, binding.id, INDEX, raw)?;
    entry.validate(binding.id, &binding.namespace)?;
    // Missing read permission cannot turn an occupied key into an absent key.
    let current = submission.current_models(state, entry.owner()).await?;
    current.require(state, "models", "read").map_err(|error| error.error)?;
    let fact: Fact = store::decode(
        state,
        tenant,
        entry.attempt(),
        FACT,
        store::read(tx, FACT, entry.attempt()).await?.ok_or_else(identity::corrupt)?,
    )?;
    entry.fact(&fact)?;
    let current = submission.current_models(state, entry.owner()).await?;
    current.require(state, "models", "read").map_err(|error| error.error)?;
    Ok(Some(Duplicate {
        attempt: entry.attempt(),
        same_input: entry.matches(binding),
        owner: Box::new(entry.owner().clone()),
    }))
}

pub(in crate::gateway_settlement) async fn append(
    state: &AppState,
    tx: &AssetTransaction<'_>,
    tenant: TenantId,
    binding: &Binding,
    fact: &Fact,
    writes: &mut BTreeMap<(&'static str, Id), Value>,
) -> DomainResult<()> {
    let key = tenant_record_id(tenant);
    let current = tx
        .admission_key_record(CAPACITY, key)
        .await?
        .map(|value| store::decode::<Capacity>(state, tenant, key, CAPACITY, value))
        .transpose()?;
    let next = Capacity::next(current, tenant, tx.admission_key_count().await?)?;
    let entry = Entry::new(binding, fact)?;
    writes.insert((INDEX, binding.id), store::encoded(state, tenant, binding.id, INDEX, &entry)?);
    writes.insert((CAPACITY, key), store::encoded(state, tenant, key, CAPACITY, &next)?);
    Ok(())
}
