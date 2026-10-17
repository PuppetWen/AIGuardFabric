//! Original evidence, source CAS, annotation/request facts and success audit share one SQL transaction.
use super::{
    FailureEvidence,
    codec::{self, Values},
    source,
    store::{self, Mutation, Plan, Snapshot},
    util,
};
use crate::{state::AppState, store::asset_transaction::AssetTransaction};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) async fn mutate<T, F>(state: &AppState, options: Mutation<'_>, apply: F) -> DomainResult<T>
where
    T: Send,
    F: FnOnce(&Snapshot) -> DomainResult<(T, Option<Plan>)> + Send,
{
    let tenant = options.submission.principal.tenant;
    let db = state.store.database().ok_or_else(util::corrupt)?;
    let tx = AssetTransaction::begin(db, tenant).await?;
    tx.tenant_enabled().await?;
    let cloud = read(&tx, crate::cloud_store::KIND, source::cloud_id(tenant)).await?;
    let mut sources = BTreeMap::new();
    let mut source_ids = options.source_ids.clone();
    source_ids.sort();
    for id in source_ids {
        sources.insert(id, read(&tx, crate::source_store::KIND, id).await?);
    }
    // Official ingest evidence is immutable. FOR SHARE also excludes direct deletion/change until commit.
    let mut evidence = options.evidence.iter().collect::<Vec<_>>();
    evidence.sort_by_key(|row| row.event_id);
    for expected in evidence {
        let row = tx.agentteams_failure_record(expected.event_id).await?.ok_or_else(|| DomainError::NotFound {
            entity: "collector-task-error",
            id: expected.event_id.to_string(),
        })?;
        if FailureEvidence::derive(tenant, &row)? != *expected {
            return Err(util::corrupt());
        }
    }
    let main = codec::state_key(tenant);
    let mut records = Values::new();
    records.insert(main.clone(), read(&tx, &main.0, main.1).await?);
    let mut keys = options.declared.clone();
    keys.sort();
    for (kind, id) in keys {
        records.insert((kind.clone(), id), read(&tx, &kind, id).await?);
    }
    options.submission.authorize(state).await?;
    let snapshot = Snapshot { records, cloud, sources };
    let (output, plan) = apply(&snapshot)?;
    let Some(plan) = plan else {
        options.submission.budget()?;
        tx.commit(&state.store).await?;
        return Ok(output);
    };
    store::validate_plan(state, &options, &snapshot, &plan)?;
    for ((kind, id), value) in plan.writes {
        tx.configure(&kind, id, value).await?;
    }
    tx.audit(*plan.audit).await?;
    // Long audit-tail waits cannot authorize with an expired token or removed current grant.
    options.submission.authorize(state).await?;
    options.submission.budget()?;
    tx.commit(&state.store).await?;
    Ok(output)
}
async fn read(tx: &AssetTransaction<'_>, kind: &str, id: Id) -> DomainResult<Option<Value>> {
    tx.configuration_lock(kind, id).await?;
    tx.configuration(kind, id).await
}
