//! SQL retains the same tenant/asset governance ordering as inventory publication.
use super::{
    KIND, archive,
    archive_store::{self, Related},
    contract::{Record, Scope},
    guard, scope, store, store_sql,
};
use crate::{Principal, state::AppState, store::asset_transaction::AssetTransaction};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
    time::Timestamp,
};
use agf_storage::configuration::BatchDecision;
use std::collections::BTreeMap;

pub(super) async fn mutate<F>(
    state: &AppState,
    principal: &Principal,
    expected: Option<&Scope>,
    ids: &[Id],
    submitted_at: Timestamp,
    apply: F,
) -> DomainResult<Record>
where
    F: FnOnce(&mut Record, &Related) -> DomainResult<BatchDecision> + Send,
{
    let tenant = principal.tenant;
    let input_count = ids.len();
    let mut ids = ids.to_vec();
    ids.sort();
    ids.dedup();
    if ids.len() > 100 || ids.len() != input_count {
        return Err(DomainError::Validation("MSE 归档最多100个唯一编号".into()));
    }
    let db = state.store.database().ok_or_else(scope::stale)?;
    let tx = AssetTransaction::begin(db, tenant).await?;
    tx.tenant_enabled().await?;
    if let Some(expected) = expected {
        store_sql::guarded(&tx, state, tenant, expected).await?;
    }
    let id = crate::integration_store::id(tenant, super::NAME);
    tx.configuration_lock(KIND, id).await?;
    let mut row = tx.configuration::<Record>(KIND, id).await?.unwrap_or_default();
    let previous = serde_json::to_value(&row)?;
    let mut related = BTreeMap::new();
    for id in &ids {
        tx.configuration_lock(archive::KIND, *id).await?;
        related.insert(*id, tx.configuration(archive::KIND, *id).await?);
    }
    guard::authorize(state, principal, submitted_at).await?;
    let BatchDecision::Write { related, audit } = apply(&mut row, &related)? else {
        tx.commit(&state.store).await?;
        return Ok(serde_json::from_value(previous)?);
    };
    archive_store::validate_candidates(tenant, &ids, &related, audit.as_deref())?;
    let payload = serde_json::from_slice(&store::bounded(&row)?)?;
    tx.configure(KIND, id, Some(payload)).await?;
    for (id, payload) in related {
        tx.configure(archive::KIND, id, Some(payload)).await?;
    }
    if let Some(audit) = audit {
        tx.audit(*audit).await?;
    }
    guard::authorize(state, principal, submitted_at).await?;
    tx.commit(&state.store).await?;
    Ok(row)
}
