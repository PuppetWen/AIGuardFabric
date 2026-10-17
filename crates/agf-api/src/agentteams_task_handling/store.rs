//! Source CAS, encrypted candidates and local success audit publish together.
use super::{
    FailureEvidence,
    authority::{self, Submission},
    codec::{self, Key, Values},
    source, sql, util,
};
use crate::{policy_store::OfflinePublicationProof, state::AppState};
use agf_core::{
    audit::AuditLog,
    error::DomainResult,
    ids::{Id, TenantId},
};
use agf_storage::configuration::{ConfigurationGuard, GuardedBatchDecision, OfflineGuardedBatch};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct Mutation<'a> {
    pub(super) submission: &'a Submission,
    pub(super) source_ids: Vec<Id>,
    pub(super) evidence: Vec<FailureEvidence>,
    pub(super) declared: Vec<Key>,
}
pub(super) struct Snapshot {
    pub(super) records: Values,
    pub(super) cloud: Option<Value>,
    pub(super) sources: BTreeMap<Id, Option<Value>>,
}
pub(super) struct Plan {
    pub(super) writes: Values,
    pub(super) audit: Box<AuditLog>,
}
pub(super) async fn get(state: &AppState, tenant: TenantId, key: &Key) -> DomainResult<Option<Value>> {
    state.configurations.get(tenant, &key.0, key.1).await
}
pub(super) async fn mutate<T, F>(state: &AppState, options: Mutation<'_>, apply: F) -> DomainResult<T>
where
    T: Send,
    F: FnOnce(&Snapshot) -> DomainResult<(T, Option<Plan>)> + Send,
{
    authority::bounded(options.submission.deadline, mutate_inner(state, options, apply)).await
}
async fn mutate_inner<T, F>(state: &AppState, options: Mutation<'_>, apply: F) -> DomainResult<T>
where
    T: Send,
    F: FnOnce(&Snapshot) -> DomainResult<(T, Option<Plan>)> + Send,
{
    validate_options(&options)?;
    options.submission.authorize(state).await?;
    if state.store.database().is_some() {
        return sql::mutate(state, options, apply).await;
    }
    let submission = options.submission.borrowed();
    let proof = OfflinePublicationProof::prepare(state, &submission).await?;
    let tenant = submission.principal.tenant;
    let main = codec::state_key(tenant);
    let guards = std::iter::once(ConfigurationGuard { kind: crate::cloud_store::KIND, id: source::cloud_id(tenant) })
        .chain(options.source_ids.iter().map(|id| ConfigurationGuard { kind: crate::source_store::KIND, id: *id }))
        .collect::<Vec<_>>();
    let related = options
        .declared
        .iter()
        .map(|(kind, id)| ConfigurationGuard { kind: kind.as_str(), id: *id })
        .collect::<Vec<_>>();
    let mut result = None;
    state.configurations.mutate_offline_guarded_batch_audited(
        tenant,
        OfflineGuardedBatch {
            kind: &main.0,
            id: main.1,
            guards: &guards,
            security: Some(OfflinePublicationProof::security(&submission)?),
            related: &related,
            max_main_bytes: 4 * 1024 * 1024,
            max_related_bytes: 1024 * 1024,
            max_total_write_bytes: 8 * 1024 * 1024,
        },
        |locked, current: &mut Value, originals| {
            let mut records = originals.clone();
            records.insert(main.clone(), if current.is_null() { None } else { Some(current.clone()) });
            let snapshot = Snapshot {
                records,
                cloud: locked
                    .guards
                    .get(&(crate::cloud_store::KIND.into(), source::cloud_id(tenant)))
                    .cloned()
                    .flatten(),
                sources: options
                    .source_ids
                    .iter()
                    .map(|id| (*id, locked.guards.get(&(crate::source_store::KIND.into(), *id)).cloned().flatten()))
                    .collect(),
            };
            let (output, plan) = apply(&snapshot)?;
            result = Some(output);
            let Some(plan) = plan else { return Ok(GuardedBatchDecision::Unchanged) };
            validate_plan(state, &options, &snapshot, &plan)?;
            let mut writes = plan.writes;
            *current = writes.remove(&main).flatten().ok_or_else(util::corrupt)?;
            Ok(GuardedBatchDecision::Write { related: writes, audit: plan.audit })
        },
        |audit, locked| {
            proof.check(state, &submission, locked)?;
            options.submission.budget()?;
            state.store.audit_append(audit)
        },
    )?;
    result.ok_or_else(util::corrupt)
}
pub(super) fn validate_options(options: &Mutation<'_>) -> DomainResult<()> {
    let tenant = options.submission.principal.tenant;
    let sources = options.source_ids.iter().collect::<BTreeSet<_>>();
    let keys = options.declared.iter().collect::<BTreeSet<_>>();
    let ids = options.evidence.iter().map(|row| row.event_id).collect::<BTreeSet<_>>();
    if sources.len() != options.source_ids.len()
        || sources.len() > super::MAX_SOURCE_GUARDS
        || sources.iter().any(|id| id.is_nil())
        || keys.len() != options.declared.len()
        || keys.len() > 100
        || ids.len() != options.evidence.len()
        || ids.is_empty()
        || ids.len() > super::MAX_ARCHIVE
    {
        return Err(util::invalid());
    }
    for evidence in &options.evidence {
        evidence.validate()?;
        if evidence.tenant != tenant || !sources.contains(&evidence.source_id) {
            return Err(util::corrupt());
        }
    }
    for (kind, id) in &options.declared {
        if id.is_nil() || ![codec::RECORD, codec::REQUEST].contains(&kind.as_str()) {
            return Err(util::corrupt());
        }
    }
    Ok(())
}
pub(super) fn validate_plan(
    state: &AppState,
    options: &Mutation<'_>,
    snapshot: &Snapshot,
    plan: &Plan,
) -> DomainResult<()> {
    let tenant = options.submission.principal.tenant;
    let main = codec::state_key(tenant);
    if plan.audit.tenant_id != tenant
        || plan.audit.id.is_nil()
        || plan.writes.get(&main).and_then(Option::as_ref).is_none()
    {
        return Err(util::corrupt());
    }
    for (key, value) in &plan.writes {
        if !snapshot.records.contains_key(key) || value.is_none() {
            return Err(util::corrupt());
        }
        util::bounded(value, if *key == main { 4 * 1024 * 1024 } else { 1024 * 1024 })?;
    }
    codec::journal(state, tenant, &plan.writes)?;
    batch_bound(tenant, &plan.writes, &plan.audit)
}

pub(super) fn batch_bound(tenant: TenantId, writes: &Values, audit: &AuditLog) -> DomainResult<()> {
    let entries = writes
        .iter()
        .map(|((kind, id), payload)| {
            serde_json::json!({
        "tenant":tenant,"kind":kind,"id":id,"delete":payload.is_none(),"payload":payload})
        })
        .collect::<Vec<_>>();
    let mut sealed = audit.clone();
    sealed.sequence = i64::MAX;
    sealed.prev_hash = "0".repeat(64);
    sealed.entry_hash = "0".repeat(64);
    util::bounded(&(entries, sealed), 8 * 1024 * 1024)
}
