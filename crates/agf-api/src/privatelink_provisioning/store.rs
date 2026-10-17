use super::{
    authority::Submission,
    codec,
    model::{Journal, Key, Values},
    source::{self, Source},
    sql, util,
};
use crate::{policy_store::OfflinePublicationProof, state::AppState};
use agf_core::{audit::AuditLog, error::DomainResult, ids::TenantId};
use agf_storage::configuration::{ConfigurationGuard, GuardedBatchDecision, OfflineGuardedBatch};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::BTreeSet;

pub(super) struct Mutation<'a> {
    pub submission: &'a Submission,
    pub source: Option<&'a Source>,
    pub guards: Vec<agf_storage::configuration::ConfigurationGuard<'a>>,
    pub keys: Vec<Key>,
}
pub(super) struct Plan {
    pub writes: Values,
    pub audit: Box<AuditLog>,
}
pub(super) async fn get<T: DeserializeOwned>(state: &AppState, tenant: TenantId, key: &Key) -> DomainResult<Option<T>> {
    state
        .configurations
        .get::<Value>(tenant, &key.0, key.1)
        .await?
        .map(|value| codec::decode(state, tenant, key, &value))
        .transpose()
}
pub(super) async fn journal(state: &AppState, tenant: TenantId) -> DomainResult<Journal> {
    let row = get(state, tenant, &util::state_key(tenant)).await?.unwrap_or_default();
    util::validate_journal(&row, tenant)?;
    Ok(row)
}
pub(super) async fn mutate<T: Send, F>(state: &AppState, options: Mutation<'_>, apply: F) -> DomainResult<T>
where
    F: FnOnce(&Values) -> DomainResult<(T, Option<Plan>)> + Send,
{
    super::authority::bounded(options.submission.deadline, Box::pin(inner(state, options, apply))).await
}
async fn inner<T: Send, F>(state: &AppState, options: Mutation<'_>, apply: F) -> DomainResult<T>
where
    F: FnOnce(&Values) -> DomainResult<(T, Option<Plan>)> + Send,
{
    validate(&options)?;
    if state.store.database().is_some() {
        return Box::pin(sql::mutate(state, options, apply)).await;
    }
    let tenant = options.submission.principal.tenant;
    let submission = options.submission.borrowed();
    let proof = OfflinePublicationProof::prepare(state, &submission).await?;
    let main = util::state_key(tenant);
    let mut guards = options
        .source
        .map(|s| ConfigurationGuard { kind: crate::cloud_store::KIND, id: s.id })
        .into_iter()
        .collect::<Vec<_>>();
    guards.extend(options.guards.iter().map(|g| ConfigurationGuard { kind: g.kind, id: g.id }));
    let related = options
        .keys
        .iter()
        .filter(|k| **k != main)
        .map(|(kind, id)| ConfigurationGuard { kind, id: *id })
        .collect::<Vec<_>>();
    let mut output = None;
    state.configurations.mutate_offline_guarded_batch_audited(
        tenant,
        OfflineGuardedBatch {
            kind: &main.0,
            id: main.1,
            guards: &guards,
            related: &related,
            security: Some(OfflinePublicationProof::security(&submission)?),
            max_main_bytes: 4 * 1024 * 1024,
            max_related_bytes: 1024 * 1024,
            max_total_write_bytes: 8 * 1024 * 1024,
        },
        |locked, value: &mut Value, originals| {
            if let Some(s) = options.source {
                source::locked(
                    state,
                    s,
                    locked.guards.get(&(crate::cloud_store::KIND.into(), s.id)).and_then(Option::as_ref),
                )?;
            }
            let mut snapshot = originals.clone();
            snapshot.extend(locked.guards.clone());
            snapshot.insert(main.clone(), if value.is_null() { None } else { Some(value.clone()) });
            let (result, plan) = apply(&snapshot)?;
            output = Some(result);
            let Some(plan) = plan else {
                return Ok(GuardedBatchDecision::Unchanged);
            };
            validate_plan(state, &options, &snapshot, &plan)?;
            let mut writes = plan.writes;
            *value = writes.remove(&main).flatten().ok_or_else(util::corrupt)?;
            Ok(GuardedBatchDecision::Write { related: writes, audit: plan.audit })
        },
        |audit, locked| {
            proof.check(state, &submission, locked)?;
            options.submission.budget()?;
            if let Some(s) = options.source {
                source::locked(
                    state,
                    s,
                    locked.guards.get(&(crate::cloud_store::KIND.into(), s.id)).and_then(Option::as_ref),
                )?;
            }
            state.store.audit_append(audit)
        },
    )?;
    output.ok_or_else(util::corrupt)
}
pub(super) fn validate(options: &Mutation<'_>) -> DomainResult<()> {
    let tenant = options.submission.principal.tenant;
    let keys = options.keys.iter().collect::<BTreeSet<_>>();
    if options.guards.len() > 2
        || options.guards.iter().any(|g| g.id.is_nil())
        || keys.len() != options.keys.len()
        || keys.len() > 101
        || !keys.contains(&util::state_key(tenant))
        || options.source.is_some_and(|s| s.tenant != tenant)
        || keys.iter().any(|(kind, id)| {
            id.is_nil()
                || ![super::STATE, super::FACT, super::BODY, super::RISK, super::REQUEST, super::PENDING, super::MOCK]
                    .contains(&kind.as_str())
        })
    {
        return Err(util::corrupt());
    }
    Ok(())
}
pub(super) fn validate_plan(
    state: &AppState,
    options: &Mutation<'_>,
    snapshot: &Values,
    plan: &Plan,
) -> DomainResult<()> {
    let tenant = options.submission.principal.tenant;
    if plan.audit.tenant_id != tenant
        || plan.audit.id.is_nil()
        || plan.writes.get(&util::state_key(tenant)).and_then(Option::as_ref).is_none()
    {
        return Err(util::corrupt());
    }
    for (key, value) in &plan.writes {
        if !options.keys.contains(key)
            || !snapshot.contains_key(key)
            || (value.is_none() && key.0 != super::BODY && key.0 != super::PENDING)
        {
            return Err(util::corrupt());
        }
        if let Some(value) = value {
            util::bound(value, 1024 * 1024)?;
        }
    }
    let journal: Journal =
        codec::read(state, tenant, &plan.writes, &util::state_key(tenant))?.ok_or_else(util::corrupt)?;
    util::validate_journal(&journal, tenant)?;
    let mut audit = (*plan.audit).clone();
    audit.sequence = i64::MAX;
    audit.prev_hash = "f".repeat(64);
    audit.entry_hash = "f".repeat(64);
    let rows = plan.writes.iter().map(|((kind,id),payload)| serde_json::json!({"tenant":tenant,"kind":kind,"id":id,"delete":payload.is_none(),"payload":payload})).collect::<Vec<_>>();
    util::bound(&serde_json::json!({"rows":rows,"audit":audit}), 8 * 1024 * 1024)?;
    Ok(())
}
