//! Declared candidates and audit publish together; observation envelopes may be the bounded main record.
use super::{
    authority::Submission,
    callback_execution::{BATCH, EXECUTION, PENDING, PROGRESS, REQUEST},
    job_management::model::{
        OPERATION as MANAGED_OPERATION, PENDING as MANAGED_PENDING, PREVIEW as MANAGED_PREVIEW,
        REQUEST as MANAGED_REQUEST, STATE as MANAGED_STATE,
    },
    records::{BINDING, BODY, FACT, Journal, MOCK, STATE, Values},
    scope::{self, SourceTarget},
    sql, util,
};
use crate::{policy_store::OfflinePublicationProof, state::AppState};
use agf_core::{
    audit::AuditLog,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use agf_storage::configuration::{ConfigurationGuard, GuardedBatchDecision, OfflineGuardedBatch};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::BTreeSet;

pub(super) struct Mutation<'a> {
    pub submission: &'a Submission,
    pub source: Option<&'a SourceTarget>,
    pub main: (String, Id),
    pub declared: Vec<(String, Id)>,
}
pub(super) struct Plan {
    pub writes: Values,
    pub audit: Box<AuditLog>,
}
pub(super) async fn get<T: DeserializeOwned>(
    state: &AppState,
    tenant: TenantId,
    key: &(String, Id),
) -> DomainResult<Option<T>> {
    state.configurations.get(tenant, &key.0, key.1).await
}
pub(super) async fn journal(state: &AppState, tenant: TenantId) -> DomainResult<Journal> {
    let row = get(state, tenant, &util::state_key(tenant)).await?.unwrap_or_default();
    validate_journal(&row, tenant)?;
    Ok(row)
}
pub(super) async fn mutate<T, F>(state: &AppState, options: Mutation<'_>, apply: F) -> DomainResult<T>
where
    T: Send,
    F: FnOnce(&Values) -> DomainResult<(T, Option<Plan>)> + Send,
{
    let deadline = options.submission.deadline;
    super::authority::bounded(deadline, Box::pin(mutate_inner(state, options, apply))).await
}
async fn mutate_inner<T, F>(state: &AppState, options: Mutation<'_>, apply: F) -> DomainResult<T>
where
    T: Send,
    F: FnOnce(&Values) -> DomainResult<(T, Option<Plan>)> + Send,
{
    validate_options(&options)?;
    if state.store.database().is_some() {
        return Box::pin(sql::mutate(state, options, apply)).await;
    }
    let submission = options.submission.borrowed();
    let proof = OfflinePublicationProof::prepare(state, &submission).await?;
    let tenant = submission.principal.tenant;
    let guards = options
        .source
        .map(|source| ConfigurationGuard { kind: crate::cloud_store::KIND, id: source.configuration_id })
        .into_iter()
        .collect::<Vec<_>>();
    let related = options
        .declared
        .iter()
        .filter(|key| **key != options.main)
        .map(|(kind, id)| ConfigurationGuard { kind: kind.as_str(), id: *id })
        .collect::<Vec<_>>();
    let mut result = None;
    state.configurations.mutate_offline_guarded_batch_audited(
        tenant,
        OfflineGuardedBatch {
            kind: &options.main.0,
            id: options.main.1,
            guards: &guards,
            security: Some(OfflinePublicationProof::security(&submission)?),
            related: &related,
            max_main_bytes: 4 * 1024 * 1024,
            max_related_bytes: 1024 * 1024,
            max_total_write_bytes: 8 * 1024 * 1024,
        },
        |locked, main: &mut Value, originals| {
            if let Some(source) = options.source {
                let cloud = locked
                    .guards
                    .get(&(crate::cloud_store::KIND.into(), source.configuration_id))
                    .and_then(Option::as_ref);
                scope::validate_locked(state, source, cloud)?;
            }
            let mut snapshot = originals.clone();
            snapshot.insert(options.main.clone(), if main.is_null() { None } else { Some(main.clone()) });
            let (output, plan) = apply(&snapshot)?;
            result = Some(output);
            let Some(plan) = plan else {
                return Ok(GuardedBatchDecision::Unchanged);
            };
            validate_plan(&options, &snapshot, &plan)?;
            let mut writes = plan.writes;
            *main = writes.remove(&options.main).flatten().ok_or_else(util::corrupt)?;
            Ok(GuardedBatchDecision::Write { related: writes, audit: plan.audit })
        },
        |audit, locked| {
            proof.check(state, &submission, locked)?;
            options.submission.budget()?;
            if let Some(source) = options.source {
                scope::validate_locked(
                    state,
                    source,
                    locked
                        .guards
                        .get(&(crate::cloud_store::KIND.into(), source.configuration_id))
                        .and_then(Option::as_ref),
                )?;
            }
            options.submission.budget()?;
            state.store.audit_append(audit)
        },
    )?;
    result.ok_or_else(|| DomainError::Internal("Scheduler 批次没有返回结果".into()))
}
pub(super) fn validate_options(options: &Mutation<'_>) -> DomainResult<()> {
    let tenant = options.submission.principal.tenant;
    let keys = options.declared.iter().collect::<BTreeSet<_>>();
    if keys.len() != options.declared.len()
        || keys.len() > 101
        || !keys.contains(&options.main)
        || !keys.contains(&util::state_key(tenant))
        || options.main.1.is_nil()
        || options.source.is_some_and(|source| source.tenant != tenant)
    {
        return Err(util::corrupt());
    }
    for (kind, id) in &options.declared {
        if id.is_nil()
            || ![
                STATE,
                FACT,
                BODY,
                BINDING,
                MOCK,
                EXECUTION,
                BATCH,
                PROGRESS,
                PENDING,
                REQUEST,
                MANAGED_STATE,
                MANAGED_PREVIEW,
                MANAGED_OPERATION,
                MANAGED_REQUEST,
                MANAGED_PENDING,
            ]
            .contains(&kind.as_str())
        {
            return Err(util::corrupt());
        }
    }
    Ok(())
}
pub(super) fn validate_plan(options: &Mutation<'_>, originals: &Values, plan: &Plan) -> DomainResult<()> {
    let tenant = options.submission.principal.tenant;
    if plan.audit.tenant_id != tenant
        || plan.audit.id.is_nil()
        || plan.writes.get(&options.main).and_then(Option::as_ref).is_none()
    {
        return Err(util::corrupt());
    }
    for (key, value) in &plan.writes {
        if !originals.contains_key(key) {
            return Err(util::corrupt());
        }
        if let Some(value) = value {
            util::bound(value, if *key == options.main { 4 * 1024 * 1024 } else { 1024 * 1024 })?;
        }
        if [FACT, EXECUTION, BATCH, PROGRESS, REQUEST, MANAGED_OPERATION, MANAGED_REQUEST].contains(&key.0.as_str())
            && value.is_none()
        {
            return Err(util::corrupt());
        }
    }
    let journal: Journal = plan
        .writes
        .get(&util::state_key(tenant))
        .and_then(Option::as_ref)
        .cloned()
        .or_else(|| originals.get(&util::state_key(tenant)).and_then(Option::as_ref).cloned())
        .map(serde_json::from_value)
        .transpose()?
        .unwrap_or_default();
    validate_journal(&journal, tenant)?;
    util::batch_bound(tenant, &plan.writes, &plan.audit)?;
    Ok(())
}
pub(super) fn validate_journal(row: &Journal, tenant: TenantId) -> DomainResult<()> {
    if row.tenant.is_some_and(|owner| owner != tenant)
        || row.observations.len() > super::MAX_RUNS
        || row.observations.iter().any(Id::is_nil)
        || row.observations.iter().collect::<BTreeSet<_>>().len() != row.observations.len()
        || row.stored_bytes > super::MAX_STORED_BYTES
    {
        return Err(util::corrupt());
    }
    util::bound(row, 1024 * 1024)?;
    Ok(())
}
pub(super) fn bump(row: &mut Journal, tenant: TenantId) -> DomainResult<()> {
    row.tenant = Some(tenant);
    row.version = row.version.checked_add(1).ok_or_else(util::capacity)?;
    row.generation = row.generation.checked_add(1).ok_or_else(util::capacity)?;
    Ok(())
}
