use super::super::{
    authority::Submission,
    claim,
    records::{BindingRecord, Values},
    scope,
    store::{self, Mutation, Plan},
    util,
};
use super::{current, dependencies, evidence, identity, input::AdmissionInput, model::*};
use crate::state::AppState;
use agf_core::{
    audit::{AuditAction, AuditOutcome},
    error::DomainResult,
    time::Timestamp,
};
use std::collections::BTreeMap;

pub(super) async fn admit(
    state: &AppState,
    submission: &Submission,
    input: AdmissionInput,
) -> DomainResult<(Fact, bool)> {
    input.validate()?;
    let principal = submission.authorize(state).await?;
    let owner = current::service(state, &principal)?;
    let tenant = principal.tenant;
    let id = identity::fact(tenant, &input)?;
    let hash = identity::input_hash(&input)?;
    let request_key = identity::request_key(tenant, input.request_id);
    let fact_key = identity::fact_key(id);
    let batch_key = identity::batch_key(identity::batch(tenant, &input)?);
    let native_key = util::fact_key(tenant, input.request_id);
    let managed_key = super::super::job_management::request_key(tenant, input.request_id);
    super::super::job_management::require_vacant(state, tenant, input.request_id).await?;
    if store::get::<serde_json::Value>(state, tenant, &native_key).await?.is_some() {
        return Err(current::conflict());
    }
    // A duplicate is local and does not acquire a new current source or execution chance.
    if let Some(index) = store::get::<RequestIndex>(state, tenant, &request_key).await? {
        validate_index(&index, tenant, input.request_id, id, &hash)?;
        let row = super::views::load(state, tenant, index.fact_id).await?;
        current::owner(state, submission, &row.context.owner).await?;
        current::replay(&row, &hash)?;
        return Ok((row, false));
    }
    if let Some(row) = store::get::<Fact>(state, tenant, &fact_key).await? {
        evidence::verify_fact(state, &row)?;
        current::owner(state, submission, &row.context.owner).await?;
        current::replay(&row, &hash)?;
        return store::mutate(
            state,
            Mutation {
                submission,
                source: None,
                main: fact_key.clone(),
                declared: vec![
                    util::state_key(tenant),
                    request_key.clone(),
                    fact_key.clone(),
                    native_key.clone(),
                    managed_key.clone(),
                ],
            },
            |snapshot| {
                vacant_native(snapshot, &native_key)?;
                super::super::job_management::vacant(snapshot, &managed_key)?;
                let stored: Fact = util::read(snapshot, &fact_key)?.ok_or_else(util::corrupt)?;
                evidence::verify_fact(state, &stored)?;
                current::owner_locked(state, submission, &stored.context.owner)?;
                current::replay(&stored, &hash)?;
                if let Some(index) = util::read::<RequestIndex>(snapshot, &request_key)? {
                    validate_index(&index, tenant, input.request_id, id, &hash)?;
                }
                alias(submission, snapshot, request_key, &input, stored)
            },
        )
        .await;
    }
    let target = scope::current(state, tenant).await?.ok_or_else(current::unqualified)?;
    if target.mocked
        || (target.configuration_version, target.fingerprint.as_str())
            != (input.configuration_version, input.source_fingerprint.as_str())
    {
        return Err(util::stale());
    }
    let progress_key = identity::progress_key(tenant, &input.kind);
    let binding_key = util::binding_key(tenant);
    let mut declared = vec![
        util::state_key(tenant),
        binding_key.clone(),
        request_key.clone(),
        fact_key.clone(),
        batch_key.clone(),
        progress_key.clone(),
        native_key.clone(),
        managed_key.clone(),
    ];
    for upstream in dependencies::kinds(tenant, &input.kind)? {
        declared.push(identity::progress_key(tenant, &upstream));
    }
    declared.sort();
    declared.dedup();
    store::mutate(state, Mutation { submission, source: Some(&target), main: fact_key.clone(), declared }, |snapshot| {
        vacant_native(snapshot, &native_key)?;
        super::super::job_management::vacant(snapshot, &managed_key)?;
        if let Some(index) = util::read::<RequestIndex>(snapshot, &request_key)? {
            validate_index(&index, tenant, input.request_id, id, &hash)?;
        }
        if let Some(row) = util::read::<Fact>(snapshot, &fact_key)? {
            evidence::verify_fact(state, &row)?;
            current::owner_locked(state, submission, &row.context.owner)?;
            current::replay(&row, &hash)?;
            return alias(submission, snapshot, request_key, &input, row);
        }
        if snapshot.get(&request_key).and_then(Option::as_ref).is_some() {
            return Err(util::corrupt());
        }
        let binding: BindingRecord = util::read(snapshot, &binding_key)?.ok_or_else(current::unqualified)?;
        let adoption_version =
            current::mapping(state, &binding, tenant, &target, &input.kind, &input.app_id, &input.job_id)?;
        if binding.version != input.binding_version {
            return Err(util::stale());
        }
        dependencies::check(state, snapshot, &binding, &target, &input.kind)?;
        let context = Context {
            tenant,
            kind: input.kind.clone(),
            app_id: input.app_id.clone(),
            job_id: input.job_id.clone(),
            job_execution_id: input.job_execution_id.clone(),
            partition_total: input.partition_total,
            binding_version: binding.version,
            adoption_version,
            target: target.clone(),
            owner: owner.clone(),
        };
        let now = Timestamp::now();
        let mut row = Fact {
            id,
            batch_id: batch_key.1,
            request_id: input.request_id,
            claim_id: agf_core::ids::Id::new(),
            input_hash: hash.clone(),
            context: context.clone(),
            partition_index: input.partition_index,
            submitted_at: submission.submitted_at,
            admitted_at: now,
            start_expires_at: now.offset_secs(110),
            started_at: None,
            execution_expires_at: None,
            finished_at: None,
            state: State::Admitted,
            outcome: None,
            outcome_hash: None,
            seal: None,
        };
        row.validate(tenant, id)?;
        evidence::seal_fact(state, &mut row)?;
        let prior: Option<Batch> = util::read(snapshot, &batch_key)?;
        let mut batch = if let Some(batch) = prior {
            batch.validate(tenant)?;
            if batch.context != context {
                return Err(current::conflict());
            }
            let progress: Progress = util::read(snapshot, &progress_key)?.ok_or_else(util::corrupt)?;
            dependencies::validate_progress(state, &progress, tenant, &input.kind)?;
            if progress.batch.id != batch.id {
                return Err(current::unqualified());
            }
            if progress.batch != batch {
                return Err(util::corrupt());
            }
            batch
        } else {
            Batch { id: batch_key.1, context, admitted_at: now, partitions: BTreeMap::default() }
        };
        if batch.partitions.contains_key(&input.partition_index) {
            return Err(util::corrupt());
        }
        batch
            .partitions
            .insert(input.partition_index, Partition { fact_id: id, claim_id: row.claim_id, terminal: None });
        batch.validate(tenant)?;
        let progress = evidence::seal(state, tenant, &input.kind, batch.clone())?;
        let mut writes = Values::new();
        util::put(&mut writes, fact_key, &row)?;
        util::put(&mut writes, batch_key, &batch)?;
        util::put(&mut writes, progress_key, &progress)?;
        util::put(
            &mut writes,
            request_key,
            &RequestIndex { tenant, request_id: input.request_id, fact_id: id, input_hash: hash },
        )?;
        Ok((
            (row, true),
            Some(Plan {
                writes,
                audit: Box::new(claim::audit(
                    submission,
                    id,
                    "scheduler-native-callback-claim",
                    AuditAction::Create,
                    AuditOutcome::Success,
                    "永久领取原生 Callback 分片；只证明准入，不证明业务执行或外部效果",
                )),
            }),
        ))
    })
    .await
}
fn validate_index(
    row: &RequestIndex,
    tenant: agf_core::ids::TenantId,
    request: agf_core::ids::Id,
    fact: agf_core::ids::Id,
    hash: &str,
) -> DomainResult<()> {
    if (row.tenant, row.request_id) != (tenant, request) || row.fact_id.is_nil() || !util::digest(&row.input_hash) {
        return Err(util::corrupt());
    }
    if (row.fact_id, row.input_hash.as_str()) != (fact, hash) {
        return Err(current::conflict());
    }
    Ok(())
}
fn alias(
    submission: &Submission,
    snapshot: &Values,
    key: identity::Key,
    input: &AdmissionInput,
    row: Fact,
) -> DomainResult<((Fact, bool), Option<Plan>)> {
    if snapshot.get(&key).and_then(Option::as_ref).is_some() {
        return Ok(((row, false), None));
    }
    let mut writes = Values::new();
    util::put(&mut writes, identity::fact_key(row.id), &row)?;
    util::put(
        &mut writes,
        key,
        &RequestIndex {
            tenant: row.context.tenant,
            request_id: input.request_id,
            fact_id: row.id,
            input_hash: row.input_hash.clone(),
        },
    )?;
    Ok((
        (row.clone(), false),
        Some(Plan {
            writes,
            audit: Box::new(claim::audit(
                submission,
                row.id,
                "scheduler-native-callback-request",
                AuditAction::Configure,
                AuditOutcome::Success,
                "把重复编号永久关联原事实；不重派业务处理器",
            )),
        }),
    ))
}
fn vacant_native(snapshot: &Values, key: &identity::Key) -> DomainResult<()> {
    if snapshot.get(key).and_then(Option::as_ref).is_some() {
        return Err(current::conflict());
    }
    Ok(())
}
