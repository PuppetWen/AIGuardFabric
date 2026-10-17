use super::{
    FACT, audit,
    authority::Submission,
    codec, input, inventory,
    model::{Delivery, Fact, Journal, Phase, Purpose, ResultData, Values},
    records, source,
    store::{self, Mutation, Plan},
    util,
};
use crate::state::AppState;
use agf_core::{
    audit::AuditAction,
    error::{DomainError, DomainResult},
    time::Timestamp,
};
use agf_storage::configuration::ConfigurationGuard;
use serde_json::json;
pub(super) async fn observe(state: &AppState, submission: &Submission, input: input::Observe) -> DomainResult<Fact> {
    submission.authorize(state).await?;
    let tenant = submission.principal.tenant;
    let hash = util::fingerprint(&input)?;
    if let Some(row) = super::authority::bounded(
        submission.deadline,
        store::get::<Fact>(state, tenant, &util::key(FACT, input.request_id)),
    )
    .await?
    {
        records::validate(&row, tenant, input.request_id)?;
        records::replay(submission, &row, Purpose::Observe, &hash)?;
        return Ok(row);
    }
    if input.original_create_request_id.is_some() == input.inventory_scope_id.is_some() {
        return Err(util::invalid());
    }
    let source = source::current(state, submission, input.configuration_version).await?;
    if source.mode == "live" && !input.confirm_live {
        return Err(util::invalid());
    }
    if let Some(scope) = input.inventory_scope_id {
        let selected = inventory::selection(state, submission, scope).await?;
        let key = crate::privatelink_inventory::provisioning_selection::key(tenant);
        return Box::pin(store::mutate(
            state,
            Mutation {
                submission,
                source: Some(&source),
                guards: vec![ConfigurationGuard { kind: key.0, id: key.1 }],
                keys: vec![util::state_key(tenant), util::key(FACT, input.request_id)],
            },
            |values| {
                if let Some(row) = codec::read::<Fact>(state, tenant, values, &util::key(FACT, input.request_id))? {
                    records::replay(submission, &row, Purpose::Observe, &hash)?;
                    return Ok((row, None));
                }
                let evidence = inventory::locked(state, &source, scope, &selected.payload_hash, values)?;
                let mut journal: Journal =
                    codec::read(state, tenant, values, &util::state_key(tenant))?.unwrap_or_default();
                let mut row = records::new(
                    submission,
                    input.request_id,
                    Purpose::Observe,
                    hash.clone(),
                    Some(source.clone()),
                    None,
                    None,
                )?;
                records::add(&mut journal, tenant, row.id)?;
                row.phase = Phase::Complete;
                row.result = Some(ResultData::Observed { evidence: Box::new(evidence) });
                records::validate(&row, tenant, row.id)?;
                let mut writes = Values::new();
                codec::put(state, tenant, &mut writes, util::state_key(tenant), &journal)?;
                codec::put(state, tenant, &mut writes, util::key(FACT, row.id), &row)?;
                Ok((row.clone(), Some(Plan { writes, audit: Box::new(audit::terminal(submission, &row)) })))
            },
        ))
        .await;
    }
    let original_id = input.original_create_request_id.ok_or_else(util::invalid)?;
    let original = super::authority::bounded(submission.deadline, records::load(state, tenant, original_id)).await?;
    submission.own(&original.owner)?;
    let Some(ResultData::Write { outcome }) = &original.result else { return Err(util::conflict()) };
    if original.purpose != Purpose::Apply
        || outcome.delivery != Delivery::Acknowledged
        || original.archived_at.is_some()
    {
        return Err(DomainError::PreconditionFailed("Observe an acknowledged original creation/acceptance or select a current inventory snapshot; Unknown is never upgraded to acknowledged".into()));
    }
    let endpoint = outcome.endpoint_id.clone().ok_or_else(util::corrupt)?;
    let intent = original.intent.as_ref().ok_or_else(util::corrupt)?.clone();
    if source.region != intent.planned().region_id {
        return Err(util::conflict());
    }
    let mut keys = vec![util::state_key(tenant), util::key(FACT, input.request_id), util::key(FACT, original.id)];
    if source.mode == "mock" {
        keys.push(util::mock_key(tenant));
    }
    let (row, created) = Box::pin(store::mutate(
        state,
        Mutation { submission, source: Some(&source), guards: vec![], keys },
        |values| {
            if let Some(row) = codec::read::<Fact>(state, tenant, values, &util::key(FACT, input.request_id))? {
                records::replay(submission, &row, Purpose::Observe, &hash)?;
                return Ok(((row, false), None));
            }
            let stored = records::read(state, tenant, values, original.id)?;
            if util::fingerprint(&stored)? != util::fingerprint(&original)? {
                return Err(util::conflict());
            }
            let mut journal: Journal =
                codec::read(state, tenant, values, &util::state_key(tenant))?.ok_or_else(util::corrupt)?;
            let mut row = records::new(
                submission,
                input.request_id,
                Purpose::Observe,
                hash.clone(),
                Some(source.clone()),
                Some(intent.clone()),
                Some(original.id),
            )?;
            records::add(&mut journal, tenant, row.id)?;
            let mut writes = Values::new();
            if source.mode == "mock" {
                let evidence = super::mock::observe(state, tenant, values, &mut writes, &original)?;
                row.phase = Phase::Complete;
                row.result = Some(ResultData::Observed { evidence: Box::new(evidence) });
            }
            codec::put(state, tenant, &mut writes, util::state_key(tenant), &journal)?;
            codec::put(state, tenant, &mut writes, util::key(FACT, row.id), &row)?;
            let audit = if source.mode == "mock" {
                audit::terminal(submission, &row)
            } else {
                audit::change(
                    submission,
                    row.id,
                    AuditAction::Create,
                    "privatelink-provisioning-read-claim",
                    json!({"providerWrite":false}),
                )
            };
            Ok(((row, true), Some(Plan { writes, audit: Box::new(audit) })))
        },
    ))
    .await?;
    if !created || row.phase == Phase::Complete {
        return Ok(row);
    }
    let started = super::claim::start(state, submission, &row).await?;
    let mut cancellation = super::dispatch::Cancellation { state: state.clone(), fact: started.clone(), armed: true };
    let guard = super::dispatch::Guard { state, submission, fact: &started };
    let result = Box::pin(crate::cloud_runtime::execute_privatelink_provisioning(
        state,
        crate::cloud_runtime::PrivateLinkProvisioningInvocation {
            tenant,
            configuration_version: source.version,
            payload_fingerprint: &source.fingerprint,
            guard: &guard,
            deadline: submission.deadline,
            call: crate::cloud_runtime::PrivateLinkProvisioningCall::Observe {
                plan: intent.planned(),
                endpoint: &endpoint,
            },
        },
    ))
    .await;
    let outcome = match result {
        Ok(crate::cloud_runtime::PrivateLinkProvisioningOutcome::Observed(observation)) => ResultData::Observed {
            evidence: Box::new(super::model::Evidence {
                plan: Box::new(intent.planned().clone()),
                observation: *observation,
                checked_at: Timestamp::now(),
                original_create_id: Some(original.id),
                inventory_scope_id: None,
                inventory_payload_hash: None,
            }),
        },
        _ => ResultData::FailedRead,
    };
    cancellation.armed = false;
    super::dispatch::retain(state, submission, started, outcome).await?;
    records::load(state, tenant, row.id).await
}
