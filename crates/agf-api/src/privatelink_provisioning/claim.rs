use super::{
    BODY, FACT, audit,
    authority::Submission,
    codec, input,
    model::{Fact, Journal, Package, Phase, Purpose, ResultData, Values},
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
use serde_json::json;
pub(super) async fn apply(state: &AppState, submission: &Submission, input: input::Apply) -> DomainResult<Fact> {
    submission.authorize(state).await?;
    let tenant = submission.principal.tenant;
    let hash = util::fingerprint(&input)?;
    if let Some(old) = super::authority::bounded(
        submission.deadline,
        store::get::<Fact>(state, tenant, &util::key(FACT, input.request_id)),
    )
    .await?
    {
        records::validate(&old, tenant, input.request_id)?;
        records::replay(submission, &old, Purpose::Apply, &hash)?;
        return Ok(old);
    }
    let preview =
        super::authority::bounded(submission.deadline, records::load(state, tenant, input.preview_id)).await?;
    submission.own(&preview.owner)?;
    if preview.purpose != Purpose::Preview || preview.archived_at.is_some() {
        return Err(util::conflict());
    }
    let source = preview.source.clone().ok_or_else(util::corrupt)?;
    source::check(state, submission, &source).await?;
    if !input.confirm_resources_and_cost
        || !input.confirm_current_role
        || !input.confirm_no_connectivity_proof
        || (source.mode == "live" && !input.confirm_live)
        || (input.initialize_mock_fixture && source.mode != "mock")
    {
        return Err(DomainError::PreconditionFailed("Explicit resource/cost, current consumer or provider role, connectivity boundary and Live confirmations are required".into()));
    }
    if source.mode != "mock" && state.store.database().is_none() {
        return Err(DomainError::PreconditionFailed("Live provisioning requires durable SQL request claims".into()));
    }
    let mut keys = vec![
        util::state_key(tenant),
        util::key(FACT, input.request_id),
        util::key(FACT, preview.id),
        util::key(BODY, preview.id),
    ];
    if let Some(super::model::Intent::Accept { observation_id, .. }) = &preview.intent {
        keys.push(util::key(FACT, *observation_id));
    }
    if source.mode == "mock" {
        keys.push(util::mock_key(tenant));
    }
    let (row, created) = Box::pin(store::mutate(
        state,
        Mutation { submission, source: Some(&source), guards: vec![], keys },
        |values| {
            if let Some(old) = codec::read::<Fact>(state, tenant, values, &util::key(FACT, input.request_id))? {
                records::validate(&old, tenant, input.request_id)?;
                records::replay(submission, &old, Purpose::Apply, &hash)?;
                return Ok(((old, false), None));
            }
            let p = records::read(state, tenant, values, preview.id)?;
            submission.own(&p.owner)?;
            if p.archived_at.is_some() || p.purpose != Purpose::Preview {
                return Err(util::conflict());
            }
            let package: Package =
                codec::read(state, tenant, values, &util::key(BODY, p.id))?.ok_or_else(util::conflict)?;
            if package.tenant != tenant
                || package.id != p.id
                || package.source != source
                || Some(&package.intent) != p.intent.as_ref()
                || package.consumed_by.is_some()
                || package.expires_at <= Timestamp::now()
            {
                return Err(util::conflict());
            }
            if let super::model::Intent::Accept { observation_id, .. } = &package.intent {
                let observed = records::read(state, tenant, values, *observation_id)?;
                submission.own(&observed.owner)?;
                let e = super::preview::selected(&observed)?;
                if e.plan.as_ref() != package.intent.planned()
                    || Some(e.observation.endpoint_id.as_str()) != package.intent.endpoint()
                {
                    return Err(util::conflict());
                }
            }

            let mut journal: Journal =
                codec::read(state, tenant, values, &util::state_key(tenant))?.ok_or_else(util::corrupt)?;
            util::validate_journal(&journal, tenant)?;
            if journal.generation != input.expected_generation || package.base_generation != journal.generation {
                return Err(util::conflict());
            }
            util::risk(&journal, tenant, &package.intent)?;
            let mut row = records::new(
                submission,
                input.request_id,
                Purpose::Apply,
                hash.clone(),
                Some(source.clone()),
                Some(package.intent.clone()),
                Some(p.id),
            )?;
            records::add(&mut journal, tenant, row.id)?;
            journal.risks.insert(util::resource(tenant, &package.intent)?, row.id);
            let mut writes = Values::new();
            let old_bytes = values
                .get(&util::key(BODY, p.id))
                .and_then(Option::as_ref)
                .map(|v| util::bound(v, 1024 * 1024))
                .transpose()?
                .ok_or_else(util::corrupt)?;
            let mut consumed = package;
            consumed.consumed_by = Some(row.id);
            let encoded = codec::encode(state, tenant, &util::key(BODY, p.id), &consumed)?;
            journal.stored_bytes = journal
                .stored_bytes
                .checked_sub(old_bytes as u64)
                .and_then(|n| n.checked_add(serde_json::to_vec(&encoded).ok()?.len() as u64))
                .ok_or_else(util::capacity)?;
            writes.insert(util::key(BODY, p.id), Some(encoded));

            if source.mode == "mock" {
                let outcome =
                    super::mock::apply(state, tenant, values, &mut writes, &row, input.initialize_mock_fixture)?;
                row.phase = Phase::Complete;
                row.started_at = Some(Timestamp::now());
                row.result = Some(ResultData::Write { outcome });
                journal.risks.remove(&util::resource(tenant, row.intent.as_ref().ok_or_else(util::corrupt)?)?);
            }
            util::validate_journal(&journal, tenant)?;
            records::validate(&row, tenant, row.id)?;
            codec::put(state, tenant, &mut writes, util::state_key(tenant), &journal)?;
            codec::put(state, tenant, &mut writes, util::key(FACT, row.id), &row)?;
            let audit = if source.mode == "mock" {
                audit::terminal(submission, &row)
            } else {
                audit::change(
                    submission,
                    row.id,
                    AuditAction::Create,
                    "privatelink-provisioning-claim",
                    json!({
                    "action":row.intent.as_ref().ok_or_else(util::corrupt)?.prepare(row.id)?.action(),
                    "providerAttempted":false}
                    ),
                )
            };
            Ok(((row, true), Some(Plan { writes, audit: Box::new(audit) })))
        },
    ))
    .await?;

    if created && row.phase == Phase::Admitted {
        super::dispatch::write(state, submission, &row).await?;
    }
    records::load(state, tenant, row.id).await
}
pub(super) async fn start(state: &AppState, submission: &Submission, original: &Fact) -> DomainResult<Fact> {
    let tenant = original.tenant;
    let source = original.source.as_ref().ok_or_else(util::corrupt)?;
    Box::pin(store::mutate(
        state,
        Mutation {
            submission,
            source: Some(source),
            guards: vec![],
            keys: vec![util::state_key(tenant), util::key(FACT, original.id)],
        },
        |values| {
            let mut row = records::read(state, tenant, values, original.id)?;
            submission.own(&row.owner)?;
            if records::claim_hash(&row)? != records::claim_hash(original)?
                || row.phase != Phase::Admitted
                || row.archived_at.is_some()
                || row.lease_expires_at <= Timestamp::now()
            {
                return Err(util::conflict());
            }
            let mut journal: Journal =
                codec::read(state, tenant, values, &util::state_key(tenant))?.ok_or_else(util::corrupt)?;
            row.phase = Phase::Started;
            row.started_at = Some(Timestamp::now());
            util::bump(&mut journal, tenant, 0)?;
            let mut writes = Values::new();
            codec::put(state, tenant, &mut writes, util::state_key(tenant), &journal)?;
            codec::put(state, tenant, &mut writes, util::key(FACT, row.id), &row)?;
            Ok((
                row.clone(),
                Some(Plan {
                    writes,
                    audit: Box::new(audit::change(
                        submission,
                        row.id,
                        AuditAction::Execute,
                        "privatelink-provisioning-start",
                        json!({"dispatchAuthorized":true,"cloudSuccess":false}),
                    )),
                }),
            ))
        },
    ))
    .await
}
