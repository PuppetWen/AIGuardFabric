use super::{
    BODY, FACT, audit,
    authority::Submission,
    codec, input,
    model::{Fact, Intent, Journal, Package, Phase, Purpose, ResultData, Values},
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
pub(super) async fn prepare(state: &AppState, submission: &Submission, input: input::Preview) -> DomainResult<Fact> {
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
        records::replay(submission, &old, Purpose::Preview, &hash)?;
        return Ok(old);
    }
    let source = source::current(state, submission, input.configuration_version).await?;
    let intent = match input.selection.clone() {
        input::Selection::Create { target } => Intent::Create { target: Box::new(target) },
        input::Selection::Accept { observation_request_id } => {
            let fact =
                super::authority::bounded(submission.deadline, records::load(state, tenant, observation_request_id))
                    .await?;
            submission.own(&fact.owner)?;
            let evidence = selected(&fact)?;
            Intent::Accept {
                target: agf_alicloud::privatelink::provisioning::AcceptConnection {
                    region_id: evidence.plan.region_id.clone(),
                    service_id: evidence.plan.service_id.clone(),
                    endpoint_id: evidence.observation.endpoint_id.clone(),
                },
                planned: evidence.plan.clone(),
                observation_id: fact.id,
            }
        }
    };
    intent.prepare(input.request_id)?;
    if source.region != intent.planned().region_id {
        return Err(util::invalid());
    }
    let mut keys = vec![util::state_key(tenant), util::key(FACT, input.request_id), util::key(BODY, input.request_id)];
    if let Intent::Accept { observation_id, .. } = &intent {
        keys.push(util::key(FACT, *observation_id));
    }
    Box::pin(store::mutate(state, Mutation { submission, source: Some(&source), guards: vec![], keys }, |values| {
        if let Some(old) = codec::read::<Fact>(state, tenant, values, &util::key(FACT, input.request_id))? {
            records::validate(&old, tenant, input.request_id)?;
            records::replay(submission, &old, Purpose::Preview, &hash)?;
            return Ok((old, None));
        }
        if let Intent::Accept { observation_id, .. } = &intent {
            let observed = records::read(state, tenant, values, *observation_id)?;
            submission.own(&observed.owner)?;
            if selected(&observed)?.plan.as_ref() != intent.planned() {
                return Err(util::conflict());
            }
        }

        let mut journal: Journal = codec::read(state, tenant, values, &util::state_key(tenant))?.unwrap_or_default();
        util::validate_journal(&journal, tenant)?;
        if journal.generation != input.expected_generation {
            return Err(util::conflict());
        }
        util::risk(&journal, tenant, &intent)?;
        let mut row = records::new(
            submission,
            input.request_id,
            Purpose::Preview,
            hash.clone(),
            Some(source.clone()),
            Some(intent.clone()),
            None,
        )?;
        records::add(&mut journal, tenant, row.id)?;
        let expires = Timestamp::now().offset_secs(300);
        row.phase = Phase::Complete;
        row.result = Some(ResultData::Preview { expires_at: expires, base_generation: journal.generation });
        let package = Package {
            tenant,
            id: row.id,
            intent: intent.clone(),
            source: source.clone(),
            base_generation: journal.generation,
            expires_at: expires,
            consumed_by: None,
        };
        let encoded = codec::encode(state, tenant, &util::key(BODY, row.id), &package)?;
        journal.stored_bytes =
            journal.stored_bytes.checked_add(util::bound(&encoded, 1024 * 1024)? as u64).ok_or_else(util::capacity)?;
        util::validate_journal(&journal, tenant)?;
        records::validate(&row, tenant, row.id)?;
        let mut writes = Values::new();
        writes.insert(util::key(BODY, row.id), Some(encoded));
        codec::put(state, tenant, &mut writes, util::key(FACT, row.id), &row)?;
        codec::put(state, tenant, &mut writes, util::state_key(tenant), &journal)?;
        Ok((
            row.clone(),
            Some(Plan {
                writes,
                audit: Box::new(audit::change(
                    submission,
                    row.id,
                    AuditAction::Create,
                    "privatelink-provisioning-preview",
                    json!({
                    "generation":journal.generation,
                    "action":intent.prepare(row.id)?.action(),
                    "mocked":source.mode=="mock"}
                    ),
                )),
            }),
        ))
    }))
    .await
}
pub(super) fn selected(fact: &Fact) -> DomainResult<&super::model::Evidence> {
    if fact.purpose != Purpose::Observe || fact.phase != Phase::Complete || fact.archived_at.is_some() {
        return Err(util::conflict());
    }
    let Some(ResultData::Observed { evidence }) = &fact.result else { return Err(util::conflict()) };
    if !evidence.observation.requested_resources_match
        || evidence.observation.connectivity_verified
        || evidence.checked_at > Timestamp::now()
        || evidence.checked_at.offset_secs(300) < Timestamp::now()
    {
        return Err(DomainError::PreconditionFailed(
            "Accept requires a fresh complete endpoint observation; old success is not current authority".into(),
        ));
    }
    super::records::evidence(evidence)?;
    Ok(evidence)
}
