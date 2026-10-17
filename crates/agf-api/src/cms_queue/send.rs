use super::{
    ATTEMPT, BODY, ITEM, REQUEST, audit,
    authority::Submission,
    codec,
    input::Send,
    model::{Attempt, Body, Item, Journal, MockRecord, Phase, Purpose, Request, Values},
    provider, records, source,
    store::{self, Mutation, Plan},
    util,
};
use crate::state::AppState;
use agf_core::{
    audit::AuditAction,
    error::{DomainError, DomainResult},
    time::Timestamp,
};

pub(super) async fn send(state: &AppState, submission: &Submission, input: Send) -> DomainResult<Request> {
    let (request, attempts) = claim(state, submission, &input).await?;
    // Empty on immutable replay: no original request ever reacquires a provider permission.
    for attempt in attempts {
        submission.budget()?;
        if attempt.source.mode == "mock" {
            provider::mock_send(state, submission, &attempt).await?;
        } else {
            Box::pin(super::dispatch::one(state, submission, &attempt)).await?;
        }
    }
    Ok(request)
}
async fn claim(state: &AppState, submission: &Submission, input: &Send) -> DomainResult<(Request, Vec<Attempt>)> {
    super::input::ids(input.request_id, &input.item_ids, 20)?;
    submission.authorize(state).await?;
    let tenant = submission.principal.tenant;
    let hash = util::fingerprint(input)?;
    let request_key = util::key(REQUEST, input.request_id);
    if let Some(request) =
        super::authority::bounded(submission.deadline, store::get::<Request>(state, tenant, &request_key)).await?
    {
        records::request_identity(submission, &request, input.request_id, Purpose::Send, &hash)?;
        return Ok((request, Vec::new()));
    }
    let mut items = Vec::new();
    for id in &input.item_ids {
        items.push(super::authority::bounded(submission.deadline, records::load_item(state, tenant, *id)).await?);
    }
    let expected = items.first().ok_or_else(util::invalid)?.source.clone();
    if items.iter().any(|item| item.source != expected) {
        return Err(util::conflict());
    }
    let current = source::current(state, submission, expected.version).await?;
    if current != expected {
        return Err(util::conflict());
    }
    if current.mode == "live" && !input.confirm_live {
        return Err(util::invalid());
    }
    if current.mode != "mock" && state.store.database().is_none() {
        return Err(DomainError::PreconditionFailed("Live CMS queue delivery requires a durable database".into()));
    }
    let mut keys = vec![util::state_key(tenant), request_key.clone()];
    let mock_key = (current.mode == "mock").then(|| provider::mock_key(&current));
    if let Some(key) = &mock_key {
        keys.push(key.clone());
    }
    let attempt_ids = (0..items.len())
        .map(|i| util::derived(tenant, input.request_id, i, "agf.cms.queue.attempt.v1"))
        .collect::<Vec<_>>();
    for (item, id) in items.iter().zip(&attempt_ids) {
        keys.extend([util::key(ITEM, item.id), util::key(BODY, item.id), util::key(ATTEMPT, *id)]);
        if let Some(old) = item.attempts.last() {
            keys.push(util::key(ATTEMPT, *old));
        }
    }
    Box::pin(store::mutate(state, Mutation { submission, source: Some(&current), keys }, |values| {
        if let Some(old) = records::replay(state, submission, values, input.request_id, Purpose::Send, &hash)? {
            return Ok(((old, Vec::new()), None));
        }
        let mut journal: Journal =
            codec::read(state, tenant, values, &util::state_key(tenant))?.ok_or_else(util::corrupt)?;
        util::validate_journal(&journal, tenant)?;
        if journal.generation != input.expected_generation {
            return Err(util::conflict());
        }
        if let Some(key) = &mock_key {
            let mock: MockRecord = codec::read(state, tenant, values, key)?.ok_or_else(|| {
                DomainError::PreconditionFailed("Explicit CMS Mock fixture initialization is required".into())
            })?;
            provider::validate_mock(&current, &mock)?;
            if mock.accepted.len().checked_add(items.len()).is_none_or(|n| n > 512) {
                return Err(util::capacity());
            }
        }
        let mut writes = Values::new();
        let mut attempts = Vec::new();
        for (loaded, id) in items.iter().zip(&attempt_ids) {
            let key = util::key(ITEM, loaded.id);
            let mut item: Item = codec::read(state, tenant, values, &key)?.ok_or_else(util::corrupt)?;
            records::item(&item, tenant, loaded.id)?;
            submission.own(&item.owner)?;
            if util::fingerprint(&item)? != util::fingerprint(loaded)? {
                return Err(util::conflict());
            }
            let last = records::latest(state, tenant, values, &item)?;
            if !records::retryable(&item, last.as_ref()) {
                return Err(DomainError::PreconditionFailed(
                    "CMS Accepted/Unknown/active/exhausted/archived items cannot be resent".into(),
                ));
            }
            let body: Body =
                codec::read(state, tenant, values, &util::key(BODY, item.id))?.ok_or_else(util::corrupt)?;
            provider::body(&body, &item)?;
            if values.get(&util::key(ATTEMPT, *id)).and_then(Option::as_ref).is_some() {
                return Err(util::corrupt());
            }
            let row = Attempt {
                tenant,
                id: *id,
                item_id: item.id,
                request_id: input.request_id,
                owner: item.owner.clone(),
                source: item.source.clone(),
                admitted_at: Timestamp::now(),
                lease_expires_at: submission.submitted_at.offset_secs(110),
                phase: Phase::Admitted,
                started_at: None,
                outcome: None,
            };
            item.attempts.push(*id);
            records::attempt(&row, &item)?;
            codec::put(state, tenant, &mut writes, key, &item)?;
            codec::put(state, tenant, &mut writes, util::key(ATTEMPT, *id), &row)?;
            attempts.push(row);
        }
        util::bump(&mut journal, tenant, 1 + attempts.len() as u64)?;
        let row = Request {
            tenant,
            id: input.request_id,
            purpose: Purpose::Send,
            input_hash: hash.clone(),
            owner: submission.owner(),
            item_ids: input.item_ids.clone(),
            attempt_ids: attempt_ids.clone(),
            submitted_at: submission.submitted_at,
            changed_count: attempts.len() as u64,
            generation: journal.generation,
        };
        codec::put(state, tenant, &mut writes, request_key, &row)?;
        codec::put(state, tenant, &mut writes, util::state_key(tenant), &journal)?;
        let audit = audit::change(
            submission,
            input.request_id,
            AuditAction::Create,
            REQUEST,
            serde_json::json!({"purpose":"send","admittedItems":attempts.len(),"providerContacted":false}),
        );
        Ok(((row, attempts), Some(Plan { writes, audit: Box::new(audit) })))
    }))
    .await
}
pub(super) async fn start(state: &AppState, submission: &Submission, original: &Attempt) -> DomainResult<Attempt> {
    let tenant = original.tenant;
    let item_key = util::key(ITEM, original.item_id);
    let attempt_key = util::key(ATTEMPT, original.id);
    Box::pin(store::mutate(
        state,
        Mutation {
            submission,
            source: Some(&original.source),
            keys: vec![util::state_key(tenant), item_key.clone(), attempt_key.clone()],
        },
        |values| {
            let item: Item = codec::read(state, tenant, values, &item_key)?.ok_or_else(util::corrupt)?;
            records::item(&item, tenant, item.id)?;
            submission.own(&item.owner)?;
            let mut row: Attempt = codec::read(state, tenant, values, &attempt_key)?.ok_or_else(util::corrupt)?;
            records::attempt(&row, &item)?;
            if util::fingerprint(&row)? != util::fingerprint(original)?
                || row.phase != Phase::Admitted
                || records::expired(&row)
                || item.archived_at.is_some()
                || item.attempts.last() != Some(&row.id)
            {
                return Err(util::conflict());
            }
            row.phase = Phase::Started;
            row.started_at = Some(Timestamp::now());
            records::attempt(&row, &item)?;
            let mut journal: Journal =
                codec::read(state, tenant, values, &util::state_key(tenant))?.ok_or_else(util::corrupt)?;
            util::bump(&mut journal, tenant, 0)?;
            let mut writes = Values::new();
            codec::put(state, tenant, &mut writes, attempt_key, &row)?;
            codec::put(state, tenant, &mut writes, util::state_key(tenant), &journal)?;
            let audit = audit::change(
                submission,
                row.id,
                AuditAction::Create,
                "cms-queue-send-start",
                serde_json::json!({"itemId":row.item_id,"requestId":row.request_id,"providerAccepted":false}),
            );
            Ok((row, Some(Plan { writes, audit: Box::new(audit) })))
        },
    ))
    .await
}
