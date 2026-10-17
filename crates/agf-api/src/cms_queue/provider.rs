use super::{
    ATTEMPT, BODY, ITEM, MOCK, PENDING, audit,
    authority::Submission,
    codec,
    model::{Attempt, Body, Delivery, Item, Journal, MockRecord, Outcome, Phase, Values},
    records,
    source::{self, Source},
    store::{self, Mutation, Plan},
    util,
};
use crate::state::AppState;
use agf_alicloud::cms::queue_delivery::{CurrentGuard, Request};
use agf_core::{error::DomainResult, ids::deterministic_id, time::Timestamp};
use async_trait::async_trait;

pub(super) fn mock_key(source: &Source) -> super::model::Key {
    util::key(MOCK, deterministic_id("agf.cms.queue.mock.v1", &format!("{}:{}", source.tenant, source.fingerprint)))
}
pub(super) fn validate_mock(source: &Source, row: &MockRecord) -> DomainResult<()> {
    if row.tenant != Some(source.tenant)
        || row.source_id != Some(source.id)
        || row.source_hash != source.fingerprint
        || row.accepted.len() > 512
        || row.accepted.iter().any(|(id, hash)| id.is_nil() || !digest(hash))
    {
        return Err(util::corrupt());
    }
    util::bound(row, 128 * 1024)?;
    Ok(())
}
pub(super) fn body(row: &Body, item: &Item) -> DomainResult<()> {
    row.payload.validate().map_err(|_| util::corrupt())?;
    let item_matches = row.item_id == item.id;
    if row.tenant != item.tenant
        || !item_matches
        || row.payload.action() != item.action
        || row.payload.name() != item.name
        || util::fingerprint(&row.payload)? != item.payload_hash
        || util::bound(&row.payload, super::MAX_BODY)? as u64 != item.payload_bytes
    {
        return Err(util::corrupt());
    }
    Ok(())
}
pub(super) fn prepare(payload: &super::input::Payload, source: &Source) -> DomainResult<Request> {
    use super::input::Payload;
    match payload {
        Payload::Event { name, content, at } => {
            Request::event(&source.group, name, content, at.as_datetime().timestamp_millis())
        }
        Payload::Metric { name, value, dimensions, at } => {
            Request::metric(&source.group, name, *value, dimensions, at.as_datetime().timestamp_millis())
        }
    }
}
pub(super) struct Guard<'a> {
    pub state: &'a AppState,
    pub submission: &'a Submission,
    pub attempt: &'a Attempt,
}
#[async_trait]
impl CurrentGuard for Guard<'_> {
    async fn validate(&self) -> DomainResult<()> {
        source::check(self.state, self.submission, &self.attempt.source).await?;
        self.submission.own(&self.attempt.owner)?;
        let item = records::load_item(self.state, self.attempt.tenant, self.attempt.item_id).await?;
        let row: Attempt = store::get(self.state, self.attempt.tenant, &util::key(ATTEMPT, self.attempt.id))
            .await?
            .ok_or_else(util::corrupt)?;
        records::attempt(&row, &item)?;
        if !same_claim(&row, self.attempt)?
            || row.phase != Phase::Started
            || records::expired(&row)
            || item.archived_at.is_some()
        {
            return Err(util::conflict());
        }
        self.submission.budget()
    }
}
pub(super) fn same_claim(left: &Attempt, right: &Attempt) -> DomainResult<bool> {
    let mut left = left.clone();
    let mut right = right.clone();
    left.phase = Phase::Started;
    right.phase = Phase::Started;
    left.outcome = None;
    right.outcome = None;
    Ok(util::fingerprint(&left)? == util::fingerprint(&right)?)
}
pub(super) async fn mock_send(state: &AppState, submission: &Submission, original: &Attempt) -> DomainResult<()> {
    let tenant = original.tenant;
    let item_key = util::key(ITEM, original.item_id);
    let attempt_key = util::key(ATTEMPT, original.id);
    let key = mock_key(&original.source);
    let keys = vec![
        util::state_key(tenant),
        item_key.clone(),
        attempt_key.clone(),
        util::key(BODY, original.item_id),
        util::key(PENDING, original.id),
        key.clone(),
    ];
    Box::pin(store::mutate(state, Mutation { submission, source: Some(&original.source), keys }, |values| {
        let item: Item = codec::read(state, tenant, values, &item_key)?.ok_or_else(util::corrupt)?;
        records::item(&item, tenant, original.item_id)?;
        submission.own(&item.owner)?;
        let mut attempt: Attempt = codec::read(state, tenant, values, &attempt_key)?.ok_or_else(util::corrupt)?;
        records::attempt(&attempt, &item)?;
        if attempt.phase == Phase::Complete {
            return Ok(((), None));
        }
        if attempt.phase != Phase::Admitted
            || util::fingerprint(&attempt)? != util::fingerprint(original)?
            || item.attempts.last() != Some(&attempt.id)
            || records::expired(&attempt)
            || item.archived_at.is_some()
        {
            return Err(util::conflict());
        }
        let payload: Body = codec::read(state, tenant, values, &util::key(BODY, item.id))?.ok_or_else(util::corrupt)?;
        body(&payload, &item)?;
        let mut mock: MockRecord = codec::read(state, tenant, values, &key)?.ok_or_else(|| {
            agf_core::error::DomainError::PreconditionFailed(
                "Explicit CMS Mock fixture initialization is required".into(),
            )
        })?;
        validate_mock(&original.source, &mock)?;
        if mock.accepted.len() >= 512 || mock.accepted.contains_key(&attempt.id) {
            return Err(util::capacity());
        }
        mock.accepted.insert(attempt.id, item.payload_hash.clone());
        let now = Timestamp::now();
        attempt.started_at = Some(now);
        attempt.phase = Phase::Complete;
        let outcome = Outcome {
            delivery: Delivery::Accepted,
            provider_request_id: Some(format!("mock-{}", attempt.id)),
            finished_at: now,
        };
        attempt.outcome = Some(outcome.clone());
        records::attempt(&attempt, &item)?;
        let mut journal: Journal =
            codec::read(state, tenant, values, &util::state_key(tenant))?.ok_or_else(util::corrupt)?;
        util::bump(&mut journal, tenant, 0)?;
        let mut writes = Values::new();
        codec::put(state, tenant, &mut writes, key, &mock)?;
        codec::put(state, tenant, &mut writes, attempt_key, &attempt)?;
        codec::put(state, tenant, &mut writes, util::state_key(tenant), &journal)?;
        Ok(((), Some(Plan { writes, audit: Box::new(audit::terminal(submission, &attempt, &outcome)) })))
    }))
    .await
}
fn digest(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
}
