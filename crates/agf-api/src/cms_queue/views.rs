use super::{
    ATTEMPT, REQUEST,
    authority::Submission,
    model::{Attempt, Delivery, Item, Phase, Request},
    records, source, staging, store, util,
};
use crate::state::AppState;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Page {
    #[serde(default = "first")]
    pub page: u32,
    #[serde(default = "size")]
    pub page_size: u32,
}
fn first() -> u32 {
    1
}
fn size() -> u32 {
    20
}
pub(super) async fn state(state: &AppState, submission: &Submission, page: Page) -> DomainResult<Value> {
    submission.authorize(state).await?;
    if page.page == 0 || !(1..=50).contains(&page.page_size) {
        return Err(util::invalid());
    }
    let tenant = submission.principal.tenant;
    let journal = store::journal(state, tenant).await?;
    let source = current(state, tenant).await?;
    let start = u64::from(page.page - 1) * u64::from(page.page_size);
    let mut items = Vec::new();
    for id in journal.items.iter().skip(usize::try_from(start).unwrap_or(usize::MAX)).take(page.page_size as usize) {
        items.push(item(state, submission, *id).await?);
    }
    submission.authorize(state).await?;
    Ok(json!({"generation":journal.generation,"storedContentBytes":journal.stored_bytes,
        "permanentFactCount":journal.facts,"page":page.page,"pageSize":page.page_size,"total":journal.items.len(),
        "items":items,"source":source.as_ref().map(source_view),
        "limits":{"detailedItems":super::MAX_ITEMS,"permanentFacts":super::MAX_FACTS,"attemptsPerItem":super::MAX_ATTEMPTS,
            "enqueueBatch":20,"sendBatch":20,"archiveBatch":32,"contentBytes":2*1024*1024},
        "automaticRetry":false,"exactlyOnce":false,"consumerApplied":"unknown"}))
}
pub(super) async fn item(state: &AppState, submission: &Submission, id: Id) -> DomainResult<Value> {
    let row = records::load_item(state, submission.principal.tenant, id).await?;
    let last = if let Some(id) = row.attempts.last() {
        let last: Attempt = store::get(state, row.tenant, &util::key(ATTEMPT, *id)).await?.ok_or_else(util::corrupt)?;
        records::attempt(&last, &row)?;
        Some(last)
    } else {
        None
    };
    let source_current = current(state, row.tenant).await?.as_ref() == Some(&row.source);
    let owner_current = submission.owner() == row.owner;
    let can_write = submission.principal.require(state, "alicloud", "write").is_ok();
    let mock_ready = if row.source.mode == "mock" {
        if let Some(mock) =
            store::get::<super::model::MockRecord>(state, row.tenant, &super::provider::mock_key(&row.source)).await?
        {
            super::provider::validate_mock(&row.source, &mock)?;
            mock.accepted.len() < 512
        } else {
            false
        }
    } else {
        true
    };
    let last_view = if let Some(last) = &last { Some(attempt(state, last, &row).await?) } else { None };
    Ok(json!({"id":row.id,"enqueueRequestId":row.enqueue_id,"name":row.name,"action":row.action,
        "payloadHash":row.payload_hash,"payloadBytes":row.payload_bytes,"queuedAt":row.queued_at,"archivedAt":row.archived_at,
        "originalSource":source_view(&row.source),"sourceCurrent":source_current,"attemptCount":row.attempts.len(),"lastAttempt":last_view,
        "deadLetter":row.attempts.len()>=super::MAX_ATTEMPTS as usize && last.as_ref().and_then(|a|a.outcome.as_ref()).is_some_and(|o|matches!(o.delivery,Delivery::NotSent|Delivery::Rejected)),
        "canSend":owner_current && can_write && source_current && mock_ready && records::retryable(&row,last.as_ref()),
        "canRecoverLocal":owner_current && can_write && last.as_ref().is_some_and(|a|a.phase!=Phase::Complete && (records::expired(a)||last_view.as_ref().is_some_and(|v|v["pendingAudit"]==true))),
        "canArchive":owner_current && can_write && row.archived_at.is_none() && last.as_ref().is_none_or(|a|a.phase==Phase::Complete)}))
}
async fn attempt(state: &AppState, row: &Attempt, item: &Item) -> DomainResult<Value> {
    let pending = staging::read(state, row, item).await?;
    let projected = pending.as_ref().map(|p| &p.outcome).or(row.outcome.as_ref());
    let completion = if row.phase == Phase::Complete {
        "complete"
    } else if pending.is_some() {
        "pending_audit"
    } else if records::expired(row) {
        "uncertain"
    } else {
        "in_flight"
    };
    let attempted = if row.source.mode == "mock" || projected.is_some_and(|o| o.delivery == Delivery::NotSent) {
        Some(false)
    } else if projected.is_some_and(|o| matches!(o.delivery, Delivery::Accepted | Delivery::Rejected)) {
        Some(true)
    } else {
        None
    };
    let outcome = projected
        .map(|o| json!({"delivery":o.delivery,"providerRequestId":o.provider_request_id,"finishedAt":o.finished_at}));
    Ok(
        json!({"id":row.id,"requestId":row.request_id,"phase":row.phase,"admittedAt":row.admitted_at,"startedAt":row.started_at,
        "leaseExpiresAt":row.lease_expires_at,"completionState":completion,"outcome":outcome,"pendingAudit":pending.is_some(),
        "mocked":row.source.mode=="mock","providerWriteAttempted":attempted,"consumerApplied":"unknown"}),
    )
}
pub(super) async fn request(state: &AppState, submission: &Submission, id: Id) -> DomainResult<Value> {
    submission.authorize(state).await?;
    let row: Request = store::get(state, submission.principal.tenant, &util::key(REQUEST, id))
        .await?
        .ok_or_else(|| records::missing(id))?;
    records::request_identity(submission, &row, id, row.purpose, &row.input_hash)?;
    let mut items = Vec::new();
    for id in &row.item_ids {
        items.push(item(state, submission, *id).await?);
    }
    let mut attempts = Vec::new();
    for id in &row.attempt_ids {
        let original: Attempt =
            store::get(state, row.tenant, &util::key(ATTEMPT, *id)).await?.ok_or_else(util::corrupt)?;
        if original.request_id != row.id || !row.item_ids.contains(&original.item_id) {
            return Err(util::corrupt());
        }
        let item = records::load_item(state, row.tenant, original.item_id).await?;
        records::attempt(&original, &item)?;
        attempts.push(attempt(state, &original, &item).await?);
    }
    submission.authorize(state).await?;
    Ok(json!({"id":row.id,"purpose":row.purpose,"inputHash":row.input_hash,"submittedAt":row.submitted_at,
        "generation":row.generation,"changedCount":row.changed_count,"itemIds":row.item_ids,"attemptIds":row.attempt_ids,
        "items":items,"originalAttempts":attempts,"immutableIntent":true,"automaticRetry":false}))
}
async fn current(state: &AppState, tenant: agf_core::ids::TenantId) -> DomainResult<Option<source::Source>> {
    let row = crate::cloud_store::load(state, tenant, super::NAME).await?;
    let Some(row) = row.filter(|row| row.enabled) else {
        return Ok(None);
    };
    match source::from_row(state, tenant, &row) {
        Ok(source) => Ok(Some(source)),
        // A newly unsupported target cannot erase access to the original safe receipt.
        Err(DomainError::Validation(_) | DomainError::PreconditionFailed(_)) => Ok(None),
        Err(error) => Err(error),
    }
}
fn source_view(row: &source::Source) -> Value {
    json!({"configurationId":row.id,"configurationVersion":row.version,
    "groupId":row.group,"region":row.region,"transportMode":row.mode,"mocked":row.mode=="mock"})
}
