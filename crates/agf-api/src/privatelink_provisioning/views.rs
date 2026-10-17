use super::{
    authority::Submission,
    model::{Fact, Pending, Phase, ResultData},
    records, source, staging, store, util,
};
use crate::state::AppState;
use agf_core::{
    error::DomainResult,
    ids::{Id, TenantId},
    time::Timestamp,
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
pub(super) fn safe_source(source: &source::Source) -> Value {
    json!({"configurationId":source.id,"configurationVersion":source.version,"configuredAccountLabel":source.account_label,"accountIdentityVerified":false,"region":source.region,"transportMode":source.mode,"mocked":source.mode=="mock"})
}
pub(super) fn safe_result(result: &ResultData) -> Value {
    match result {
        ResultData::Preview { expires_at, base_generation } => {
            json!({"kind":"preview","expiresAt":expires_at,"baseGeneration":base_generation})
        }
        ResultData::Write { outcome } => {
            json!({"kind":"write","delivery":outcome.delivery,"providerRequestId":outcome.provider_request_id,"endpointId":outcome.endpoint_id,"finishedAt":outcome.finished_at})
        }
        ResultData::Observed { evidence } => {
            json!({"kind":"observation","endpointId":evidence.observation.endpoint_id,"endpointState":evidence.observation.endpoint_state,"connectionState":evidence.observation.connection_state,"requestedResourcesMatch":evidence.observation.requested_resources_match,"connectivityVerified":false,"checkedAt":evidence.checked_at,"originalCreateRequestId":evidence.original_create_id,"inventoryScopeId":evidence.inventory_scope_id,"serviceId":evidence.plan.service_id,"vpcId":evidence.plan.vpc_id,"region":evidence.plan.region_id,"serviceRegion":evidence.plan.service_region_id})
        }
        ResultData::FailedRead => json!({"kind":"failed_read"}),
        ResultData::Archived { changed_count, generation } => {
            json!({"kind":"archive","changedCount":changed_count,"generation":generation})
        }
    }
}
pub(super) fn summary(intent: &super::model::Intent) -> Value {
    let p = intent.planned();
    json!({"serviceId":p.service_id,"vpcId":p.vpc_id,"region":p.region_id,"serviceRegion":p.service_region_id,"name":p.name,"zones":p.zones.iter().map(|z|json!({"zoneId":z.zone_id,"vSwitchId":z.vswitch_id})).collect::<Vec<_>>(),"securityGroupIds":p.security_group_ids,"crossRegionBandwidth":p.cross_region_bandwidth,"endpointId":intent.endpoint()})
}
pub(super) async fn current(state: &AppState, tenant: TenantId) -> DomainResult<Option<source::Source>> {
    let row = crate::cloud_store::load(state, tenant, super::NAME).await?;
    row.filter(|row| row.enabled).map(|r| source::from_row(state, tenant, &r)).transpose()
}
pub(super) async fn receipt(state: &AppState, submission: &Submission, id: Id) -> DomainResult<Value> {
    submission.authorize(state).await?;
    let row = records::load(state, submission.principal.tenant, id).await?;
    submission.own(&row.owner)?;
    let current = current(state, row.tenant).await?;
    project(state, submission, &row, current.as_ref()).await
}
async fn project(
    state: &AppState,
    submission: &Submission,
    row: &Fact,
    current: Option<&source::Source>,
) -> DomainResult<Value> {
    let pending = store::get::<Pending>(state, row.tenant, &util::key(super::PENDING, row.id)).await?;
    if let Some(p) = &pending {
        staging::validate(p, row)?;
    }
    let result = pending.as_ref().map(|p| &p.outcome).or(row.result.as_ref());
    let source_current = row.source.as_ref().is_some_and(|s| Some(s) == current);
    let can_write = submission.principal.require(state, "alicloud", "write").is_ok();
    submission.authorize(state).await?;
    Ok(
        json!({"requestId":row.id,"purpose":row.purpose,"inputHash":row.input_hash,"submittedAt":row.submitted_at,"admittedAt":row.admitted_at,"startedAt":row.started_at,"leaseExpiresAt":row.lease_expires_at,"phase":row.phase,"completionState":if row.phase==Phase::Complete{"complete"}else if pending.is_some(){"pending_audit"}else if row.lease_expires_at<=Timestamp::now(){"uncertain"}else{"in_flight"},"originalSource":row.source.as_ref().map(safe_source),"sourceCurrent":source_current,"action":row.intent.as_ref().map(|i|i.prepare(row.id).map(|p|p.action())).transpose()?,"resourceSummary":row.intent.as_ref().map(summary),"referenceRequestId":row.reference,"result":result.map(safe_result),"archived":row.archived_at.is_some(),"archivedAt":row.archived_at,"canRecoverLocal":can_write&&row.phase!=Phase::Complete&&(pending.is_some()||row.lease_expires_at<=Timestamp::now()),"canArchive":can_write&&row.phase==Phase::Complete&&row.archived_at.is_none(),"canRedispatch":false,"automaticRetry":false,"connectivityVerified":false,"ramAuthorizationVerified":false}),
    )
}
pub(super) async fn state(state: &AppState, submission: &Submission, page: Page) -> DomainResult<Value> {
    submission.authorize(state).await?;
    if page.page == 0 || !(1..=50).contains(&page.page_size) {
        return Err(util::invalid());
    }
    let tenant = submission.principal.tenant;
    let journal = store::journal(state, tenant).await?;
    let source = current(state, tenant).await?;
    let mut requests = vec![];
    let start = u64::from(page.page - 1) * u64::from(page.page_size);
    for id in
        journal.items.iter().rev().skip(usize::try_from(start).unwrap_or(usize::MAX)).take(page.page_size as usize)
    {
        let row = records::load(state, tenant, *id).await?;
        if row.owner == submission.owner() {
            requests.push(project(state, submission, &row, source.as_ref()).await?);
        }
    }
    submission.authorize(state).await?;
    Ok(
        json!({"generation":journal.generation,"storedContentBytes":journal.stored_bytes,"permanentFactCount":journal.facts,"page":page.page,"pageSize":page.page_size,"total":journal.items.len(),"requests":requests,"source":source.as_ref().map(safe_source),"inventorySelection":super::inventory::available(state,tenant).await?,"unresolvedWriteCount":journal.risks.len(),"limits":{"detailedRequests":super::MAX_ITEMS,"permanentFacts":super::MAX_FACTS,"archiveBatch":32,"bodyBytes":2*1024*1024,"originalSeconds":110,"previewSeconds":300},"automaticRetry":false,"exactlyOnce":false,"connectivityVerified":false,"ramAuthorizationVerified":false}),
    )
}
