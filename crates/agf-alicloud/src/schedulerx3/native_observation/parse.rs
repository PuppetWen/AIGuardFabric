use super::{
    AppObservation, JobObservation, MAX_EVIDENCE_BYTES, MAX_JOBS, MAX_OBSERVATION_BYTES, MAX_PAGES, Observation,
    PAGE_SIZE, PageEvidence, Pagination, Schedule, Scope, fields,
};
use crate::http::RpcResponse;
use agf_core::error::{DomainError, DomainResult};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Validate GetApp and every ListJobs page into a safe complete observation.
///
/// All pages must be consecutive, use page size 100, share Total, contain unique job IDs
/// and exactly cover Total. Provider message, AccessToken and HTTP bodies are never exposed.
///
/// # Errors
/// Provider errors, invalid identity/field types, incomplete/drifting pages or budget violations.
pub fn parse_current(scope: &Scope, app: &RpcResponse, pages: &[RpcResponse]) -> DomainResult<Observation> {
    let mut collector = Collector::new(scope, app)?;
    for page in pages {
        collector.push(page)?;
    }
    collector.finish()
}

pub(super) struct Collector {
    scope: Scope,
    app: AppObservation,
    jobs: BTreeMap<String, JobObservation>,
    pages: Vec<PageEvidence>,
    total: Option<u32>,
    evidence_bytes: usize,
}

impl Collector {
    pub(super) fn new(scope: &Scope, response: &RpcResponse) -> DomainResult<Self> {
        scope.validate()?;
        let (data, _, evidence_bytes) = fields::data(response)?;
        let name = fields::required_text(data, "AppName", 256)?;
        if name != scope.app_name {
            return Err(fields::invalid());
        }
        let app = AppObservation {
            id: fields::identifier(data.get("Id").ok_or_else(fields::invalid)?)?,
            name: name.into(),
            title: fields::optional_text(data, "Title", 512)?,
            kind: fields::optional_integer(data, "AppType")?,
        };
        Ok(Self { scope: scope.clone(), app, jobs: BTreeMap::new(), pages: Vec::new(), total: None, evidence_bytes })
    }

    pub(super) fn next_page(&self) -> DomainResult<u32> {
        let number = u32::try_from(self.pages.len()).map_err(|_| fields::invalid())? + 1;
        if number > MAX_PAGES || self.complete() {
            return Err(fields::invalid());
        }
        Ok(number)
    }

    pub(super) fn push(&mut self, response: &RpcResponse) -> DomainResult<bool> {
        let expected = self.next_page()?;
        let (data, request_id, bytes) = fields::data(response)?;
        self.evidence_bytes = self.evidence_bytes.checked_add(bytes).ok_or_else(fields::invalid)?;
        if self.evidence_bytes > MAX_EVIDENCE_BYTES {
            return Err(fields::invalid());
        }
        let total = fields::required_count(data, "Total")?;
        let number = fields::required_count(data, "PageNumber")?;
        let size = fields::required_count(data, "PageSize")?;
        let records = data.get("Records").and_then(Value::as_array).ok_or_else(fields::invalid)?;
        let remaining = total.saturating_sub(self.jobs.len() as u32);
        if total > MAX_JOBS
            || number != expected
            || size != PAGE_SIZE
            || records.len() > PAGE_SIZE as usize
            || records.len() != remaining.min(PAGE_SIZE) as usize
            || self.total.is_some_and(|prior| prior != total)
        {
            return Err(fields::invalid());
        }
        self.total = Some(total);
        for record in records {
            let job = job(&self.scope, &self.app, record)?;
            if self.jobs.insert(job.id.clone(), job).is_some() {
                return Err(fields::invalid());
            }
        }
        let observed = self.jobs.len();
        if observed > total as usize || (records.is_empty() && observed != total as usize) {
            return Err(fields::invalid());
        }
        self.pages.push(PageEvidence { number, size, records: records.len(), request_id });
        Ok(self.complete())
    }

    fn complete(&self) -> bool {
        self.total.is_some_and(|total| self.jobs.len() == total as usize)
    }

    pub(super) fn finish(self) -> DomainResult<Observation> {
        if !self.complete() {
            return Err(DomainError::PreconditionFailed(
                "Scheduler job listing is incomplete; preserve the previous observation".into(),
            ));
        }
        let total = self.total.ok_or_else(fields::invalid)?;
        let jobs: Vec<_> = self.jobs.into_values().collect();
        let fingerprint = fields::hash(&json!({"scope":self.scope,"app":self.app,"jobs":jobs,"total":total}))?;
        let observation = Observation {
            scope: self.scope,
            app: self.app,
            jobs,
            pagination: Pagination { total, listing_complete: true, strong_snapshot: false, pages: self.pages },
            fingerprint,
        };
        if serde_json::to_vec(&observation)?.len() > MAX_OBSERVATION_BYTES {
            return Err(fields::invalid());
        }
        Ok(observation)
    }
}

fn job(scope: &Scope, app: &AppObservation, data: &Value) -> DomainResult<JobObservation> {
    let app_name = fields::required_text(data, "AppName", 256)?.to_owned();
    let app_id = fields::optional_identifier(data, "AppGroupId")?;
    if app_name != scope.app_name || app_id.as_ref().is_some_and(|id| *id != app.id) {
        return Err(fields::invalid());
    }
    let status = fields::optional_integer(data, "Status")?;
    if status.is_some_and(|status| !matches!(status, 0 | 1)) {
        return Err(fields::invalid());
    }
    let kind = fields::optional_text(data, "JobType", 64)?;
    let zone = fields::zone(data)?;
    Ok(JobObservation {
        id: fields::identifier(data.get("JobId").ok_or_else(fields::invalid)?)?,
        app_name,
        app_id,
        name: fields::required_text(data, "Name", 512)?.into(),
        http_job: kind.as_deref() == Some("http"),
        kind,
        status,
        enabled: status.map(|status| status == 1),
        schedule: Schedule {
            kind: fields::optional_integer(data, "TimeType")?,
            expression: fields::optional_text(data, "TimeExpression", 256)?,
            calendar: fields::optional_text(data, "Calendar", 256)?,
            utc: zone.as_ref().map(|zone| zone == "UTC"),
            zone,
        },
        max_attempt: fields::nonnegative(data, "MaxAttempt")?,
        attempt_interval: fields::nonnegative(data, "AttemptInterval")?,
        route_strategy: fields::nonnegative(data, "RouteStrategy")?,
        shard_count: None,
        update_time_native: fields::native_time(data)?,
        http: fields::opaque(data)?,
    })
}
