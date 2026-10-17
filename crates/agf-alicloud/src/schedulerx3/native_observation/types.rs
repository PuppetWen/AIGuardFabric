use agf_core::error::{DomainError, DomainResult};
use serde::Serialize;

/// The explicitly configured application in one resolved SchedulerX3 source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Scope {
    /// Existing cloud cluster identifier; never inferred from a job name.
    pub cluster_id: String,
    /// Existing application name, compared with GetApp and every returned job.
    pub app_name: String,
}

impl Scope {
    /// Validate the two required configured identifiers.
    ///
    /// # Errors
    /// Empty, oversized, surrounding-whitespace or control-character identifiers are rejected.
    pub fn validate(&self) -> DomainResult<()> {
        if [&self.cluster_id, &self.app_name].iter().any(|value| {
            value.is_empty()
                || value.len() > 256
                || value.trim() != value.as_str()
                || value.chars().any(char::is_control)
        }) {
            return Err(DomainError::Validation("Scheduler application scope is invalid".into()));
        }
        Ok(())
    }
}

/// Safe GetApp identity; cloud application AccessToken is deliberately omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppObservation {
    /// Canonical positive int64 rendered as a string to preserve browser precision.
    pub id: String,
    /// Exactly the configured AppName.
    pub name: String,
    /// Optional public title; absence is unknown.
    pub title: Option<String>,
    /// Observed numeric AppType; no HTTP semantics are inferred from it.
    pub kind: Option<i32>,
}

/// The presence of an opaque provider field, without exposing its contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CarrierPresence {
    /// The provider did not return the field.
    Missing,
    /// The provider explicitly returned null.
    Null,
    /// The provider explicitly returned an empty string.
    Empty,
    /// A nonempty opaque string was returned.
    Present,
}

/// Opaque HTTP configuration evidence, never a verified HTTP request profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpConfiguration {
    /// Always false until a separate public HTTP carrier contract is implemented.
    pub verified: bool,
    /// Parameters presence; its JSON/string body and credentials are not exposed.
    pub parameters: CarrierPresence,
    /// JobHandler presence; not interpreted as a URL or callback path.
    pub handler: CarrierPresence,
    /// Xattrs/XAttrs presence; conflicting aliases are rejected.
    pub attributes: CarrierPresence,
    /// Script presence; script contents are not exposed.
    pub script: CarrierPresence,
    /// SHA256 of bounded opaque fields, including their presence, for drift detection only.
    pub fingerprint: String,
}

/// Explicit control-plane scheduling observations; missing values remain unknown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Schedule {
    /// Observed TimeType; no five-field to Quartz conversion is performed.
    pub kind: Option<i32>,
    /// Observed expression, without calculating next execution times.
    pub expression: Option<String>,
    /// Calendar name; existence and holiday coverage are not verified here.
    pub calendar: Option<String>,
    /// Explicit TimeZone/Timezone, or null when it was not provided.
    pub zone: Option<String>,
    /// Null for unknown, true only for literal UTC, false for another observed value.
    pub utc: Option<bool>,
}

/// Safe job identity and observations, without Parameters/Xattrs/JobHandler/Script bodies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JobObservation {
    /// Canonical positive int64 string.
    pub id: String,
    /// Exact AppName from the provider response.
    pub app_name: String,
    /// Explicit AppGroupId, if provided; it must match the observed application Id.
    pub app_id: Option<String>,
    /// Public name; no ownership is inferred from it.
    pub name: String,
    /// Actual JobType, or null when unknown.
    pub kind: Option<String>,
    /// True only for explicit JobType=http; not a proof of callback configuration.
    pub http_job: bool,
    /// Actual status 0 or 1, or null; absent status is never treated as disabled.
    pub status: Option<i32>,
    /// Null for unknown status, otherwise whether status equals 1.
    pub enabled: Option<bool>,
    /// Actual scheduling fields, with no inferred UTC default.
    pub schedule: Schedule,
    /// Actual retry count, if returned.
    pub max_attempt: Option<i32>,
    /// Native retry interval; no unit conversion is claimed.
    pub attempt_interval: Option<i32>,
    /// Actual route strategy; it does not prove a fixed shard count.
    pub route_strategy: Option<i32>,
    /// Always null: actual shards require authenticated execution evidence.
    pub shard_count: Option<u32>,
    /// Native UpdateTime integer; it is not converted to a guessed timestamp unit.
    pub update_time_native: Option<String>,
    /// Presence and digest of opaque configuration; no HTTP secrets are included.
    pub http: HttpConfiguration,
}

/// Safe provider receipt and paging facts for one successful page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PageEvidence {
    /// Strictly checked consecutive PageNumber, starting at 1.
    pub number: u32,
    /// Provider PageSize must equal the requested 100.
    pub size: u32,
    /// Actual number of records on this page.
    pub records: usize,
    /// Safe RequestId; it does not prove authorization or data-plane execution.
    pub request_id: String,
}

/// A complete traversal under the documented list contract, not a strong cloud snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Pagination {
    /// The explicitly returned, stable Total, including a real observed zero.
    pub total: u32,
    /// True only after all records exactly match Total with no duplicates.
    pub listing_complete: bool,
    /// Always false: the provider offers no list snapshot token or CAS here.
    pub strong_snapshot: bool,
    /// Bounded page metadata.
    pub pages: Vec<PageEvidence>,
}

/// Validated safe observation; it is constructed only by the strict parser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    pub(super) scope: Scope,
    pub(super) app: AppObservation,
    pub(super) jobs: Vec<JobObservation>,
    pub(super) pagination: Pagination,
    pub(super) fingerprint: String,
}

impl Observation {
    /// The configured source-local scope.
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// Actual application identity, with no AccessToken.
    pub fn app(&self) -> &AppObservation {
        &self.app
    }

    /// All validated jobs, sorted by canonical ID string.
    pub fn jobs(&self) -> &[JobObservation] {
        &self.jobs
    }

    /// Exact bounded traversal facts, explicitly not a strong cloud snapshot.
    pub fn pagination(&self) -> &Pagination {
        &self.pagination
    }

    /// Stable SHA256 of scope, safe observations and opaque carrier digests.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}
