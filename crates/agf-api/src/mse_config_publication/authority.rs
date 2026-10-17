//! Server-owned grants reuse the policy publication facade without copying RBAC or MFA rules.
use crate::{
    Principal,
    policy_store::{AccessLease, AuthorizedSubmission, Grant, PublicationAuthorization},
    state::AppState,
};
use agf_core::{
    error::{DomainError, DomainResult},
    time::Timestamp,
};
use axum::http::HeaderMap;

pub(super) static READ: PublicationAuthorization = PublicationAuthorization {
    resource: "alicloud",
    action: "read",
    additional: &[Grant { resource: "policies", action: "read" }],
};
pub(super) static WRITE: PublicationAuthorization = PublicationAuthorization {
    resource: "alicloud",
    action: "write",
    additional: &[Grant { resource: "alicloud", action: "read" }, Grant { resource: "policies", action: "read" }],
};

pub(super) struct Submission {
    pub principal: Principal,
    pub submitted_at: Timestamp,
    pub lease: Option<AccessLease>,
    pub write: bool,
    pub deadline: tokio::time::Instant,
}
impl Submission {
    pub(super) fn capture(
        state: &AppState,
        principal: Principal,
        headers: &HeaderMap,
        write: bool,
    ) -> DomainResult<Self> {
        let submitted_at = Timestamp::now();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(110);
        let lease = AccessLease::capture(state, &principal, headers)?;
        Ok(Self { principal, submitted_at, lease, write, deadline })
    }
    pub(super) fn borrowed(&self) -> AuthorizedSubmission<'_> {
        AuthorizedSubmission {
            principal: &self.principal,
            submitted_at: self.submitted_at,
            lease: self.lease.as_ref(),
            authorization: if self.write { &WRITE } else { &READ },
        }
    }
    pub(super) async fn authorize(&self, state: &AppState) -> DomainResult<Principal> {
        crate::policy_store::authorize_publication(state, &self.borrowed()).await
    }
    pub(super) fn check_budget(&self) -> DomainResult<()> {
        if tokio::time::Instant::now() >= self.deadline {
            return Err(DomainError::Timeout("原操作总执行预算已过期；永久领取保留，禁止继续云派发".into()));
        }
        Ok(())
    }
}
