use super::util;
use crate::{
    AppState, Principal,
    policy_store::{AccessLease, AuthorizedSubmission, PublicationAuthorization, authorize_publication},
};
use agf_core::{error::DomainResult, time::Timestamp};
use axum::http::HeaderMap;
use tokio::time::Instant;

static WRITE: PublicationAuthorization =
    PublicationAuthorization { resource: "models", action: "write", additional: &[] };

pub(crate) struct Submission {
    pub(super) principal: Principal,
    submitted_at: Timestamp,
    lease: Option<AccessLease>,
    pub(super) deadline: Instant,
}
impl Submission {
    pub(crate) fn capture(
        state: &AppState,
        principal: &Principal,
        headers: &HeaderMap,
        deadline: Instant,
    ) -> DomainResult<Self> {
        principal.require(state, "models", "write").map_err(|error| error.error)?;
        let submission = Self {
            principal: principal.clone(),
            submitted_at: Timestamp::now(),
            lease: AccessLease::capture(state, principal, headers)?,
            deadline,
        };
        submission.budget()?;
        Ok(submission)
    }
    pub(super) fn borrowed(&self) -> AuthorizedSubmission<'_> {
        AuthorizedSubmission {
            principal: &self.principal,
            submitted_at: self.submitted_at,
            lease: self.lease.as_ref(),
            authorization: &WRITE,
        }
    }
    pub(super) fn budget(&self) -> DomainResult<()> {
        if Instant::now() >= self.deadline {
            return Err(util::stale());
        }
        if let Some(lease) = &self.lease {
            lease.check_subject(&self.principal)?;
        }
        Ok(())
    }
    pub(super) async fn authorize(&self, state: &AppState) -> DomainResult<()> {
        self.budget()?;
        tokio::time::timeout_at(self.deadline, authorize_publication(state, &self.borrowed()))
            .await
            .map_err(|_| util::stale())??;
        self.budget()
    }
}
