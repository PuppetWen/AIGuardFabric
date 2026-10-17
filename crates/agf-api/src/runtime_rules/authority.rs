use crate::{
    AppState, Principal,
    policy_store::{AccessLease, AuthorizedSubmission, PublicationAuthorization, authorize_publication},
};
use agf_core::{error::DomainResult, time::Timestamp};
use axum::http::HeaderMap;
use std::time::Duration;
use tokio::time::Instant;

static WRITE: PublicationAuthorization =
    PublicationAuthorization { resource: "policies", action: "write", additional: &[] };

pub(crate) struct Submission {
    pub(super) principal: Principal,
    pub(super) deadline: Instant,
    submitted_at: Timestamp,
    lease: Option<AccessLease>,
}
impl Submission {
    pub(crate) fn capture(state: &AppState, principal: &Principal, headers: &HeaderMap) -> DomainResult<Self> {
        let deadline = Instant::now() + Duration::from_secs(110);
        let submitted_at = Timestamp::now();
        principal.require(state, "policies", "write").map_err(|error| error.error)?;
        Ok(Self {
            principal: principal.clone(),
            deadline,
            submitted_at,
            lease: AccessLease::capture(state, principal, headers)?,
        })
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
            return Err(super::expired());
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
            .map_err(|_| super::expired())??;
        self.budget()
    }
}
