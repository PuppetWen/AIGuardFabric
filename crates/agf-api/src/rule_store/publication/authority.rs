use crate::{
    AppState, Principal,
    policy_store::{AccessLease, AuthorizedSubmission, PublicationAuthorization, authorize_publication},
};
use agf_core::{error::DomainResult, time::Timestamp};
use axum::http::HeaderMap;
use std::time::Duration;
use tokio::time::Instant;

static RULES: PublicationAuthorization =
    PublicationAuthorization { resource: "rules", action: "write", additional: &[] };
static SKILLS: PublicationAuthorization =
    PublicationAuthorization { resource: "skills", action: "write", additional: &[] };

#[derive(Clone, Copy)]
pub(crate) enum Grant {
    Rules,
    Skills,
}
pub(crate) struct Submission {
    pub(crate) principal: Principal,
    pub(crate) deadline: Instant,
    submitted_at: Timestamp,
    lease: Option<AccessLease>,
    authorization: &'static PublicationAuthorization,
}
impl Submission {
    pub(crate) fn capture(
        state: &AppState,
        principal: &Principal,
        headers: &HeaderMap,
        grant: Grant,
    ) -> DomainResult<Self> {
        let authorization = match grant {
            Grant::Rules => &RULES,
            Grant::Skills => &SKILLS,
        };
        let deadline = Instant::now() + Duration::from_secs(110);
        let submitted_at = Timestamp::now();
        principal.require(state, authorization.resource, authorization.action).map_err(|error| error.error)?;
        Ok(Self {
            principal: principal.clone(),
            deadline,
            submitted_at,
            lease: AccessLease::capture(state, principal, headers)?,
            authorization,
        })
    }
    pub(crate) fn borrowed(&self) -> AuthorizedSubmission<'_> {
        AuthorizedSubmission {
            principal: &self.principal,
            submitted_at: self.submitted_at,
            lease: self.lease.as_ref(),
            authorization: self.authorization,
        }
    }
    pub(crate) fn budget(&self) -> DomainResult<()> {
        if Instant::now() >= self.deadline {
            return Err(super::expired());
        }
        if let Some(lease) = &self.lease {
            lease.check_subject(&self.principal)?;
        }
        Ok(())
    }
    pub(crate) async fn authorize(&self, state: &AppState) -> DomainResult<()> {
        self.budget()?;
        tokio::time::timeout_at(self.deadline, authorize_publication(state, &self.borrowed()))
            .await
            .map_err(|_| super::expired())??;
        self.budget()
    }
}
