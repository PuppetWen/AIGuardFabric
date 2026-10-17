//! The plan is pure read, but every awaited inventory read retains the original identity lease.
use crate::{
    Principal,
    policy_store::{AccessLease, AuthorizedSubmission, Grant, PublicationAuthorization, authorize_publication},
    state::AppState,
};
use agf_core::{error::DomainResult, time::Timestamp};
use axum::http::HeaderMap;

const AGENTS: PublicationAuthorization =
    PublicationAuthorization { resource: "agents", action: "read", additional: &[] };
const SDK: PublicationAuthorization = PublicationAuthorization {
    resource: "agents",
    action: "read",
    additional: &[Grant { resource: "sources", action: "read" }, Grant { resource: "alicloud", action: "read" }],
};
const MODEL: PublicationAuthorization = PublicationAuthorization {
    resource: "agents",
    action: "read",
    additional: &[Grant { resource: "models", action: "read" }],
};

pub(super) struct ReadAuthority<'a> {
    principal: &'a Principal,
    submitted_at: Timestamp,
    lease: Option<AccessLease>,
    authorization: &'static PublicationAuthorization,
}
impl<'a> ReadAuthority<'a> {
    pub(super) fn capture(
        state: &AppState,
        principal: &'a Principal,
        headers: &HeaderMap,
        sdk: bool,
        model: bool,
    ) -> DomainResult<Self> {
        Ok(Self {
            principal,
            submitted_at: Timestamp::now(),
            lease: AccessLease::capture(state, principal, headers)?,
            authorization: if sdk {
                &SDK
            } else if model {
                &MODEL
            } else {
                &AGENTS
            },
        })
    }
    pub(super) async fn check(&self, state: &AppState) -> DomainResult<()> {
        authorize_publication(
            state,
            &AuthorizedSubmission {
                principal: self.principal,
                submitted_at: self.submitted_at,
                lease: self.lease.as_ref(),
                authorization: self.authorization,
            },
        )
        .await?;
        Ok(())
    }
}
