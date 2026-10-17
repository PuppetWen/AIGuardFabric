use crate::{
    AppState, Principal,
    policy_store::{self, AccessLease, AuthorizedSubmission, Grant, PublicationAuthorization},
};
use agf_core::{
    error::{DomainError, DomainResult},
    time::Timestamp,
};
use axum::http::HeaderMap;
use tokio::time::Instant;

static EXECUTE: PublicationAuthorization = PublicationAuthorization {
    resource: "redteam",
    action: "execute",
    additional: &[Grant { resource: "agents", action: "read" }, Grant { resource: "mcps", action: "read" }],
};
static READ: PublicationAuthorization = PublicationAuthorization {
    resource: "redteam",
    action: "read",
    additional: &[Grant { resource: "agents", action: "read" }, Grant { resource: "mcps", action: "read" }],
};
static ADMIN: PublicationAuthorization = PublicationAuthorization {
    resource: "platform",
    action: "admin",
    additional: &[
        Grant { resource: "redteam", action: "execute" },
        Grant { resource: "agents", action: "read" },
        Grant { resource: "mcps", action: "read" },
    ],
};

pub(super) struct Authority {
    pub principal: Principal,
    pub submitted_at: Timestamp,
    pub deadline: Instant,
    lease: Option<AccessLease>,
    read: bool,
}
impl Authority {
    pub(super) async fn admin(&self, state: &AppState) -> DomainResult<()> {
        if self.principal.subject_kind != agf_core::rbac::SubjectKind::User {
            return Err(DomainError::Forbidden(
                "Managed target transport approval requires a current administrator User session".into(),
            ));
        }
        self.within(policy_store::authorize_publication(
            state,
            &AuthorizedSubmission {
                principal: &self.principal,
                submitted_at: self.submitted_at,
                lease: self.lease.as_ref(),
                authorization: &ADMIN,
            },
        ))
        .await?;
        Ok(())
    }
    pub(super) fn capture(
        state: &AppState,
        principal: Principal,
        headers: &HeaderMap,
        read: bool,
    ) -> DomainResult<Self> {
        let submitted_at = Timestamp::now();
        let deadline = Instant::now() + std::time::Duration::from_secs(110);
        let lease = AccessLease::capture(state, &principal, headers)?;
        Ok(Self { principal, submitted_at, deadline, lease, read })
    }
    pub(super) async fn check(&self, state: &AppState) -> DomainResult<()> {
        self.within(policy_store::authorize_publication(
            state,
            &AuthorizedSubmission {
                principal: &self.principal,
                submitted_at: self.submitted_at,
                lease: self.lease.as_ref(),
                authorization: if self.read { &READ } else { &EXECUTE },
            },
        ))
        .await?;
        Ok(())
    }
    pub(super) async fn within<T>(
        &self,
        future: impl std::future::Future<Output = DomainResult<T>>,
    ) -> DomainResult<T> {
        self.budget()?;
        let value = tokio::time::timeout_at(self.deadline, future)
            .await
            .map_err(|_| DomainError::Timeout("redteam multi-target original budget".into()))??;
        self.budget()?;
        Ok(value)
    }
    pub(super) fn budget(&self) -> DomainResult<()> {
        if Instant::now() >= self.deadline {
            return Err(DomainError::Timeout("redteam multi-target original budget".into()));
        }
        Ok(())
    }
}
