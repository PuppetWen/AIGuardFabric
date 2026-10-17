//! Existing grants and original access-token lease; no invented replay authorization.
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

static READ: PublicationAuthorization = PublicationAuthorization {
    resource: "alicloud",
    action: "read",
    additional: &[Grant { resource: "sources", action: "read" }],
};
static WRITE: PublicationAuthorization = PublicationAuthorization {
    resource: "alicloud",
    action: "write",
    additional: &[Grant { resource: "sources", action: "write" }],
};
pub(super) struct Submission {
    pub(super) principal: Principal,
    pub(super) lease: Option<AccessLease>,
    pub(super) submitted_at: Timestamp,
    pub(super) deadline: tokio::time::Instant,
    write: bool,
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
        Ok(Self { principal, lease, submitted_at, deadline, write })
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
        self.budget()?;
        let principal =
            bounded(self.deadline, crate::policy_store::authorize_publication(state, &self.borrowed())).await?;
        self.budget()?;
        Ok(principal)
    }
    pub(super) fn actor(&self) -> DomainResult<super::Actor> {
        let actor = super::Actor {
            subject_id: self.principal.subject_id.ok_or_else(super::util::corrupt)?,
            identity_tenant: self.principal.identity_tenant,
            subject_kind: self.principal.subject_kind.as_str().into(),
        };
        actor.validate()?;
        Ok(actor)
    }
    pub(super) fn budget(&self) -> DomainResult<()> {
        if tokio::time::Instant::now() >= self.deadline {
            return Err(expired());
        }
        Ok(())
    }
}
pub(super) async fn bounded<T>(
    deadline: tokio::time::Instant,
    future: impl std::future::Future<Output = DomainResult<T>>,
) -> DomainResult<T> {
    tokio::time::timeout_at(deadline, future).await.map_err(|_| expired())?
}
fn expired() -> DomainError {
    DomainError::Timeout("人工处理原110秒预算已过期；未提交的标注和审计保持不变".into())
}
