use super::{model::Owner, util};
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
use tokio::time::{Instant, timeout_at};

static READ: PublicationAuthorization =
    PublicationAuthorization { resource: "alicloud", action: "read", additional: &[] };
static WRITE: PublicationAuthorization = PublicationAuthorization {
    resource: "alicloud",
    action: "write",
    additional: &[Grant { resource: "alicloud", action: "read" }],
};

#[derive(Clone)]
pub(super) struct Submission {
    pub principal: Principal,
    pub submitted_at: Timestamp,
    pub deadline: Instant,
    pub lease: Option<AccessLease>,
    pub write: bool,
}
impl Submission {
    pub(super) fn capture(
        state: &AppState,
        principal: Principal,
        headers: &HeaderMap,
        write: bool,
    ) -> DomainResult<Self> {
        let submitted_at = Timestamp::now();
        let deadline = Instant::now() + std::time::Duration::from_secs(110);
        let lease = AccessLease::capture(state, &principal, headers)?;
        if principal.tenant.as_uuid().is_nil() || principal.subject_id.is_none() {
            return Err(util::invalid());
        }
        Ok(Self { principal, submitted_at, deadline, lease, write })
    }
    pub(super) fn borrowed(&self) -> AuthorizedSubmission<'_> {
        AuthorizedSubmission {
            principal: &self.principal,
            submitted_at: self.submitted_at,
            lease: self.lease.as_ref(),
            authorization: if self.write { &WRITE } else { &READ },
        }
    }
    pub(super) fn owner(&self) -> Owner {
        Owner {
            tenant: self.principal.tenant,
            identity_tenant: self.principal.identity_tenant,
            kind: self.principal.subject_kind,
            subject: self.principal.subject_id,
            agent: self.principal.agent_id,
        }
    }
    pub(super) fn own(&self, owner: &Owner) -> DomainResult<()> {
        if self.owner() != *owner {
            return Err(DomainError::Forbidden(
                "CMS intent belongs to a different original subject or agent binding".into(),
            ));
        }
        Ok(())
    }
    pub(super) fn budget(&self) -> DomainResult<()> {
        if Instant::now() >= self.deadline {
            return Err(expired());
        }
        Ok(())
    }
    pub(super) async fn authorize(&self, state: &AppState) -> DomainResult<()> {
        self.budget()?;
        bounded(self.deadline, crate::policy_store::authorize_publication(state, &self.borrowed())).await?;
        self.budget()
    }
}
pub(super) async fn bounded<T>(
    deadline: Instant,
    future: impl std::future::Future<Output = DomainResult<T>>,
) -> DomainResult<T> {
    if Instant::now() >= deadline {
        return Err(expired());
    }
    timeout_at(deadline, future).await.map_err(|_| expired())?
}
fn expired() -> DomainError {
    DomainError::Timeout("CMS original operation budget expired; its claimed UUID is never dispatched again".into())
}
