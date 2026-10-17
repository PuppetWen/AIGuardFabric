//! Grant-bearing model calls and fixed identity-only Failure publication are distinct capabilities.
use super::{records::Origin, store};
use crate::{
    Principal,
    policy_store::{AccessLease, AuthorizedSubmission, PublicationAuthorization},
    state::AppState,
};
use agf_core::{
    error::{DomainError, DomainResult},
    time::Timestamp,
};

static MODELS: PublicationAuthorization =
    PublicationAuthorization { resource: "models", action: "write", additional: &[] };

pub(super) struct Submission<'a> {
    pub(super) principal: &'a Principal,
    pub(super) lease: Option<&'a AccessLease>,
    pub(super) submitted_at: Timestamp,
    pub(super) deadline: tokio::time::Instant,
}

impl Submission<'_> {
    pub(super) async fn models(&self, state: &AppState, origin: &Origin) -> DomainResult<()> {
        self.current_models(state, origin).await.map(|_| ())
    }
    pub(super) async fn current_models(&self, state: &AppState, origin: &Origin) -> DomainResult<Principal> {
        budget(self.deadline)?;
        let current = crate::policy_store::authorize_publication(
            state,
            &AuthorizedSubmission {
                principal: self.principal,
                lease: self.lease,
                submitted_at: self.submitted_at,
                authorization: &MODELS,
            },
        )
        .await?;
        origin.matches(&current)?;
        budget(self.deadline)?;
        Ok(current)
    }

    pub(super) async fn failure(&self, state: &AppState, origin: &Origin) -> DomainResult<()> {
        budget(self.deadline)?;
        origin.matches(self.principal)?;
        crate::policy_store::AuthenticatedRejection::capture(self.principal, self.lease, self.submitted_at)?
            .recheck(state)
            .await?;
        budget(self.deadline)
    }
}

pub(super) fn budget(deadline: tokio::time::Instant) -> DomainResult<()> {
    if tokio::time::Instant::now() >= deadline {
        return Err(DomainError::Timeout("Gateway original execution or local publication budget expired".into()));
    }
    Ok(())
}

pub(super) fn database(state: &AppState) -> DomainResult<&agf_storage::Store> {
    state.store.database().map(std::sync::Arc::as_ref).ok_or_else(store::missing)
}
