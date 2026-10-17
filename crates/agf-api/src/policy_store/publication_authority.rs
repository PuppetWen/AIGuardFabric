//! Fixed server-owned publication grants reuse the approved actor, lease and offline evidence rules.
use super::*;
use agf_storage::configuration::{OfflineGuardedSnapshot, OfflineSecurityRecords};

pub(crate) struct Grant {
    pub resource: &'static str,
    pub action: &'static str,
}
pub(crate) struct PublicationAuthorization {
    pub resource: &'static str,
    pub action: &'static str,
    pub additional: &'static [Grant],
}
pub(crate) struct AuthorizedSubmission<'a> {
    pub principal: &'a Principal,
    pub submitted_at: Timestamp,
    pub lease: Option<&'a AccessLease>,
    pub authorization: &'static PublicationAuthorization,
}

pub(crate) async fn authorize_publication(
    state: &AppState,
    submission: &AuthorizedSubmission<'_>,
) -> DomainResult<Principal> {
    let authorization = submission.authorization;
    let current = authority::authorize_for(
        state,
        submission.principal,
        authorization.resource,
        authorization.action,
        submission.submitted_at,
        submission.lease,
    )
    .await?;
    for grant in authorization.additional {
        current.require(state, grant.resource, grant.action).map_err(|error| error.error)?;
    }
    if let Some(lease) = submission.lease {
        lease.check_subject(submission.principal)?;
    }
    Ok(current)
}

pub(crate) struct OfflinePublicationProof(offline_authority::Proof);
impl OfflinePublicationProof {
    pub(crate) async fn prepare(state: &AppState, submission: &AuthorizedSubmission<'_>) -> DomainResult<Self> {
        let original = original(submission);
        let authorization = submission.authorization;
        let proof = offline_authority::prepare_for(
            state,
            &original,
            authorization.resource,
            authorization.action,
            authorization.additional,
        )
        .await?
        .ok_or_else(|| DomainError::Forbidden("发布事务缺少原认证身份".into()))?;
        Ok(Self(proof))
    }

    pub(crate) fn security(submission: &AuthorizedSubmission<'_>) -> DomainResult<OfflineSecurityRecords> {
        offline_authority::security(submission.principal)
    }

    /// This callback must not await or reenter the configuration-backed authorizer.
    pub(crate) fn check(
        &self,
        state: &AppState,
        submission: &AuthorizedSubmission<'_>,
        locked: &OfflineGuardedSnapshot,
    ) -> DomainResult<()> {
        let authorization = submission.authorization;
        offline_authority::tenant_enabled(submission.principal.tenant, locked.tenant_directory.as_ref())?;
        self.0.check_for(
            state,
            &original(submission),
            authorization.resource,
            authorization.action,
            authorization.additional,
            locked,
        )
    }
}

fn original<'a>(submission: &AuthorizedSubmission<'a>) -> mutation::Submission<'a> {
    mutation::Submission::management(submission.principal, submission.submitted_at, submission.lease.cloned())
}

#[cfg(test)]
mod tests;
