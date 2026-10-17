//! Policy-store child: authenticate a fixed internal Failure publisher without a business grant.
//! This is NOT a public route authorizer or a replacement for Actor::resolve_for on successful calls.
use super::AccessLease;
use crate::{Principal, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    rbac::SubjectKind,
    time::Timestamp,
};

pub(crate) struct AuthenticatedRejection<'a> {
    original: &'a Principal,
    lease: Option<&'a AccessLease>,
    submitted_at: Timestamp,
}

impl<'a> AuthenticatedRejection<'a> {
    // Called only by the fixed gateway rejection publisher after Principal extraction.
    pub(crate) fn capture(
        original: &'a Principal,
        lease: Option<&'a AccessLease>,
        submitted_at: Timestamp,
    ) -> DomainResult<Self> {
        if original.subject_id.is_none_or(|id| id.is_nil())
            || original.tenant.as_uuid().is_nil()
            || original.identity_tenant.as_uuid().is_nil()
            || (original.subject_kind == SubjectKind::User && lease.is_none())
        {
            return Err(DomainError::Unauthenticated(
                "Gateway rejection requires its original authenticated identity".into(),
            ));
        }
        Ok(Self { original, lease, submitted_at })
    }

    pub(crate) async fn recheck(&self, state: &AppState) -> DomainResult<()> {
        if let Some(lease) = self.lease {
            lease.check_subject(self.original)?;
        }
        // Uses the same current identity resolver as existing successful business callers.
        // Their final require(group,action) remains intact; this has no fabricated grant.
        let current = crate::soar_workflow::Actor::from_principal(self.original)?
            .resolve_identity(state, self.original.tenant)
            .await?;
        if current.agent_id != self.original.agent_id {
            return Err(DomainError::Forbidden("Gateway bound Agent changed".into()));
        }
        if current.subject_kind == SubjectKind::User {
            let subject = current.subject_id.ok_or_else(|| DomainError::Unauthenticated("Missing subject".into()))?;
            let user = state
                .auth_backend
                .find_user(current.identity_tenant, subject)
                .await?
                .ok_or_else(|| DomainError::Forbidden("Gateway subject no longer exists".into()))?;
            let issued_at = self.lease.map_or(self.submitted_at.unix_millis(), |lease| lease.issued_at_ms);
            if !state.auth_backend.session_valid(current.identity_tenant, &user, issued_at).await? {
                return Err(DomainError::Forbidden("Gateway original session security changed".into()));
            }
        }
        if let Some(lease) = self.lease {
            lease.check_subject(self.original)?;
        }
        Ok(())
    }
}
