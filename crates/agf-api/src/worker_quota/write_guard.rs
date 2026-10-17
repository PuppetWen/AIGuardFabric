//! Recheck immediately before sending, including after cloud credential or queue waits.
use super::{
    contract::{Operation, SyncInput},
    operations,
};
use crate::{Principal, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
    rbac::SubjectKind,
    time::Timestamp,
};

pub(crate) struct WriteGuard<'a> {
    pub(super) state: &'a AppState,
    pub(super) principal: &'a Principal,
    pub(super) asset: Id,
    pub(super) run: Id,
    pub(super) input: &'a SyncInput,
}

impl WriteGuard<'_> {
    pub(crate) async fn validate(&self) -> DomainResult<()> {
        let run = self
            .state
            .configurations
            .get::<Operation>(self.principal.tenant, super::RUNS, self.run)
            .await?
            .ok_or_else(super::stale)?;
        authority(self.state, self.principal, "write", run.started_at).await?;
        let (binding, _) = operations::verified(
            self.state,
            self.principal,
            self.asset,
            self.input.expected_binding_version,
            self.input.expected_quota_version,
            self.input.configuration_version,
        )
        .await?;
        if binding
            .active
            .as_ref()
            .is_none_or(|active| active.run_id != self.run || active.expires_at <= Timestamp::now())
        {
            return Err(super::stale());
        }
        Ok(())
    }
}

/// Reads used by sync need write authority; an independent observation needs read authority.
pub(super) struct QuotaPermission<'a> {
    pub state: &'a AppState,
    pub principal: &'a Principal,
    pub action: &'static str,
    pub issued_at: Timestamp,
}
#[async_trait::async_trait]
impl crate::cloud_runtime::WritePrecondition for QuotaPermission<'_> {
    async fn validate(&self) -> DomainResult<()> {
        authority(self.state, self.principal, self.action, self.issued_at).await
    }
}
async fn authority(state: &AppState, principal: &Principal, action: &str, issued_at: Timestamp) -> DomainResult<()> {
    let current = crate::soar_workflow::Actor::from_principal(principal)?
        .resolve_for(state, principal.tenant, "quotas", action)
        .await?;
    if current.subject_kind == SubjectKind::User {
        let user = state
            .auth_backend
            .find_user(current.identity_tenant, current.subject_id.ok_or_else(super::stale)?)
            .await?
            .ok_or_else(super::stale)?;
        if !state.auth_backend.session_valid(current.identity_tenant, &user, issued_at.unix_millis()).await? {
            return Err(DomainError::Forbidden("同步期间账号安全设置已改变，请重新登录后核对回执".into()));
        }
    }
    Ok(())
}

#[async_trait::async_trait]
impl crate::cloud_runtime::WritePrecondition for WriteGuard<'_> {
    async fn validate(&self) -> DomainResult<()> {
        WriteGuard::validate(self).await
    }
}
