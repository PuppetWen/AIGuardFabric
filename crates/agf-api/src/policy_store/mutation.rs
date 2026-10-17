//! A prepared candidate is never published before its successful audit.
use super::*;
use agf_core::audit::AuditActor;

#[derive(Clone)]
pub(super) struct Submission<'a> {
    pub tenant: TenantId,
    pub principal: Option<&'a Principal>,
    pub submitted_at: Timestamp,
    pub lease: Option<authority::AccessLease>,
}
impl<'a> Submission<'a> {
    pub(super) fn management(
        principal: &'a Principal,
        submitted_at: Timestamp,
        lease: Option<authority::AccessLease>,
    ) -> Self {
        Self { tenant: principal.tenant, principal: Some(principal), submitted_at, lease }
    }
    pub(super) fn internal(tenant: TenantId) -> Self {
        Self { tenant, principal: None, submitted_at: Timestamp::now(), lease: None }
    }
    pub(super) async fn authorize(&self, state: &AppState, action: &str) -> DomainResult<()> {
        if let Some(principal) = self.principal {
            authority::authorize(state, principal, action, self.submitted_at, self.lease.as_ref()).await?;
        }
        if !crate::tenant_directory::get(state, self.tenant).await?.enabled {
            return Err(DomainError::Forbidden("策略所属租户已停用".into()));
        }
        Ok(())
    }
    pub(super) fn actor(&self) -> AuditActor {
        self.principal.map_or_else(
            || crate::integration_receipts::internal_actor("policy-store"),
            |principal| AppState::audit_actor(principal, "policy-publication"),
        )
    }
}

pub(super) async fn execute(
    state: &AppState,
    submission: Submission<'_>,
    change: change::Change,
) -> DomainResult<Policy> {
    submission.authorize(state, change.action()).await?;
    validation::preflight(state, submission.tenant, change.candidate()).await?;
    let saved = if state.store.database().is_some() {
        sql::execute(state, submission, change).await?
    } else {
        offline::execute(state, submission, change).await?
    };
    // This cache is only a projection. Do not use the legacy upsert which increments versions and journals another SQL write.
    if let Err(error) = state.store.hydrate_policy(&saved) {
        tracing::warn!(%error,"已提交策略的本地投影刷新失败；持久版本仍是运行时依据");
    }
    Ok(saved)
}
