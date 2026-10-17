//! Current authority, original session, scope and fencing are checked before every provider read and publication.
use super::{contract::Run, scope, store};
use crate::{Principal, cloud_runtime::WritePrecondition, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    rbac::SubjectKind,
    time::Timestamp,
};

pub(super) async fn authorize(state: &AppState, principal: &Principal, issued_at: Timestamp) -> DomainResult<()> {
    let current = crate::soar_workflow::Actor::from_principal(principal)?
        .resolve_for(state, principal.tenant, "alicloud", "write")
        .await?;
    current.require(state, "alicloud", "read").map_err(|error| error.error)?;
    current.require(state, "assets", "write").map_err(|error| error.error)?;
    if current.subject_kind == SubjectKind::User {
        let user = state
            .auth_backend
            .find_user(
                current.identity_tenant,
                current.subject_id.ok_or_else(|| DomainError::Forbidden("盘点账号缺少身份".into()))?,
            )
            .await?
            .ok_or_else(|| DomainError::Forbidden("盘点账号已不存在".into()))?;
        if !state.auth_backend.session_valid(current.identity_tenant, &user, issued_at.unix_millis()).await? {
            return Err(DomainError::Forbidden("盘点期间账号安全设置已改变，请重新登录".into()));
        }
    }
    Ok(())
}

pub(super) struct Guard<'a> {
    pub state: &'a AppState,
    pub principal: &'a Principal,
    pub run: &'a Run,
}

#[async_trait::async_trait]
impl WritePrecondition for Guard<'_> {
    async fn validate(&self) -> DomainResult<()> {
        if !crate::tenant_directory::get(self.state, self.principal.tenant).await?.enabled {
            return Err(DomainError::Forbidden("盘点租户已停用".into()));
        }
        authorize(self.state, self.principal, self.run.submitted_at.unwrap_or(self.run.started_at)).await?;
        let (_, current) = scope::load(self.state, self.principal.tenant).await?;
        if current != self.run.scope {
            return Err(scope::stale());
        }
        store::owns(&store::load(self.state, self.principal.tenant).await?, self.run)
    }
}
