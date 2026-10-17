//! Configuration checks apply to every cloud call, including internal read-only observers.
use super::WritePrecondition;
use crate::{Principal, cloud_store, state::AppState};
use agf_alicloud::http::RpcClient;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::TenantId,
    rbac::SubjectKind,
    time::Timestamp,
};

pub(super) struct Guard<'a> {
    pub state: &'a AppState,
    pub tenant: TenantId,
    pub name: &'a str,
    pub version: u64,
    pub mocked: bool,
    pub principal: Option<&'a Principal>,
    pub business: Option<&'a dyn WritePrecondition>,
    pub issued_at: Timestamp,
    pub require_read: bool,
}

#[async_trait::async_trait]
impl WritePrecondition for Guard<'_> {
    async fn validate(&self) -> DomainResult<()> {
        if !crate::tenant_directory::get(self.state, self.tenant).await?.enabled {
            return Err(DomainError::Forbidden("云操作所属租户已停用".into()));
        }
        let row = cloud_store::load(self.state, self.tenant, self.name)
            .await?
            .filter(|row| row.enabled)
            .ok_or_else(|| DomainError::PreconditionFailed("云配置已停用，排队操作未派发".into()))?;
        if row.version != self.version || (self.state.config.mock_mode || row.mock) != self.mocked {
            return Err(DomainError::Conflict("云配置或模式已改变，排队操作未派发；请重新加载".into()));
        }
        if let Some(principal) = self.principal {
            let current = crate::soar_workflow::Actor::from_principal(principal)?
                .resolve_for(self.state, self.tenant, "alicloud", "write")
                .await?;
            if self.require_read {
                current.require(self.state, "alicloud", "read").map_err(|error| error.error)?;
            }
            if current.subject_kind == SubjectKind::User {
                let user = self
                    .state
                    .auth_backend
                    .find_user(
                        current.identity_tenant,
                        current.subject_id.ok_or_else(|| DomainError::Forbidden("云操作账号缺少身份".into()))?,
                    )
                    .await?
                    .ok_or_else(|| DomainError::Forbidden("云操作账号已不存在".into()))?;
                if !self
                    .state
                    .auth_backend
                    .session_valid(current.identity_tenant, &user, self.issued_at.unix_millis())
                    .await?
                {
                    return Err(DomainError::Forbidden("排队期间账号安全设置已改变，请重新登录".into()));
                }
            }
        }
        if let Some(business) = self.business {
            business.validate().await?;
        }
        Ok(())
    }

    async fn preflight(&self, client: Option<&RpcClient>) -> DomainResult<()> {
        if let Some(business) = self.business {
            business.preflight(client).await?;
        }
        Ok(())
    }
}
