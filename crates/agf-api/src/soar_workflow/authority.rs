//! Persist identities, never credentials or an enduring snapshot of administrator permissions.
use super::*;
use agf_core::rbac::SubjectKind;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    pub id: Id,
    pub kind: SubjectKind,
    pub identity_tenant: TenantId,
    pub source_ip: Option<String>,
}
impl Actor {
    pub fn from_principal(principal: &Principal) -> DomainResult<Self> {
        Ok(Self {
            id: principal.subject_id.ok_or_else(|| DomainError::Forbidden("处置需要可追溯的账号或密钥".into()))?,
            kind: principal.subject_kind,
            identity_tenant: principal.identity_tenant,
            source_ip: principal.source_ip.clone(),
        })
    }
    pub fn display(&self) -> String {
        format!("{}:{}", self.kind.as_str(), self.id)
    }

    pub(crate) async fn resolve(&self, state: &AppState, tenant: TenantId) -> DomainResult<Principal> {
        self.resolve_for(state, tenant, "cases", "write").await
    }

    /// Recheck current identity permissions for a particular durable operation.
    pub(crate) async fn resolve_for(
        &self,
        state: &AppState,
        tenant: TenantId,
        group: &str,
        action: &str,
    ) -> DomainResult<Principal> {
        let principal = self.resolve_identity(state, tenant).await?;
        principal.require(state, group, action).map_err(|error| error.error)?;
        Ok(principal)
    }

    /// Current identity only; this does not confer any business grant.
    pub(crate) async fn resolve_identity(&self, state: &AppState, tenant: TenantId) -> DomainResult<Principal> {
        crate::tenant_directory::resolve(state, &tenant.to_string()).await?;
        let mut principal = Principal {
            subject_id: Some(self.id),
            subject_kind: self.kind,
            tenant,
            identity_tenant: self.identity_tenant,
            agent_id: None,
            roles: Vec::new(),
            scopes: Vec::new(),
            superadmin: false,
            must_change_password: false,
            must_setup_mfa: false,
            session_id: None,
            source_ip: self.source_ip.clone(),
            user_agent: Some("durable-soar-worker".into()),
            department: None,
        };
        match self.kind {
            SubjectKind::User => {
                let user = state
                    .auth_backend
                    .find_user(self.identity_tenant, self.id)
                    .await?
                    .filter(agf_core::user::User::can_authenticate)
                    .ok_or_else(|| DomainError::Forbidden("剧本执行账号已停用、锁定或删除".into()))?;
                principal.roles = state.auth_backend.roles_of(self.identity_tenant, self.id).await?;
                principal.superadmin = user.is_superadmin;
                principal.must_change_password = user.must_change_password;
                principal.must_setup_mfa =
                    state.auth_backend.mfa_required(self.identity_tenant).await? && !user.mfa_enabled;
                principal.department = user.department;
            }
            SubjectKind::ApiKey => {
                let key = state
                    .store
                    .api_key_list_durable(self.identity_tenant)
                    .await?
                    .into_iter()
                    .find(|key| {
                        key.id == self.id && !key.revoked && key.expires_at.is_none_or(|at| at > Timestamp::now())
                    })
                    .ok_or_else(|| DomainError::Forbidden("剧本提交密钥已吊销、过期或删除".into()))?;
                if !key.allowed_cidrs.is_empty() {
                    if !self
                        .source_ip
                        .as_deref()
                        .is_some_and(|ip| agf_auth::rbac::cidr_matches_any(&key.allowed_cidrs, ip))
                    {
                        return Err(DomainError::Forbidden("剧本提交来源已不满足密钥 CIDR 限制".into()));
                    }
                }
                principal.scopes = crate::agentteams_role_mapping::constrain_key(state, tenant, &key).await?;
                principal.agent_id = key.bound_agent_id;
                if let Some(id) = key.bound_agent_id {
                    principal.department = state
                        .store
                        .asset_get_durable(tenant, id)
                        .await?
                        .filter(|asset| asset.kind == agf_core::enums::AssetKind::Agent)
                        .ok_or_else(|| DomainError::Forbidden("密钥绑定的 Agent 已不存在".into()))?
                        .department;
                }
            }
            _ => return Err(DomainError::Forbidden("该主体不能执行持久化剧本".into())),
        }
        if tenant != self.identity_tenant && !principal.superadmin {
            return Err(DomainError::Forbidden("执行账号已失去跨租户权限".into()));
        }
        Ok(principal)
    }
}
