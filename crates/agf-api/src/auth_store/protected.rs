//! 对 SQL 和离线认证后端统一装配加密 MFA 与租户策略。
use super::*;
use crate::{
    auth_policy::{KIND, TenantPolicy},
    config_store::ConfigStore,
    model_routes::tenant_record_id,
};
use agf_storage::crypto::FieldCipher;

#[derive(Debug)]
pub struct ProtectedBackend {
    inner: Arc<dyn AuthBackend>,
    configurations: Arc<ConfigStore>,
    cipher: Option<FieldCipher>,
}
impl ProtectedBackend {
    pub fn new(inner: Arc<dyn AuthBackend>, configurations: Arc<ConfigStore>, key: &str) -> Self {
        Self {
            inner,
            configurations,
            cipher: FieldCipher::from_base64(key, "agf-master", agf_core::credential::KeyBackend::LocalFile).ok(),
        }
    }
}
#[async_trait]
impl AuthBackend for ProtectedBackend {
    fn current_user_authority(
        &self,
        tenant: TenantId,
        user: Id,
    ) -> DomainResult<agf_auth::service::CurrentUserAuthority> {
        use agf_auth::service::CurrentUserAuthority;
        let policy_store = Some(Arc::as_ptr(&self.configurations).addr());
        Ok(match self.inner.current_user_authority(tenant, user)? {
            CurrentUserAuthority::Unavailable => CurrentUserAuthority::Unavailable,
            CurrentUserAuthority::Sql { store_identity, .. } => {
                CurrentUserAuthority::Sql { store_identity, mfa_configuration_identity: policy_store }
            }
            CurrentUserAuthority::Synchronous { user, roles, .. } => {
                CurrentUserAuthority::Synchronous { user, roles, mfa_configuration_identity: policy_store }
            }
        })
    }

    async fn provision_federated(&self, user: &User, roles: &[String]) -> DomainResult<()> {
        self.inner.provision_federated(user, roles).await
    }
    async fn list_users(&self, tenant: TenantId) -> DomainResult<Vec<User>> {
        self.inner.list_users(tenant).await
    }
    async fn save_account(&self, user: &User, password: Option<&str>, roles: &[String]) -> DomainResult<()> {
        self.inner.save_account(user, password, roles).await
    }
    async fn find_user_with_secret(&self, tenant: TenantId, name: &str) -> DomainResult<Option<UserWithSecret>> {
        self.inner.find_user_with_secret(tenant, name).await
    }
    async fn find_user(&self, tenant: TenantId, id: Id) -> DomainResult<Option<User>> {
        self.inner.find_user(tenant, id).await
    }
    async fn save_user(&self, user: &User, password: Option<&str>) -> DomainResult<()> {
        self.inner.save_user(user, password).await
    }
    async fn password_history(&self, tenant: TenantId, id: Id) -> DomainResult<Vec<String>> {
        self.inner.password_history(tenant, id).await
    }
    async fn store_refresh(&self, record: &RefreshTokenRecord) -> DomainResult<()> {
        self.inner.store_refresh(record).await
    }
    async fn find_refresh(&self, tenant: TenantId, fingerprint: &str) -> DomainResult<Option<RefreshTokenRecord>> {
        let record = self.inner.find_refresh(tenant, fingerprint).await?;
        if let Some(record) = &record {
            if let Some(mfa) = self
                .configurations
                .get::<crate::mfa_store::Enrollment>(tenant, crate::mfa_store::KIND, record.user_id)
                .await?
            {
                if record.created_at.unix_millis() < mfa.confirmed_at {
                    return Ok(None);
                }
            }
        }
        Ok(record)
    }
    async fn revoke_refresh(&self, tenant: TenantId, id: Id, reason: &str) -> DomainResult<bool> {
        self.inner.revoke_refresh(tenant, id, reason).await
    }
    async fn record_attempt(&self, attempt: &LoginAttempt) -> DomainResult<()> {
        self.inner.record_attempt(attempt).await
    }
    async fn roles_of(&self, tenant: TenantId, id: Id) -> DomainResult<Vec<String>> {
        self.inner.roles_of(tenant, id).await
    }
    async fn mfa_required(&self, tenant: TenantId) -> DomainResult<bool> {
        Ok(self
            .configurations
            .get::<TenantPolicy>(tenant, KIND, tenant_record_id(tenant))
            .await?
            .is_some_and(|p| p.view.mfa_enforced))
    }
    async fn session_valid(&self, tenant: TenantId, user: &User, issued_at: i64) -> DomainResult<bool> {
        if let Some(mfa) =
            self.configurations.get::<crate::mfa_store::Enrollment>(tenant, crate::mfa_store::KIND, user.id).await?
        {
            if issued_at < mfa.confirmed_at {
                return Ok(false);
            }
        }
        Ok(user.password_changed_at.is_none_or(|at| issued_at >= at.unix_millis()))
    }
    async fn verify_mfa(&self, tenant: TenantId, user: &User, code: Option<&str>) -> DomainResult<bool> {
        if !user.mfa_enabled {
            return Ok(user.tenant_id == tenant);
        }
        let cipher = self.cipher.as_ref().ok_or_else(|| DomainError::Config("MFA 加密主密钥不可用".into()))?;
        crate::mfa_store::verify(&self.configurations, cipher, tenant, user, code).await
    }
}
