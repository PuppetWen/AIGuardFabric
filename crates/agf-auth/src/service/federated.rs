//! Session issuance after a server-side identity provider has verified the external subject.
use super::{AuthBackend, AuthService, LoginOutcome, LoginRequest};
use crate::claims::IssueContext;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    rbac::SubjectKind,
    time::Timestamp,
    user::{IdentityProvider, LoginAttempt, RefreshTokenRecord, UserState},
};

impl AuthService {
    /// Caller must first verify the external identity and resolve its exact issuer/subject mapping.
    /// Local accounts cannot be authenticated through this entry point.
    pub async fn login_federated<B: AuthBackend + ?Sized>(
        &self,
        backend: &B,
        tenant: TenantId,
        user_id: Id,
        request: &LoginRequest,
    ) -> DomainResult<LoginOutcome> {
        let mut user = backend
            .find_user(tenant, user_id)
            .await?
            .ok_or_else(|| DomainError::Unauthenticated("企业账号不存在".into()))?;
        if user.tenant_id != tenant || user.idp == IdentityProvider::Local || !user.can_authenticate() {
            return Err(DomainError::Forbidden("企业账号不可用".into()));
        }
        let now = Timestamp::now();
        let valid_mfa = !user.mfa_enabled || backend.verify_mfa(tenant, &user, request.mfa_code.as_deref()).await?;
        if !valid_mfa {
            backend
                .record_attempt(&LoginAttempt {
                    id: Id::new(),
                    tenant_id: Some(tenant),
                    username: user.username.clone(),
                    source_ip: request.source_ip.clone().unwrap_or_else(|| "unknown".into()),
                    user_agent: request.user_agent.clone(),
                    success: false,
                    failure_code: Some("bad_mfa".into()),
                    at: now,
                })
                .await?;
            user.failed_logins = user.failed_logins.saturating_add(1);
            if user.failed_logins >= self.policy.max_failures {
                user.state = UserState::Locked;
                user.locked_until = Some(now.offset_secs(self.policy.lockout_secs));
            }
            backend.save_user(&user, None).await?;
            return Err(DomainError::Unauthenticated("MFA 验证码错误".into()));
        }
        self.issue_verified(backend, tenant, user, request, false, now).await
    }

    /// Issue a new browser session after another authenticated device approved a
    /// short-lived, browser-bound QR transaction and verified platform MFA.
    /// Callers must enforce those conditions before invoking this method.
    pub async fn login_approved_device<B: AuthBackend + ?Sized>(
        &self,
        backend: &B,
        tenant: TenantId,
        user_id: Id,
        request: &LoginRequest,
    ) -> DomainResult<LoginOutcome> {
        let user = backend
            .find_user(tenant, user_id)
            .await?
            .ok_or_else(|| DomainError::Unauthenticated("扫码批准账号不存在".into()))?;
        if user.tenant_id != tenant || !user.can_authenticate() || !user.mfa_enabled || user.must_change_password {
            return Err(DomainError::Forbidden("扫码批准账号不可用，请重新登录并确认 MFA".into()));
        }
        let superadmin = user.is_superadmin;
        self.issue_verified(backend, tenant, user, request, superadmin, Timestamp::now()).await
    }

    async fn issue_verified<B: AuthBackend + ?Sized>(
        &self,
        backend: &B,
        tenant: TenantId,
        mut user: agf_core::user::User,
        request: &LoginRequest,
        superadmin: bool,
        now: Timestamp,
    ) -> DomainResult<LoginOutcome> {
        backend
            .record_attempt(&LoginAttempt {
                id: Id::new(),
                tenant_id: Some(tenant),
                username: user.username.clone(),
                source_ip: request.source_ip.clone().unwrap_or_else(|| "unknown".into()),
                user_agent: request.user_agent.clone(),
                success: true,
                failure_code: None,
                at: now,
            })
            .await?;
        user.failed_logins = 0;
        user.last_login_at = Some(now);
        user.last_login_ip = request.source_ip.clone();
        user.updated_at = now;
        backend.save_user(&user, None).await?;
        user.version += 1;
        let enroll = backend.mfa_required(tenant).await? && !user.mfa_enabled;
        let roles = if enroll { vec!["mfa-enroll-only".into()] } else { backend.roles_of(tenant, user.id).await? };
        let session_id = agf_core::secret::generate_token();
        let ctx = IssueContext {
            subject: user.id,
            tenant,
            kind: SubjectKind::User,
            roles,
            superadmin,
            must_change_password: false,
            session_id,
        };
        let (tokens, refresh) = self.issuer.issue_pair(&ctx, now)?;
        backend
            .store_refresh(&RefreshTokenRecord {
                id: Id::new(),
                tenant_id: tenant,
                user_id: user.id,
                token_fingerprint: self.issuer.refresh_fingerprint(&refresh, &self.fingerprint_salt),
                expires_at: now.offset_secs(self.issuer.refresh_ttl_secs()),
                revoked: false,
                revoked_reason: None,
                device: if enroll { Some("mfa-enroll-only".into()) } else { request.device.clone() },
                created_at: now,
            })
            .await?;
        Ok(LoginOutcome::Success { tokens, user, permissions: Vec::new() })
    }
}
