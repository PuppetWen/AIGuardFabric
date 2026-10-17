//! 由 `service.rs` 拆分：`AuthError`/`AuthService`/`DomainError` 的实现（纯搬移，逻辑不变）。
use super::*;

use crate::claims::{IssueContext, TokenIssuer};
use crate::password::PasswordHasher;
use agf_core::auth::{PasswordPolicy, TokenPair};
use agf_core::error::{DomainError, DomainResult};
use agf_core::ids::{Id, TenantId};
use agf_core::rbac::SubjectKind;
use agf_core::time::Timestamp;
use agf_core::user::{LoginAttempt, RefreshTokenRecord, User, UserState};

impl AuthError {
    /// 对外展示文案（**不泄露账号是否存在**）。
    #[must_use]
    pub fn public_message(&self) -> String {
        match self {
            Self::InvalidCredentials | Self::NotFound => "用户名或口令错误".to_string(),
            Self::Locked { remaining_secs } => {
                format!("账号已锁定，请在 {} 分钟后重试", (remaining_secs / 60).max(1))
            }
            Self::Disabled(reason) => format!("账号不可用：{reason}"),
            Self::MfaRequired => "需要提供多因子验证码".to_string(),
            Self::MfaInvalid => "验证码错误".to_string(),
            Self::PasswordChangeRequired => "首次登录必须修改口令".to_string(),
            Self::WeakPassword(msg) => msg.clone(),
        }
    }
}

impl From<AuthError> for DomainError {
    fn from(value: AuthError) -> Self {
        match value {
            AuthError::InvalidCredentials | AuthError::NotFound | AuthError::MfaInvalid => {
                Self::Unauthenticated("用户名或口令错误".to_string())
            }
            AuthError::Locked { .. } | AuthError::Disabled(_) => Self::Forbidden("账号不可用".to_string()),
            AuthError::MfaRequired => Self::Unauthenticated("需要多因子验证码".to_string()),
            AuthError::PasswordChangeRequired => Self::PreconditionFailed("首次登录必须修改口令".to_string()),
            AuthError::WeakPassword(msg) => Self::Validation(msg),
        }
    }
}

impl std::fmt::Debug for AuthService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthService")
            .field("issuer", &self.issuer)
            .field("policy_min_len", &self.policy.min_length)
            .finish_non_exhaustive()
    }
}

impl AuthService {
    /// 构造。
    #[must_use]
    pub fn new(issuer: TokenIssuer, policy: PasswordPolicy, fingerprint_salt: impl Into<String>) -> Self {
        Self { issuer, hasher: PasswordHasher::new(policy.clone()), policy, fingerprint_salt: fingerprint_salt.into() }
    }

    /// 口令策略。
    #[must_use]
    pub const fn policy(&self) -> &PasswordPolicy {
        &self.policy
    }

    /// 为当前请求应用租户策略，不改变签名密钥和刷新令牌盐。
    #[must_use]
    pub fn with_policy(&self, policy: PasswordPolicy) -> Self {
        Self::new(self.issuer.clone(), policy, self.fingerprint_salt.clone())
    }

    /// 口令哈希器（引导管理员创建时使用）。
    #[must_use]
    pub const fn hasher(&self) -> &PasswordHasher {
        &self.hasher
    }

    /// 登录。
    ///
    /// 状态机：
    /// 1. 查用户（不存在 → 记审计 + 返回与口令错误**相同**的提示）；
    /// 2. 锁定/状态检查；
    /// 3. 口令校验（失败 → 累加失败计数，达到阈值锁定）；
    /// 4. MFA 校验（若开启）；
    /// 5. 成功 → 清零失败计数、更新 last_login、签发令牌；
    /// 6. `must_change_password` → 返回 [`LoginOutcome::MustChangePassword`]。
    ///
    /// # Errors
    /// 存储错误。
    pub async fn login<B: AuthBackend + ?Sized>(
        &self,
        backend: &B,
        tenant: TenantId,
        req: &LoginRequest,
    ) -> DomainResult<LoginOutcome> {
        // Concurrent login bookkeeping may advance the account version. Re-read the
        // account before issuing a token; a stale snapshot must never revive a
        // disabled account or undo a newly enabled MFA requirement.
        for _ in 0..3 {
            match self.login_once(backend, tenant, req).await {
                Err(DomainError::Conflict(_)) => {}
                result => return result,
            }
        }
        Err(DomainError::Unauthenticated("账号状态已变化，请重试登录".into()))
    }

    async fn login_once<B: AuthBackend + ?Sized>(
        &self,
        backend: &B,
        tenant: TenantId,
        req: &LoginRequest,
    ) -> DomainResult<LoginOutcome> {
        let now = Timestamp::now();
        let attempt_base = |success: bool, code: Option<String>| LoginAttempt {
            id: Id::new(),
            tenant_id: Some(tenant),
            username: req.username.clone(),
            source_ip: req.source_ip.clone().unwrap_or_else(|| "unknown".to_string()),
            user_agent: req.user_agent.clone(),
            success,
            failure_code: code,
            at: now,
        };

        let Some(mut record) = backend.find_user_with_secret(tenant, &req.username).await? else {
            backend.record_attempt(&attempt_base(false, Some("user_not_found".into()))).await?;
            return Err(AuthError::InvalidCredentials.into());
        };
        let user = &mut record.user;

        if user.is_locked_now() {
            backend.record_attempt(&attempt_base(false, Some("locked".into()))).await?;
            let remaining = user.locked_until.map(|t| t.unix_secs() - now.unix_secs()).unwrap_or(0);
            return Err(AuthError::Locked { remaining_secs: remaining.max(0) }.into());
        }
        if !user.state.can_login() {
            backend.record_attempt(&attempt_base(false, Some("state_disabled".into()))).await?;
            return Err(AuthError::Disabled(user.state.as_str().to_string()).into());
        }

        let Some(phc) = record.password_hash.as_deref() else {
            backend.record_attempt(&attempt_base(false, Some("no_password_set".into()))).await?;
            return Err(AuthError::Disabled("该账号未设置口令（请使用单点登录）".to_string()).into());
        };
        let matched = self.hasher.verify(&req.password, phc)?;
        if !matched {
            user.failed_logins = user.failed_logins.saturating_add(1);
            if user.failed_logins >= self.policy.max_failures {
                user.state = UserState::Locked;
                user.locked_until = Some(now.offset_secs(self.policy.lockout_secs));
            }
            user.updated_at = now;
            backend.save_user(user, None).await?;
            backend.record_attempt(&attempt_base(false, Some("bad_password".into()))).await?;
            if user.state == UserState::Locked {
                return Err(AuthError::Locked { remaining_secs: self.policy.lockout_secs }.into());
            }
            return Err(AuthError::InvalidCredentials.into());
        }

        // MFA
        if user.mfa_enabled && !backend.verify_mfa(tenant, user, req.mfa_code.as_deref()).await? {
            user.failed_logins = user.failed_logins.saturating_add(1);
            if user.failed_logins >= self.policy.max_failures {
                user.state = UserState::Locked;
                user.locked_until = Some(now.offset_secs(self.policy.lockout_secs));
            }
            backend.save_user(user, None).await?;
            backend.record_attempt(&attempt_base(false, Some("bad_mfa".into()))).await?;
            return Err(AuthError::MfaInvalid.into());
        }

        // 成功后：清零失败、解锁、记录登录
        user.failed_logins = 0;
        if user.state == UserState::Locked {
            user.state = UserState::Active;
        }
        user.locked_until = None;
        user.last_login_at = Some(now);
        user.last_login_ip = req.source_ip.clone();
        user.updated_at = now;

        if self.policy.max_age_days > 0
            && now.since_secs(&user.password_changed_at.unwrap_or(user.created_at))
                >= i64::from(self.policy.max_age_days) * 86400
        {
            user.must_change_password = true;
        }

        // 口令哈希参数升级（渐进式）：参数落后时用当前基线重新哈希
        let rehash: Option<String> =
            if self.hasher.needs_rehash(phc)? { Some(self.hasher.hash(&req.password)?) } else { None };
        backend.save_user(user, rehash.as_deref()).await?;
        user.version += 1;
        backend.record_attempt(&attempt_base(true, None)).await?;

        let roles = if backend.mfa_required(tenant).await? && !user.mfa_enabled {
            vec!["mfa-enroll-only".into()]
        } else {
            backend.roles_of(tenant, user.id).await?
        };

        if user.must_change_password {
            // 首登强制改密：签发一个用途受限的临时令牌（此处复用访问令牌，但标记 must_change_password，
            // 由 API 中间件只放行改密/登出接口）
            let session_id = agf_core::secret::generate_token();
            let ctx = IssueContext {
                subject: user.id,
                tenant,
                kind: SubjectKind::User,
                roles: roles.clone(),
                superadmin: user.is_superadmin,
                must_change_password: true,
                session_id,
            };
            let change_token = self.issuer.issue_access(&ctx, now)?;
            return Ok(LoginOutcome::MustChangePassword { change_token, user: user.clone() });
        }

        let session_id = agf_core::secret::generate_token();
        let ctx = IssueContext {
            subject: user.id,
            tenant,
            kind: SubjectKind::User,
            roles: roles.clone(),
            superadmin: user.is_superadmin,
            must_change_password: false,
            session_id: session_id.clone(),
        };
        let (tokens, refresh_plain) = self.issuer.issue_pair(&ctx, now)?;
        backend
            .store_refresh(&RefreshTokenRecord {
                id: Id::new(),
                tenant_id: tenant,
                user_id: user.id,
                token_fingerprint: self.issuer.refresh_fingerprint(&refresh_plain, &self.fingerprint_salt),
                expires_at: self.issuer.refresh_expiry(now),
                revoked: false,
                revoked_reason: None,
                device: if roles.iter().any(|role| role == "mfa-enroll-only") {
                    Some("mfa-enroll-only".into())
                } else {
                    req.device.clone()
                },
                created_at: now,
            })
            .await?;

        Ok(LoginOutcome::Success { tokens, user: user.clone(), permissions: Vec::new() })
    }

    /// 修改口令（首登强制 + 常规改密共用）。
    ///
    /// # Errors
    /// - 用户不存在或已被禁用；
    /// - 新口令不符合策略。
    pub async fn change_password<B: AuthBackend + ?Sized>(
        &self,
        backend: &B,
        tenant: TenantId,
        user_id: Id,
        new_password: &str,
    ) -> DomainResult<()> {
        self.policy.validate(new_password, "").map_err(DomainError::Validation)?;
        let Some(mut user) = backend.find_user(tenant, user_id).await? else {
            return Err(DomainError::NotFound { entity: "user", id: user_id.to_string() });
        };
        self.policy.validate(new_password, &user.username).map_err(DomainError::Validation)?;
        if self.policy.history_size > 0 {
            let current =
                backend.find_user_with_secret(tenant, &user.username).await?.and_then(|record| record.password_hash);
            let history = backend.password_history(tenant, user_id).await?;
            for phc in current.into_iter().chain(history).take(usize::try_from(self.policy.history_size).unwrap_or(24))
            {
                if self.hasher.verify(new_password, &phc)? {
                    return Err(DomainError::Validation("新口令不能与最近使用过的口令相同".into()));
                }
            }
        }
        let phc = self.hasher.hash(new_password)?;
        user.must_change_password = false;
        user.password_changed_at = Some(Timestamp::now());
        user.updated_at = Timestamp::now();
        backend.save_user(&user, Some(&phc)).await?;
        Ok(())
    }

    /// 刷新令牌（轮换刷新令牌，防重放）。
    ///
    /// # Errors
    /// - 刷新令牌不存在/已吊销/已过期；
    /// - 用户已不可用。
    pub async fn refresh<B: AuthBackend + ?Sized>(
        &self,
        backend: &B,
        tenant: TenantId,
        refresh_plain: &str,
    ) -> DomainResult<TokenPair> {
        let now = Timestamp::now();
        let fp = self.issuer.refresh_fingerprint(refresh_plain, &self.fingerprint_salt);
        let Some(record) = backend.find_refresh(tenant, &fp).await? else {
            return Err(DomainError::Unauthenticated("刷新令牌无效".to_string()));
        };
        if record.revoked {
            return Err(DomainError::Unauthenticated("刷新令牌已被吊销".to_string()));
        }
        if record.device.as_deref() == Some("mfa-enroll-only") {
            return Err(DomainError::Unauthenticated("MFA 绑定会话不能刷新，请重新登录".into()));
        }
        if record.expires_at.as_datetime() <= now.as_datetime() {
            return Err(DomainError::Unauthenticated("刷新令牌已过期".to_string()));
        }
        let Some(user) = backend.find_user(tenant, record.user_id).await? else {
            return Err(DomainError::Unauthenticated("用户不存在".to_string()));
        };
        if !user.can_authenticate() {
            return Err(DomainError::Forbidden("账号不可用".to_string()));
        }
        if user.must_change_password
            || !backend.session_valid(tenant, &user, record.created_at.unix_millis()).await?
            || (backend.mfa_required(tenant).await? && !user.mfa_enabled)
            || (user.idp == agf_core::user::IdentityProvider::Local
                && self.policy.max_age_days > 0
                && now.since_secs(&user.password_changed_at.unwrap_or(user.created_at))
                    >= i64::from(self.policy.max_age_days) * 86400)
        {
            return Err(DomainError::Unauthenticated("账号安全策略已变更或口令已过期，请重新登录".into()));
        }
        let roles = backend.roles_of(tenant, user.id).await?;
        let ctx = IssueContext {
            subject: user.id,
            tenant,
            kind: SubjectKind::User,
            roles,
            superadmin: user.is_superadmin,
            must_change_password: user.must_change_password,
            session_id: agf_core::secret::generate_token(),
        };
        let (tokens, new_refresh) = self.issuer.issue_pair(&ctx, now)?;
        // 轮换：吊销旧令牌，写入新令牌
        if !backend.revoke_refresh(tenant, record.id, "rotated").await? {
            return Err(DomainError::Unauthenticated("刷新令牌已被使用".into()));
        }
        backend
            .store_refresh(&RefreshTokenRecord {
                id: Id::new(),
                tenant_id: tenant,
                user_id: user.id,
                token_fingerprint: self.issuer.refresh_fingerprint(&new_refresh, &self.fingerprint_salt),
                expires_at: self.issuer.refresh_expiry(now),
                revoked: false,
                revoked_reason: None,
                device: record.device.clone(),
                created_at: now,
            })
            .await?;
        Ok(tokens)
    }

    /// 登出（吊销刷新令牌）。
    ///
    /// # Errors
    /// 存储错误。
    pub async fn logout<B: AuthBackend + ?Sized>(
        &self,
        backend: &B,
        tenant: TenantId,
        refresh_plain: &str,
    ) -> DomainResult<()> {
        let fp = self.issuer.refresh_fingerprint(refresh_plain, &self.fingerprint_salt);
        if let Some(record) = backend.find_refresh(tenant, &fp).await? {
            backend.revoke_refresh(tenant, record.id, "logout").await?;
        }
        Ok(())
    }

    /// 签发令牌（供引导管理员创建后直接登录使用）。
    ///
    /// # Errors
    /// 编码失败。
    pub fn issue_for_user(&self, user: &User, tenant: TenantId, roles: Vec<String>) -> DomainResult<TokenPair> {
        let now = Timestamp::now();
        let ctx = IssueContext {
            subject: user.id,
            tenant,
            kind: SubjectKind::User,
            roles,
            superadmin: user.is_superadmin,
            must_change_password: user.must_change_password,
            session_id: agf_core::secret::generate_token(),
        };
        self.issuer.issue_pair(&ctx, now).map(|(pair, _)| pair)
    }

    /// 令牌签发者（API 中间件校验令牌用）。
    #[must_use]
    pub const fn issuer(&self) -> &TokenIssuer {
        &self.issuer
    }
}
