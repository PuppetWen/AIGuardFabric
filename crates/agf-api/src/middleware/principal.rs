//! 认证主体提取与租户解析（自 `middleware.rs` 拆出，逻辑未变）。

use super::*;

// ===========================================================================
// 认证主体
// ===========================================================================

/// 已认证主体。
#[derive(Debug, Clone)]
pub struct Principal {
    /// 主体 id（API Key 认证时为 Key 的 id）。
    pub subject_id: Option<Id>,
    /// Agent identity bound to the authenticated API Key (never supplied by a request body).
    pub agent_id: Option<Id>,
    /// 主体类型。
    pub subject_kind: SubjectKind,
    /// **有效租户**（超级管理员可通过 `X-AGF-Tenant` 切换）。
    pub tenant: TenantId,
    /// 账号/凭据所属租户；切换工作组织不改变个人身份和安全设置。
    pub identity_tenant: TenantId,
    /// 角色名列表（JWT 携带）。
    pub roles: Vec<String>,
    /// 是否超级管理员。
    pub superadmin: bool,
    /// 是否必须先改密。
    pub must_change_password: bool,
    /// 仅允许绑定 MFA 的会话。
    pub must_setup_mfa: bool,
    /// 会话 id。
    pub session_id: Option<String>,
    /// API Key 直接授予的权限点。
    pub scopes: Vec<Permission>,
    /// 来源地址。
    pub source_ip: Option<String>,
    /// User-Agent。
    pub user_agent: Option<String>,
    /// 部门（ABAC）。
    pub department: Option<String>,
}

impl Principal {
    /// Resolve a caller hint without allowing a bound key to impersonate another Agent.
    pub fn resolve_agent(&self, hint: Option<Id>) -> Result<Option<Id>, ApiError> {
        if self.agent_id.is_some() && hint.is_some() && self.agent_id != hint {
            return Err(DomainError::Forbidden("请求 Agent 与 API Key 绑定身份不匹配".into()).into());
        }
        Ok(self.agent_id.or(hint))
    }
    /// 主体显示名（审计用；不泄露凭据）。
    #[must_use]
    pub fn display(&self) -> String {
        match self.subject_id {
            Some(id) => format!("{}:{id}", self.subject_kind.as_str()),
            None => self.subject_kind.as_str().to_string(),
        }
    }

    /// RBAC + ABAC 判定；API Key 主体改用其 `scopes`。
    ///
    /// # Errors
    /// - 首登未改密 → [`DomainError::PreconditionFailed`]；
    /// - 跨租户 → [`DomainError::TenantViolation`]；
    /// - 权限不足 → [`DomainError::Forbidden`]。
    pub fn require(&self, state: &AppState, group: &str, action: &str) -> Result<(), ApiError> {
        let result = self.check_permission(state, group, action);
        if result.is_ok() {
            super::idempotency_store::record_permission(group, action);
        }
        result
    }

    fn check_permission(&self, state: &AppState, group: &str, action: &str) -> Result<(), ApiError> {
        if self.must_setup_mfa {
            return Err(DomainError::PreconditionFailed("请先到账号安全页面绑定 MFA，再重新登录".into()).into());
        }
        if self.must_change_password {
            return Err(ApiError::new(DomainError::PreconditionFailed(
                "首次登录必须修改口令后才能访问其它接口（POST /api/v1/auth/change-password）".to_string(),
            )));
        }
        let permission = Permission::new(group, action);
        if self.subject_kind == SubjectKind::ApiKey {
            if self.superadmin || self.scopes.iter().any(|p| p.matches(&permission)) {
                return Ok(());
            }
            return Err(ApiError::new(DomainError::Forbidden(format!("API Key 缺少权限 {permission}"))));
        }
        let request = AccessRequest {
            permission,
            resource_tenant: self.tenant,
            data_class: None,
            department: self.department.clone(),
            source_ip: self.source_ip.clone(),
        };
        state
            .authorizer
            .authorize(self.subject_id, &self.roles, self.superadmin, &request, self.tenant)
            .map_err(ApiError::new)
    }

    /// 只读判定（供前端裁剪 UI）。
    #[must_use]
    pub fn read_only(&self) -> bool {
        self.roles
            .iter()
            .all(|r| r != agf_core::rbac::builtin::SUPERADMIN && r != agf_core::rbac::builtin::TENANT_ADMIN)
            && self.scopes.iter().all(|p| p.as_str().ends_with(":read"))
    }
}

/// 由 `X-AGF-Tenant` 头解析目标租户并与主体租户比对。
fn resolve_tenant(headers: &axum::http::HeaderMap, base: TenantId, superadmin: bool) -> Result<TenantId, ApiError> {
    let Some(raw) = headers.get(HEADER_TENANT) else { return Ok(base) };
    let value = raw.to_str().unwrap_or_default().trim();
    if value.is_empty() {
        return Ok(base);
    }
    let requested = TenantId::parse(value)
        .map_err(|e| ApiError::new(DomainError::Validation(format!("{HEADER_TENANT} 非法: {e}"))))?;
    if requested == base {
        return Ok(base);
    }
    if superadmin {
        return Ok(requested);
    }
    // 跨租户访问：**必须短路**，任何角色都不例外
    Err(ApiError::new(DomainError::TenantViolation {
        tenant: base.to_string(),
        resource: format!("tenant:{requested}"),
    }))
}

fn source_ip_of(headers: &axum::http::HeaderMap) -> Option<String> {
    for name in ["x-forwarded-for", "x-real-ip"] {
        if let Some(raw) = headers.get(name) {
            if let Ok(value) = raw.to_str() {
                if let Some(first) = value.split(',').next() {
                    let trimmed = first.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }
        }
    }
    None
}

fn optional_header(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    headers.get(name).and_then(|v| v.to_str().ok()).map(str::trim).filter(|s| !s.is_empty()).map(ToString::to_string)
}

impl FromRequestParts<AppState> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        // The rate-limit middleware has already verified this request. Reuse the same snapshot
        // instead of querying the account and API key stores a second time.
        if let Some(principal) = parts.extensions.get::<Self>() {
            return Ok(principal.clone());
        }
        let headers = &parts.headers;
        let source_ip = source_ip_of(headers);
        let user_agent = optional_header(headers, "user-agent");
        let mut department = None;

        // 1) API Key
        let bearer_key = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| agf_auth::claims::TokenIssuer::extract_bearer(v).ok())
            .filter(|token| token.starts_with("agf_"));
        let explicit_key = headers
            .get(HEADER_API_KEY)
            .or_else(|| parts.uri.path().starts_with("/v1/messages").then(|| headers.get("x-api-key")).flatten())
            .map(|v| v.to_str())
            .transpose()
            .map_err(|_| DomainError::Unauthenticated("X-AGF-Key 非 ASCII".into()))?;
        if let Some(plaintext) = explicit_key.or(bearer_key) {
            let key = state.verify_api_key(plaintext, source_ip.as_deref()).await.map_err(ApiError::new)?;
            let tenant = resolve_tenant(headers, key.tenant_id, false)?;
            crate::tenant_directory::resolve(state, &tenant.to_string()).await?;
            if let Some(agent) = key.bound_agent_id {
                let asset = state
                    .store
                    .asset_get_durable(tenant, agent)
                    .await?
                    .filter(|asset| asset.kind == agf_core::enums::AssetKind::Agent)
                    .ok_or_else(|| DomainError::Forbidden("API Key 绑定的 Agent 不存在".into()))?;
                department = asset.department;
            }
            let scopes = crate::agentteams_role_mapping::constrain_key(state, tenant, &key).await?;
            return Ok(Self {
                subject_id: Some(key.id),
                agent_id: key.bound_agent_id,
                subject_kind: SubjectKind::ApiKey,
                tenant,
                identity_tenant: key.tenant_id,
                roles: Vec::new(),
                superadmin: false,
                must_change_password: false,
                must_setup_mfa: false,
                session_id: None,
                scopes,
                source_ip,
                user_agent,
                department,
            });
        }

        // 2) Bearer JWT
        let Some(raw) = headers.get(header::AUTHORIZATION) else {
            return Err(ApiError::new(DomainError::Unauthenticated(
                "缺少认证凭据：请提供 `Authorization: Bearer <JWT>` 或 `X-AGF-Key`".to_string(),
            )));
        };
        let header_value = raw
            .to_str()
            .map_err(|_| ApiError::new(DomainError::Unauthenticated("Authorization 头非 ASCII".to_string())))?;
        let token = agf_auth::claims::TokenIssuer::extract_bearer(header_value).map_err(ApiError::new)?;
        let claims = state.auth.issuer().verify(token).map_err(ApiError::new)?;
        let subject_id =
            Id::parse(&claims.sub).map_err(|e| ApiError::new(DomainError::Parse(format!("令牌 sub 非法: {e}"))))?;
        let base_tenant = TenantId::parse(&claims.tenant_id)
            .map_err(|e| ApiError::new(DomainError::Parse(format!("令牌 tenant_id 非法: {e}"))))?;
        let mut must_setup_mfa = claims.roles.iter().any(|role| role == "mfa-enroll-only");
        // 角色与账号状态以当前记录为准：停用/降权无需等待旧 JWT 自然过期。
        let (roles, superadmin, must_change_password) = if claims.subject_kind == SubjectKind::User {
            let user = state
                .auth_backend
                .find_user(base_tenant, subject_id)
                .await?
                .filter(agf_core::user::User::can_authenticate)
                .ok_or_else(|| DomainError::Unauthenticated("账号已停用、锁定或不存在".into()))?;
            if must_setup_mfa && user.mfa_enabled {
                return Err(DomainError::Unauthenticated("MFA 绑定已完成，请重新登录".into()).into());
            }
            must_setup_mfa |= state.auth_backend.mfa_required(base_tenant).await? && !user.mfa_enabled;
            department.clone_from(&user.department);
            if !state
                .auth_backend
                .session_valid(
                    base_tenant,
                    &user,
                    if claims.issued_at_ms > 0 { claims.issued_at_ms } else { claims.iat.saturating_mul(1000) },
                )
                .await?
            {
                return Err(DomainError::Unauthenticated("账号安全设置已更新，请重新登录".into()).into());
            }
            (
                state.auth_backend.roles_of(base_tenant, subject_id).await?,
                user.is_superadmin,
                user.must_change_password || claims.must_change_password,
            )
        } else {
            (claims.roles, claims.superadmin, claims.must_change_password)
        };
        let tenant = resolve_tenant(headers, base_tenant, superadmin)?;
        let entry = crate::tenant_directory::get(state, tenant).await?;
        if !entry.enabled && !superadmin {
            return Err(DomainError::Forbidden("租户已停用".into()).into());
        }
        Ok(Self {
            subject_id: Some(subject_id),
            agent_id: None,
            subject_kind: claims.subject_kind,
            tenant,
            identity_tenant: base_tenant,
            roles,
            superadmin,
            must_change_password,
            must_setup_mfa,
            session_id: Some(claims.session_id),
            scopes: Vec::new(),
            source_ip,
            user_agent,
            department,
        })
    }
}

// ===========================================================================
// 限流
// ===========================================================================
