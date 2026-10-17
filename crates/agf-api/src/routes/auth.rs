//! 认证路由：登录（含首登强制改密）、改密、刷新、登出、当前用户。

use agf_auth::service::{LoginOutcome, LoginRequest};
use agf_core::audit::{AuditAction, AuditOutcome, AuditTarget};
use agf_core::constants::HEADER_TENANT;
use agf_core::error::DomainError;
use agf_core::rbac::Permission;
use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{ApiError, ApiResult};
use crate::middleware::Principal;
use crate::routes::ApiJson;
use crate::state::AppState;

/// 认证路由。
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/change-password", post(change_password))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
}

/// 登录请求。
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct LoginBody {
    /// 租户标识或 UUID；空值使用默认租户。
    pub tenant_slug: Option<String>,
    /// 登录名。
    pub username: String,
    /// 口令。
    pub password: String,
    /// MFA 验证码（已开启 MFA 时必填）。
    #[serde(default)]
    pub mfa_code: Option<String>,
    /// 设备标识。
    #[serde(default)]
    pub device: Option<String>,
}

/// 登录响应。
#[derive(Debug, Clone, Serialize)]
pub struct LoginResponse {
    /// Password rules for first-login UI; available only after credentials are verified.
    pub password_policy: crate::routes::console::PasswordPolicyView,
    /// 当前角色，与服务端授权一致。
    pub roles: Vec<String>,
    /// 租户强制 MFA 时仅签发绑定用途的会话。
    pub mfa_enrollment_required: bool,
    /// 是否需要先改密（true 时**不签发可用令牌**）。
    pub must_change_password: bool,
    /// 令牌对（`must_change_password=true` 时为 `None`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens: Option<agf_core::auth::TokenPair>,
    /// 一次性改密令牌（仅用于 `POST /auth/change-password`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_token: Option<String>,
    /// 用户视图。
    pub user: agf_core::user::User,
    /// 有效权限点。
    pub permissions: Vec<Permission>,
    /// 提示文案。
    pub message: String,
}

/// 登录（`POST /api/v1/auth/login`）。
///
/// # Errors
/// 口令错误 / 账号锁定 / 状态不可用 → problem+json（不区分账号是否存在）。
pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<LoginBody>,
) -> ApiResult<Json<LoginResponse>> {
    let value = body
        .tenant_slug
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| headers.get(HEADER_TENANT).and_then(|v| v.to_str().ok()))
        .unwrap_or("default");
    let tenant = crate::tenant_directory::resolve(&state, value).await?.id;
    let request = LoginRequest {
        username: body.username.clone(),
        password: body.password,
        mfa_code: body.mfa_code,
        source_ip: header_str(&headers, "x-forwarded-for").or_else(|| header_str(&headers, "x-real-ip")),
        user_agent: header_str(&headers, "user-agent"),
        device: body.device,
    };
    let auth = crate::auth_policy::service(&state, tenant).await?;
    let outcome = auth.login(&*state.auth_backend, tenant, &request).await;
    match outcome {
        Ok(LoginOutcome::Success { tokens, user, permissions }) => {
            state
                .audit(
                    tenant,
                    AuditAction::Login,
                    AuditOutcome::Success,
                    agf_core::audit::AuditActor {
                        id: Some(user.id),
                        kind: "user".to_string(),
                        name: user.username.clone(),
                        source_ip: request.source_ip.clone(),
                        user_agent: request.user_agent.clone(),
                        session_id: Some(tokens.session_id.clone()),
                    },
                    AuditTarget::new("session", Some(tokens.session_id.clone()), Some(user.username.clone())),
                    "登录成功",
                )
                .await?;
            Ok(Json(LoginResponse {
                password_policy: crate::auth_policy::TenantPolicy::load(&state, tenant).await?.view,
                roles: state.auth_backend.roles_of(tenant, user.id).await?,
                mfa_enrollment_required: state.auth_backend.mfa_required(tenant).await? && !user.mfa_enabled,
                must_change_password: false,
                tokens: Some(tokens),
                change_token: None,
                user,
                permissions,
                message: "登录成功".to_string(),
            }))
        }
        Ok(LoginOutcome::MustChangePassword { change_token, user }) => {
            state
                .audit(
                    tenant,
                    AuditAction::Login,
                    AuditOutcome::Success,
                    agf_core::audit::AuditActor {
                        id: Some(user.id),
                        kind: "user".to_string(),
                        name: user.username.clone(),
                        source_ip: request.source_ip.clone(),
                        user_agent: request.user_agent.clone(),
                        session_id: None,
                    },
                    AuditTarget::new("session", None, Some(user.username.clone())),
                    "登录成功但必须修改口令（未签发可用令牌）",
                )
                .await?;
            Ok(Json(LoginResponse {
                password_policy: crate::auth_policy::TenantPolicy::load(&state, tenant).await?.view,
                roles: state.auth_backend.roles_of(tenant, user.id).await?,
                mfa_enrollment_required: false,
                must_change_password: true,
                tokens: None,
                change_token: Some(change_token),
                user,
                permissions: Vec::new(),
                message: "首次登录必须修改口令：请用 change_token 调用 POST /api/v1/auth/change-password".to_string(),
            }))
        }
        Err(e) => {
            let failure = state
                .audit(
                    tenant,
                    AuditAction::Login,
                    AuditOutcome::Failure,
                    agf_core::audit::AuditActor {
                        id: None,
                        kind: "user".to_string(),
                        name: request.username.clone(),
                        source_ip: request.source_ip.clone(),
                        user_agent: request.user_agent.clone(),
                        session_id: None,
                    },
                    AuditTarget::new("session", None, Some(request.username.clone())),
                    "登录失败",
                )
                .await;
            if let Err(err) = failure {
                tracing::warn!(error = %err, "登录失败审计写入失败");
            }
            Err(ApiError::new(e))
        }
    }
}

/// 改密请求。
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct ChangePasswordBody {
    /// 当前口令（非首登场景必填）。
    #[serde(default)]
    pub current_password: Option<String>,
    /// 新口令。
    pub new_password: String,
}

/// 修改口令（`POST /api/v1/auth/change-password`）。
///
/// # Errors
/// 未认证、当前口令错误、新口令不符合策略。
pub async fn change_password(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<ChangePasswordBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let Some(user_id) = principal.subject_id else {
        return Err(ApiError::new(DomainError::Unauthenticated("缺少主体身份".to_string())));
    };
    let tenant = principal.identity_tenant;
    if principal.subject_kind != agf_core::rbac::SubjectKind::User {
        return Err(DomainError::Forbidden("只有用户会话可以修改密码".into()).into());
    }
    let user = state
        .auth_backend
        .find_user(tenant, user_id)
        .await?
        .ok_or_else(|| DomainError::Unauthenticated("账号不存在".into()))?;
    if principal.must_change_password && !user.must_change_password {
        return Err(DomainError::Unauthenticated("改密令牌已使用，请重新登录".into()).into());
    }
    if !user.must_change_password {
        let Some(current) = body.current_password.as_deref().filter(|s| !s.is_empty()) else {
            return Err(ApiError::new(DomainError::Validation("非首次改密必须提供 current_password".to_string())));
        };
        let Some(user) = state.auth_backend.find_user(tenant, user_id).await? else {
            return Err(ApiError::new(DomainError::NotFound { entity: "user", id: user_id.to_string() }));
        };
        let record = state.auth_backend.find_user_with_secret(tenant, &user.username).await?;
        let mut verified = false;
        if let Some(rec) = record {
            if let Some(phc) = rec.password_hash {
                verified = state.auth.hasher().verify(current, &phc)?;
            }
        }
        if !verified {
            return Err(ApiError::new(DomainError::Unauthenticated("当前口令错误".to_string())));
        }
    }
    let policy = crate::auth_policy::TenantPolicy::load(&state, tenant).await?;
    policy.validate(&body.new_password)?;
    state
        .auth
        .with_policy(policy.core(&state))
        .change_password(&*state.auth_backend, tenant, user_id, &body.new_password)
        .await?;
    state
        .audit(
            tenant,
            AuditAction::Update,
            AuditOutcome::Success,
            AppState::audit_actor(&principal, "self"),
            AuditTarget::new("user", Some(user_id.to_string()), None),
            "修改口令",
        )
        .await?;
    Ok(Json(serde_json::json!({
        "status": "ok",
        "must_change_password": false,
        "message": "口令已修改，请使用新口令重新登录",
    })))
}

/// 刷新令牌请求。
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct RefreshBody {
    /// 刷新令牌明文。
    pub refresh_token: String,
}

/// 刷新令牌（`POST /api/v1/auth/refresh`，轮换并吊销旧令牌）。
///
/// # Errors
/// 刷新令牌无效/已吊销/已过期。
pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<RefreshBody>,
) -> ApiResult<Json<agf_core::auth::TokenPair>> {
    let value = headers.get(HEADER_TENANT).and_then(|v| v.to_str().ok()).unwrap_or("default");
    let tenant = crate::tenant_directory::resolve(&state, value).await?.id;
    let pair = crate::auth_policy::service(&state, tenant)
        .await?
        .refresh(&*state.auth_backend, tenant, &body.refresh_token)
        .await?;
    Ok(Json(pair))
}

/// 登出（`POST /api/v1/auth/logout`，吊销刷新令牌）。
///
/// # Errors
/// 未认证或存储错误。
pub async fn logout(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<RefreshBody>,
) -> ApiResult<Json<serde_json::Value>> {
    state.auth.logout(&*state.auth_backend, principal.identity_tenant, &body.refresh_token).await?;
    state
        .audit(
            principal.identity_tenant,
            AuditAction::Logout,
            AuditOutcome::Success,
            AppState::audit_actor(&principal, "self"),
            AuditTarget::new("session", principal.session_id.clone(), None),
            "登出",
        )
        .await?;
    Ok(Json(serde_json::json!({"status": "ok", "message": "已登出"})))
}

/// 当前用户（`GET /api/v1/auth/me`）。
///
/// # Errors
/// 主体不存在或存储错误。
pub async fn me(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<serde_json::Value>> {
    let access: std::collections::BTreeMap<String, bool> = agf_core::rbac::ResourceGroup::all()
        .into_iter()
        .flat_map(|group| {
            agf_core::rbac::Action::all().into_iter().map(move |action| (group.as_str(), action.as_str()))
        })
        .map(|(group, action)| (format!("{group}:{action}"), principal.require(&state, group, action).is_ok()))
        .collect();
    let mut effective =
        state.authorizer.effective_permissions(principal.subject_id, &principal.roles, principal.superadmin, None);
    if principal.subject_kind == agf_core::rbac::SubjectKind::ApiKey {
        effective.permissions = principal.scopes.iter().cloned().collect();
        effective.read_only = !principal.superadmin
            && principal
                .scopes
                .iter()
                .all(|permission| permission.as_str().ends_with(":read") || permission.as_str().ends_with(":export"));
    }
    let user = match (principal.subject_kind, principal.subject_id) {
        (agf_core::rbac::SubjectKind::User, Some(id)) => {
            state.auth_backend.find_user(principal.identity_tenant, id).await?
        }
        _ => None,
    };
    Ok(Json(serde_json::json!({
        "subject_id": principal.subject_id,
        "subject_kind": principal.subject_kind.as_str(),
        "tenant_id": principal.tenant,
        "identity_tenant_id": principal.identity_tenant,
        "roles": principal.roles,
        "superadmin": principal.superadmin,
        "must_change_password": principal.must_change_password,
        "session_id": principal.session_id,
        "read_only": effective.read_only,
        "scopes": principal.scopes.iter().map(Permission::as_str).collect::<Vec<_>>(),
        "permissions": effective.permissions.iter().map(Permission::as_str).collect::<Vec<_>>(),
        "access": access,
        "user": user,
    })))
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name).and_then(|v| v.to_str().ok()).map(str::trim).filter(|s| !s.is_empty()).map(ToString::to_string)
}
