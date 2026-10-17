//! 真实账号管理：创建强制改密账号，修改角色/状态并立即影响现存会话。
use super::*;
use crate::routes::{ApiJson, parse_id};
use agf_core::{
    audit::{AuditAction, AuditOutcome, AuditTarget},
    user::{User, UserState},
};
use axum::extract::Path;

#[derive(Deserialize)]
pub(super) struct CreateUser {
    username: String,
    email: String,
    #[serde(default)]
    display_name: String,
    password: String,
    role: String,
}

#[derive(Deserialize)]
pub(super) struct UpdateUser {
    expected_version: Option<u64>,
    role: Option<String>,
    status: Option<String>,
}

fn role_name(value: &str) -> Result<&'static str, ApiError> {
    match value {
        "admin" => Ok("tenant-admin"),
        "analyst" => Ok("soc-analyst"),
        "responder" => Ok("redteam-engineer"),
        "auditor" => Ok("auditor"),
        "viewer" => Ok("viewer"),
        _ => Err(DomainError::Validation("请选择租户管理员、安全运营、红队、审计或只读角色".into()).into()),
    }
}

pub(super) async fn create_user(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<CreateUser>,
) -> ApiResult<(axum::http::StatusCode, Json<UserView>)> {
    principal.require(&state, "platform", "admin")?;
    let username = body.username.trim();
    let email = body.email.trim();
    if username.is_empty() || username.len() > 80 || email.len() > 254 || !email.contains('@') {
        return Err(DomainError::Validation("请输入 1–80 字符用户名和有效邮箱".into()).into());
    }
    let roles = vec![role_name(&body.role)?.to_string()];
    if state.auth_backend.find_user_with_secret(principal.tenant, username).await?.is_some() {
        return Err(DomainError::Conflict("用户名已存在".into()).into());
    }
    let policy = crate::auth_policy::TenantPolicy::load(&state, principal.tenant).await?;
    policy.validate(&body.password)?;
    let auth = state.auth.with_policy(policy.core(&state));
    let phc = auth.hasher().hash_checked(&body.password, username)?;
    let mut user = User::new_local(principal.tenant, username, email);
    if !body.display_name.trim().is_empty() {
        user.display_name = body.display_name.trim().into();
    }
    user.password_changed_at = Some(Timestamp::now());
    state.auth_backend.save_account(&user, Some(&phc), &roles).await?;
    audit_account(&state, &principal, &user, "创建账号；首次登录必须修改初始口令").await?;
    let saved = state
        .auth_backend
        .find_user(principal.tenant, user.id)
        .await?
        .ok_or(DomainError::NotFound { entity: "user", id: user.id.to_string() })?;
    let view = super::identity::user_view(&state, principal.tenant, &saved, false).await?;
    Ok((axum::http::StatusCode::CREATED, Json(view)))
}

pub(super) async fn update_user(
    State(state): State<AppState>,
    principal: Principal,
    Path(raw): Path<String>,
    ApiJson(body): ApiJson<UpdateUser>,
) -> ApiResult<Json<UserView>> {
    principal.require(&state, "platform", "admin")?;
    let expected_version =
        body.expected_version.ok_or_else(|| DomainError::Validation("更新账号须提供 expected_version".into()))?;
    if body.role.is_none() && body.status.is_none() {
        return Err(DomainError::Validation("请选择要修改的角色或状态".into()).into());
    }
    let id = parse_id(&raw, "user")?;
    let mut user = state
        .auth_backend
        .find_user(principal.tenant, id)
        .await?
        .ok_or(DomainError::NotFound { entity: "user", id: raw })?;
    if user.version != expected_version {
        return Err(DomainError::Conflict("账号已被其他操作修改，请刷新后重试".into()).into());
    }
    if user.is_superadmin || principal.subject_id == Some(id) {
        return Err(DomainError::Forbidden("此入口不能调整平台所有者或当前账号，避免管理账号被锁出".into()).into());
    }
    let roles = match body.role {
        Some(role) => vec![role_name(&role)?.to_string()],
        None => state.auth_backend.roles_of(principal.tenant, id).await?,
    };
    if let Some(status) = body.status {
        user.state = match status.as_str() {
            "active" => UserState::Active,
            "disabled" => UserState::Disabled,
            "locked" => UserState::Locked,
            _ => return Err(DomainError::Validation("无效账号状态".into()).into()),
        };
        if user.state == UserState::Active {
            user.failed_logins = 0;
            user.locked_until = None;
        }
    }
    user.updated_at = Timestamp::now();
    state.auth_backend.save_account(&user, None, &roles).await?;
    audit_account(&state, &principal, &user, "更新账号角色或状态").await?;
    let saved = state
        .auth_backend
        .find_user(principal.tenant, id)
        .await?
        .ok_or(DomainError::NotFound { entity: "user", id: id.to_string() })?;
    Ok(Json(super::identity::user_view(&state, principal.tenant, &saved, false).await?))
}

async fn audit_account(state: &AppState, principal: &Principal, user: &User, note: &str) -> ApiResult<()> {
    state
        .audit(
            principal.tenant,
            AuditAction::Grant,
            AuditOutcome::Success,
            AppState::audit_actor(principal, "user-management"),
            AuditTarget::new("user", Some(user.id.to_string()), Some(user.username.clone())),
            note,
        )
        .await?;
    Ok(())
}
