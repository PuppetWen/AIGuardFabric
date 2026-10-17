//! 身份类只读端点：用户 / 租户 / API Key / 密码策略 / 黑名单。

use super::*;

// ===========================================================================
// 身份：用户 / 租户 / API Key
// ===========================================================================

/// 用户列表（`GET /api/v1/users`）：**裸数组**。
///
/// 从认证后端读取当前租户的完整账号目录，包含本地及已纳管的企业账号。
///
/// # Errors
/// 权限不足（`platform:admin`）或认证后端错误。
pub(super) async fn list_users(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Vec<UserView>>> {
    principal.require(&state, "platform", "admin")?;
    let tenant = principal.tenant;
    let mut users = Vec::new();
    for user in state.auth_backend.list_users(tenant).await? {
        users.push(user_view(&state, tenant, &user, user.is_superadmin).await?);
    }
    Ok(Json(users))
}

/// 用户 → 视图（角色由 `roles_of` 映射，与 `client.ts::mapRole` 同口径）。
///
/// # Errors
/// 认证后端错误。
pub(super) async fn user_view(
    state: &AppState,
    tenant: TenantId,
    user: &agf_core::user::User,
    is_superadmin: bool,
) -> ApiResult<UserView> {
    let roles = state.auth_backend.roles_of(tenant, user.id).await?;
    Ok(UserView {
        version: user.version,
        identity_provider: user.idp.as_str().into(),
        id: user.id.to_string(),
        tenant_id: user.tenant_id.to_string(),
        username: user.username.clone(),
        display_name: if user.display_name.is_empty() { user.username.clone() } else { user.display_name.clone() },
        email: user.email.clone(),
        role: user_role(&roles, is_superadmin).to_string(),
        mfa_enabled: user.mfa_enabled,
        must_change_password: user.must_change_password,
        // domain.ts 不允许 null：从未登录时回落账号创建时间。
        last_login_at: user.last_login_at.unwrap_or(user.created_at).to_rfc3339(),
        status: user_state_frontend(user.state).to_string(),
    })
}

/// 平台角色 → 控制台角色（`client.ts::mapRole` 的同一张表）。
fn user_role(roles: &[String], is_superadmin: bool) -> &'static str {
    if is_superadmin || roles.iter().any(|role| role == "superadmin") {
        return "owner";
    }
    for role in roles {
        let mapped = match role.as_str() {
            "tenant-admin" => Some("admin"),
            "soc-analyst" => Some("analyst"),
            "redteam-engineer" => Some("responder"),
            "auditor" => Some("auditor"),
            "viewer" | "asset-owner" => Some("viewer"),
            _ => None,
        };
        if let Some(mapped) = mapped {
            return mapped;
        }
    }
    // 未命中任何内置角色：按最小权限呈现（与前端 mapRole 的兜底一致）。
    "viewer"
}

/// 账号状态 → 控制台状态（`invited` 按不可登录处理，归 `disabled`）。
const fn user_state_frontend(state: agf_core::user::UserState) -> &'static str {
    match state {
        agf_core::user::UserState::Active => "active",
        agf_core::user::UserState::Locked => "locked",
        agf_core::user::UserState::Disabled | agf_core::user::UserState::Invited => "disabled",
    }
}

/// 租户列表（`GET /api/v1/tenants`）：超管可见目录，其余用户只见所属租户。
///
/// # Errors
/// 权限不足（`platform:admin`）或存储错误。
pub(super) async fn list_tenants(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<Vec<TenantView>>> {
    principal.require(&state, "settings", "read")?;
    let ids = if principal.superadmin {
        crate::tenant_directory::list(&state).await?.into_iter().map(|row| row.id).collect()
    } else {
        vec![principal.tenant]
    };
    let mut views = Vec::new();
    for id in ids {
        views.push(super::settings::current(&state, id).await?);
    }
    Ok(Json(views))
}

/// 默认租户视图（白标/套餐/区域取环境变量，缺省值见模块文档）。
pub(super) fn tenant_view(state: &AppState, tenant: TenantId, quotas: &[Quota]) -> TenantView {
    let created_at = quotas.iter().map(|q| q.created_at).min().unwrap_or_else(Timestamp::now);
    TenantView {
        version: 0,
        directory_version: 0,
        directory_name: String::new(),
        id: tenant.to_string(),
        enabled: true,
        slug: env_or("AGF_DEFAULT_TENANT_SLUG", agf_core::constants::DEFAULT_TENANT_SLUG),
        name: env_or("AGF_TENANT_NAME", "默认租户"),
        plan: env_or("AGF_TENANT_PLAN", "enterprise"),
        region: env_or("AGF_TENANT_REGION", "cn-hangzhou"),
        white_label: WhiteLabelView {
            product_name: env_or("AGF_PRODUCT_NAME", agf_core::constants::PRODUCT_NAME_ZH),
            logo_text: env_or("AGF_LOGO_TEXT", "AGF"),
            primary_color: env_or("AGF_PRIMARY_COLOR", "#1677ff"),
            favicon: None,
        },
        quota_defaults: QuotaDefaultsView {
            version: 0,
            // 真实：租户级 Token/日 配额上限（缺省回落到配置值）。
            tenant_tokens_per_day: quota_limit(quotas, QuotaScope::Tenant, QuotaDimension::Tokens)
                .unwrap_or(state.config.quota.tenant_tokens_per_day),
            // 前端字段是"每小时/每轮"，配置里是"每日/每会话"：**不做不同粒度的换算**，无对应配额时为 0。
            agent_tokens_per_hour: quota_limit(quotas, QuotaScope::Agent, QuotaDimension::Tokens).unwrap_or(0),
            session_tokens_per_turn: quota_limit(quotas, QuotaScope::Session, QuotaDimension::Tokens).unwrap_or(0),
            max_concurrent_sessions: quota_limit(quotas, QuotaScope::Tenant, QuotaDimension::Concurrency).unwrap_or(0),
        },
        created_at: created_at.to_rfc3339(),
    }
}

/// 读取环境变量（空白视为未设置）。
fn env_or(key: &str, fallback: &str) -> String {
    match std::env::var(key) {
        Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => fallback.to_string(),
    }
}

/// 指定作用域 + 维度的配额上限。
fn quota_limit(quotas: &[Quota], scope: QuotaScope, dimension: QuotaDimension) -> Option<i64> {
    quotas.iter().find(|q| q.scope == scope && q.dimension == dimension).map(|q| q.limit)
}

/// API Key 列表（`GET /api/v1/api-keys`）：**裸数组**，与 `/settings/api-keys` 同源但按
/// domain.ts 的 `ApiKey` 投影（**不含 `key_fingerprint`、`allowed_cidrs`**）。
///
/// # Errors
/// 权限不足（`settings:read`）或存储错误。
pub(super) async fn list_api_keys(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<Vec<ApiKeyView>>> {
    principal.require(&state, "settings", "read")?;
    let keys = state.store.api_key_list_durable(principal.tenant).await?;
    Ok(Json(
        keys.into_iter()
            .map(|key| ApiKeyView {
                id: key.id.to_string(),
                tenant_id: key.tenant_id.to_string(),
                name: key.name,
                prefix: key.prefix,
                scopes: key.scopes.iter().map(|p| p.as_str().to_string()).collect(),
                created_at: key.created_at.to_rfc3339(),
                expires_at: key.expires_at.map(|t| t.to_rfc3339()),
                last_used_at: key.last_used_at.map(|t| t.to_rfc3339()),
                revoked: key.revoked,
                bound_agent_id: key.bound_agent_id.map(|id| id.to_string()),
            })
            .collect(),
    ))
}

/// 生效的口令策略（`GET /api/v1/settings/password-policy`）。
///
/// # Errors
/// 权限不足（`settings:read`）。
pub(super) async fn password_policy(
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<PasswordPolicyView>> {
    principal.require(&state, "settings", "read")?;
    Ok(Json(crate::auth_policy::TenantPolicy::load(&state, principal.tenant).await?.view))
}
