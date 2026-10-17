//! SQL MCP 夹具更换配置存储后，显式重绑原同步账号与当前 MFA 配置。
use agf_api::AppState;
use agf_auth::service::{AuthBackend, CurrentUserAuthority, InMemoryAuthBackend};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::TenantId,
};
use std::sync::Arc;

/// 仅用于尚未启动请求的夹具装配；不复制会话、刷新令牌或登录历史。
/// 保留账号全部字段、版本、角色和口令 PHC，不嵌套保留旧 ProtectedBackend。
pub(crate) async fn rebind(state: &mut AppState, tenants: &[TenantId]) -> DomainResult<()> {
    let database = state.store.database().ok_or_else(|| DomainError::Config("SQL 夹具缺少业务数据库".into()))?;
    if !state.configurations.uses_database(database) {
        return Err(DomainError::Config("SQL 夹具配置与业务数据库不一致".into()));
    }
    let previous = state.auth_backend.clone();
    let replacement = Arc::new(InMemoryAuthBackend::new());
    let mut copied = false;
    // common::setup 的 JWT 身份位于默认租户；业务租户可以另选。
    let mut identities = vec![TenantId::default_tenant()];
    for tenant in tenants {
        if !identities.contains(tenant) {
            identities.push(*tenant);
        }
    }
    for tenant in identities {
        for listed in previous.list_users(tenant).await? {
            let CurrentUserAuthority::Synchronous { user: Some(user), roles, .. } =
                previous.current_user_authority(tenant, listed.id)?
            else {
                return Err(DomainError::Config("此夹具只允许显式同步内存身份".into()));
            };
            let secret = previous
                .find_user_with_secret(tenant, &user.username)
                .await?
                .ok_or_else(|| DomainError::Config("夹具账号缺少原口令记录".into()))?;
            if serde_json::to_value(&secret.user)? != serde_json::to_value(&user)? {
                return Err(DomainError::Config("夹具账号复制期间发生变化".into()));
            }
            let id = user.id;
            let expected = serde_json::to_value(&user)?;
            replacement.insert_user(*user, secret.password_hash)?;
            replacement.set_roles(id, roles.clone())?;
            let CurrentUserAuthority::Synchronous { user: Some(user), roles: saved_roles, .. } =
                replacement.current_user_authority(tenant, id)?
            else {
                return Err(DomainError::Config("夹具账号复制失败".into()));
            };
            if serde_json::to_value(&user)? != expected || saved_roles != roles {
                return Err(DomainError::Config("夹具账号字段或角色发生变化".into()));
            }
            copied = true;
        }
    }
    if !copied {
        return Err(DomainError::Config("SQL MCP 夹具不得使用无账号的 JWT 身份".into()));
    }
    state.auth_backend = Arc::new(agf_api::auth_store::protected::ProtectedBackend::new(
        replacement,
        state.configurations.clone(),
        &state.config.security.master_key_b64,
    ));
    Ok(())
}
