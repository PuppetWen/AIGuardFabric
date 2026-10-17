use super::*;
use agf_core::user::{IdentityProvider, User};

pub(super) async fn resolve(
    state: &AppState,
    tenant: TenantId,
    provider: &Provider,
    identity: &oidc::Identity,
) -> DomainResult<User> {
    if !provider.email_domains.is_empty()
        && !identity
            .email
            .as_ref()
            .and_then(|e| e.rsplit_once('@'))
            .is_some_and(|(_, domain)| provider.email_domains.iter().any(|d| d.eq_ignore_ascii_case(domain)))
    {
        return Err(DomainError::Forbidden("身份服务未返回允许域名下的已验证邮箱".into()));
    }
    let external = serde_json::to_string(&[&identity.issuer, &identity.subject])?;
    let id = agf_core::ids::deterministic_id("oidc-user", &format!("{tenant}:{external}"));
    if state.auth_backend.find_user(tenant, id).await?.is_none() && provider.auto_provision {
        // A stable ID plus an atomic insert prevents concurrent first logins from resetting roles or disabled accounts.
        let mut user = User::new_local(tenant, format!("oidc-{id}"), identity.email.clone().unwrap_or_default());
        user.id = id;
        user.idp = IdentityProvider::Oidc;
        user.external_subject = Some(external.clone());
        user.must_change_password = false;
        user.display_name = identity.name.clone().unwrap_or_else(|| user.username.clone());
        state.auth_backend.provision_federated(&user, std::slice::from_ref(&provider.default_role)).await?;
    }
    let user = state
        .auth_backend
        .find_user(tenant, id)
        .await?
        .ok_or_else(|| DomainError::Forbidden("账号尚未纳管，请联系管理员启用首次登录创建账号".into()))?;
    if user.idp != IdentityProvider::Oidc
        || user.external_subject.as_deref() != Some(&external)
        || user.is_superadmin
        || !user.can_authenticate()
    {
        return Err(DomainError::Forbidden("企业账号不可用".into()));
    }
    Ok(user)
}
