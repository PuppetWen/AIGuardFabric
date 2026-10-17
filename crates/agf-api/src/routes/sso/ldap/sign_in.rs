use super::*;
use agf_auth::service::{LoginOutcome, LoginRequest};
use agf_core::user::{IdentityProvider, User};
use axum::http::HeaderMap;

#[derive(Deserialize)]
pub(super) struct Body {
    tenant_slug: String,
    username: String,
    password: String,
    mfa_code: Option<String>,
}

async fn resolve(
    state: &AppState,
    tenant: TenantId,
    provider: &Directory,
    identity: &agf_auth::ldap::Identity,
) -> DomainResult<User> {
    let external = serde_json::to_string(&[&provider.config.url, &identity.subject])?;
    let id = agf_core::ids::deterministic_id("ldap-user", &format!("{tenant}:{external}"));
    if state.auth_backend.find_user(tenant, id).await?.is_none() && provider.auto_provision {
        let mut user = User::new_local(tenant, format!("ldap-{id}"), identity.email.clone().unwrap_or_default());
        user.id = id;
        user.idp = IdentityProvider::Ldap;
        user.external_subject = Some(external.clone());
        user.must_change_password = false;
        user.display_name = identity.name.clone().unwrap_or_else(|| user.username.clone());
        state.auth_backend.provision_federated(&user, std::slice::from_ref(&provider.default_role)).await?;
    }
    let user = state
        .auth_backend
        .find_user(tenant, id)
        .await?
        .ok_or_else(|| DomainError::Forbidden("目录账号尚未纳管，请联系管理员启用首次登录创建账号".into()))?;
    if user.idp != IdentityProvider::Ldap
        || user.external_subject.as_deref() != Some(&external)
        || user.is_superadmin
        || !user.can_authenticate()
    {
        return Err(DomainError::Forbidden("企业目录账号不可用".into()));
    }
    Ok(user)
}

pub(super) async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Body>,
) -> ApiResult<Json<crate::routes::auth::LoginResponse>> {
    let tenant = crate::tenant_directory::resolve(&state, &body.tenant_slug).await?.id;
    let provider = provider(&state, tenant).await?;
    let secret = provider.secret.as_ref().ok_or_else(|| DomainError::Config("目录服务账号未配置".into()))?;
    let service_password = unseal(&state, tenant, Id::nil(), secret)?;
    let identity =
        agf_auth::ldap::authenticate(&provider.config, &service_password, &body.username, &body.password).await;
    let identity = match identity {
        Ok(value) => value,
        Err(error) => {
            let _ = state
                .audit(
                    tenant,
                    agf_core::audit::AuditAction::Login,
                    agf_core::audit::AuditOutcome::Failure,
                    agf_core::audit::AuditActor {
                        id: None,
                        kind: "user".into(),
                        name: body.username,
                        source_ip: None,
                        user_agent: headers.get("user-agent").and_then(|v| v.to_str().ok()).map(str::to_owned),
                        session_id: None,
                    },
                    agf_core::audit::AuditTarget::new("session", None, None),
                    "企业 LDAP/AD 登录失败",
                )
                .await;
            return Err(error.into());
        }
    };
    if super::provider(&state, tenant).await?.revision != provider.revision {
        return Err(DomainError::PreconditionFailed("目录配置已变化，请重新登录".into()).into());
    }
    let user = resolve(&state, tenant, &provider, &identity).await?;
    let auth = crate::auth_policy::service(&state, tenant).await?;
    let request = LoginRequest {
        username: body.username,
        password: String::new(),
        mfa_code: body.mfa_code,
        source_ip: headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).map(str::to_owned),
        user_agent: headers.get("user-agent").and_then(|v| v.to_str().ok()).map(str::to_owned),
        device: Some("ldap".into()),
    };
    let LoginOutcome::Success { tokens, user, permissions } =
        auth.login_federated(&*state.auth_backend, tenant, user.id, &request).await?
    else {
        return Err(DomainError::Unauthenticated("企业目录登录未完成".into()).into());
    };
    super::super::recent::record(&state, tenant, user.id, &tokens.session_id).await?;
    state
        .audit(
            tenant,
            agf_core::audit::AuditAction::Login,
            agf_core::audit::AuditOutcome::Success,
            agf_core::audit::AuditActor {
                id: Some(user.id),
                kind: "user".into(),
                name: user.username.clone(),
                source_ip: request.source_ip,
                user_agent: request.user_agent,
                session_id: Some(tokens.session_id.clone()),
            },
            agf_core::audit::AuditTarget::new("session", Some(tokens.session_id.clone()), Some(user.username.clone())),
            "企业 LDAP/AD 登录成功",
        )
        .await?;
    Ok(Json(crate::routes::auth::LoginResponse {
        password_policy: crate::auth_policy::TenantPolicy::load(&state, tenant).await?.view,
        roles: state.auth_backend.roles_of(tenant, user.id).await?,
        mfa_enrollment_required: state.auth_backend.mfa_required(tenant).await? && !user.mfa_enabled,
        must_change_password: false,
        tokens: Some(tokens),
        change_token: None,
        user,
        permissions,
        message: "企业目录登录成功".into(),
    }))
}
