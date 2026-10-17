//! Cross-device QR sign-in: the QR contains only a flow ID, never a token.
use super::*;
use agf_auth::service::{LoginOutcome, LoginRequest};
use agf_core::{
    audit::{AuditAction, AuditActor, AuditOutcome, AuditTarget},
    rbac::SubjectKind,
    secret::generate_token,
    user::User,
};
use axum::{extract::Path, http::HeaderMap};

const KIND: &str = "qr-login-flow";
const LIFETIME_SECS: i64 = 180;

#[derive(Default, Clone, Serialize, Deserialize)]
struct Flow {
    expires_at: i64,
    phase: String,
    binding_hash: String,
    user_id: Option<Id>,
    attempts: u8,
}

#[derive(Deserialize)]
struct Start {
    tenant_slug: String,
}

#[derive(Deserialize)]
struct Claim {
    tenant_slug: String,
    state: Id,
    binding: String,
}

#[derive(Deserialize)]
struct Approve {
    mfa_code: String,
}

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/qr/start", post(start))
        .route("/auth/qr/status", post(status))
        .route("/auth/qr/complete", post(complete))
        .route("/auth/qr/{tenant_slug}/{state}/preview", get(preview))
        .route("/auth/qr/{tenant_slug}/{state}/approve", post(approve))
}

fn denied() -> DomainError {
    DomainError::Unauthenticated("扫码登录事务无效或已过期，请重新生成二维码".into())
}

fn live(flow: &Flow) -> DomainResult<()> {
    if flow.expires_at <= Timestamp::now().unix_secs()
        || !matches!(flow.phase.as_str(), "pending" | "verifying" | "approved")
    {
        return Err(denied());
    }
    Ok(())
}

async fn flow(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Flow> {
    let stored: Flow = state.configurations.get(tenant, KIND, id).await?.ok_or_else(denied)?;
    live(&stored)?;
    Ok(stored)
}

async fn approving_user(state: &AppState, principal: &Principal, tenant: TenantId) -> DomainResult<User> {
    if principal.subject_kind != SubjectKind::User
        || principal.tenant != tenant
        || principal.identity_tenant != tenant
        || principal.must_change_password
        || principal.must_setup_mfa
    {
        return Err(DomainError::Forbidden("请使用目标租户内已完成 MFA 的用户会话批准扫码登录".into()));
    }
    let id = principal.subject_id.ok_or_else(denied)?;
    let user = state.auth_backend.find_user(tenant, id).await?.ok_or_else(denied)?;
    if !user.can_authenticate() || !user.mfa_enabled || user.must_change_password {
        return Err(DomainError::PreconditionFailed("请先在当前账号启用平台 MFA，再批准扫码登录".into()));
    }
    Ok(user)
}

async fn start(State(state): State<AppState>, ApiJson(body): ApiJson<Start>) -> ApiResult<Json<Value>> {
    let tenant = crate::tenant_directory::resolve(&state, &body.tenant_slug).await?.id;
    state.configurations.purge_expired(tenant, KIND, Timestamp::now().unix_secs()).await?;
    let id = Id::new();
    let binding = generate_token();
    let expires_at = Timestamp::now().unix_secs() + LIFETIME_SECS;
    state
        .configurations
        .put(
            tenant,
            KIND,
            id,
            &Flow {
                expires_at,
                phase: "pending".into(),
                binding_hash: agf_auth::oidc::challenge(&binding),
                ..Flow::default()
            },
        )
        .await?;
    Ok(Json(json!({"state":id,"binding":binding,"expires_at":expires_at})))
}

async fn preview(
    Path((slug, raw_id)): Path<(String, String)>,
    State(state): State<AppState>,
    principal: Principal,
) -> ApiResult<Json<Value>> {
    let tenant = crate::tenant_directory::resolve(&state, &slug).await?.id;
    let user = approving_user(&state, &principal, tenant).await?;
    let id = Id::parse(&raw_id).map_err(|_| denied())?;
    let stored = flow(&state, tenant, id).await?;
    Ok(Json(json!({"expires_at":stored.expires_at,"status":stored.phase,
        "tenant_slug":slug,"user_name":user.display_name})))
}

async fn approve(
    Path((slug, raw_id)): Path<(String, String)>,
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<Approve>,
) -> ApiResult<Json<Value>> {
    let tenant = crate::tenant_directory::resolve(&state, &slug).await?.id;
    let user = approving_user(&state, &principal, tenant).await?;
    let id = Id::parse(&raw_id).map_err(|_| denied())?;
    if !(6..=64).contains(&body.mfa_code.len()) {
        return Err(DomainError::Validation("请填写 MFA 验证码或恢复码".into()).into());
    }
    state
        .configurations
        .mutate(tenant, KIND, id, |stored: &mut Flow| {
            live(stored)?;
            if stored.phase != "pending" || stored.attempts >= 5 {
                return Err(denied());
            }
            stored.phase = "verifying".into();
            stored.attempts += 1;
            Ok(())
        })
        .await?;
    let verified = state.auth_backend.verify_mfa(tenant, &user, Some(&body.mfa_code)).await;
    if !matches!(verified, Ok(true)) {
        state
            .configurations
            .mutate(tenant, KIND, id, |stored: &mut Flow| {
                if stored.phase == "verifying" {
                    stored.phase = "pending".into();
                }
                Ok(())
            })
            .await?;
        if !verified? {
            state
                .audit(
                    tenant,
                    AuditAction::Approve,
                    AuditOutcome::Denied,
                    AppState::audit_actor(&principal, "qr-login"),
                    AuditTarget::new("qr-login", Some(id.to_string()), None),
                    "扫码登录批准 MFA 验证失败",
                )
                .await?;
            return Err(DomainError::Unauthenticated("MFA 验证码或恢复码错误".into()).into());
        }
    }
    let entry = AppState::audit_entry(
        tenant,
        AuditAction::Approve,
        AuditOutcome::Success,
        AppState::audit_actor(&principal, "qr-login"),
        AuditTarget::new("qr-login", Some(id.to_string()), Some(user.username.clone())),
        "批准新浏览器扫码登录",
    );
    let (_, sealed) = state
        .configurations
        .mutate_audited::<Flow, _>(tenant, KIND, id, entry.clone(), |stored| {
            live(stored)?;
            if stored.phase != "verifying" {
                return Err(denied());
            }
            stored.phase = "approved".into();
            stored.user_id = Some(user.id);
            Ok(())
        })
        .await?;
    if let Some(sealed) = sealed {
        if let Err(error) = state.store.hydrate_audit(&sealed) {
            tracing::warn!(%error, "扫码批准审计投影刷新失败");
        }
    } else {
        state.store.audit_append_durable(entry).await?;
    }
    Ok(Json(json!({"approved":true})))
}

async fn status(State(state): State<AppState>, ApiJson(body): ApiJson<Claim>) -> ApiResult<Json<Value>> {
    let tenant = crate::tenant_directory::resolve(&state, &body.tenant_slug).await?.id;
    let stored = flow(&state, tenant, body.state).await?;
    if !(32..=256).contains(&body.binding.len()) || stored.binding_hash != agf_auth::oidc::challenge(&body.binding) {
        return Err(denied().into());
    }
    Ok(Json(json!({"status":if stored.phase == "approved" {"approved"} else {"pending"},
        "expires_at":stored.expires_at})))
}

async fn complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Claim>,
) -> ApiResult<Json<crate::routes::auth::LoginResponse>> {
    let tenant = crate::tenant_directory::resolve(&state, &body.tenant_slug).await?.id;
    if !(32..=256).contains(&body.binding.len()) {
        return Err(denied().into());
    }
    let stored: Flow = state
        .configurations
        .mutate(tenant, KIND, body.state, |stored: &mut Flow| {
            live(stored)?;
            if stored.phase != "approved" || stored.binding_hash != agf_auth::oidc::challenge(&body.binding) {
                return Err(denied());
            }
            stored.phase = "redeeming".into();
            Ok(())
        })
        .await?;
    let user_id = stored.user_id.ok_or_else(denied)?;
    let request = LoginRequest {
        username: String::new(),
        password: String::new(),
        mfa_code: None,
        source_ip: None,
        user_agent: headers.get("user-agent").and_then(|v| v.to_str().ok()).map(str::to_owned),
        device: Some("qr-browser".into()),
    };
    let auth = crate::auth_policy::service(&state, tenant).await?;
    let LoginOutcome::Success { tokens, user, permissions } =
        auth.login_approved_device(&*state.auth_backend, tenant, user_id, &request).await?
    else {
        return Err(denied().into());
    };
    state.configurations.delete(tenant, KIND, body.state).await?;
    state
        .audit(
            tenant,
            AuditAction::Login,
            AuditOutcome::Success,
            AuditActor {
                id: Some(user.id),
                kind: "user".into(),
                name: user.username.clone(),
                source_ip: None,
                user_agent: request.user_agent,
                session_id: Some(tokens.session_id.clone()),
            },
            AuditTarget::new("session", Some(tokens.session_id.clone()), Some(user.username.clone())),
            "扫码登录成功",
        )
        .await?;
    Ok(Json(crate::routes::auth::LoginResponse {
        password_policy: crate::auth_policy::TenantPolicy::load(&state, tenant).await?.view,
        roles: state.auth_backend.roles_of(tenant, user.id).await?,
        mfa_enrollment_required: false,
        must_change_password: false,
        tokens: Some(tokens),
        change_token: None,
        user,
        permissions,
        message: "扫码登录成功".into(),
    }))
}
