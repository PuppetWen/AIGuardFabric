//! 自助 MFA：重新验证口令、十分钟绑定窗口、一次性恢复码。
use crate::{
    error::ApiResult,
    mfa_store::{Enrollment, KIND, decrypt},
    middleware::Principal,
    routes::ApiJson,
    state::AppState,
};
use agf_auth::mfa::TotpService;
use agf_core::{error::DomainError, rbac::SubjectKind, time::Timestamp, user::User};
use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/mfa", get(status))
        .route("/auth/mfa/setup", post(setup))
        .route("/auth/mfa/confirm", post(confirm))
        .route("/auth/mfa/disable", post(disable))
}

#[derive(Deserialize)]
struct PasswordBody {
    #[serde(default)]
    current_password: String,
    code: Option<String>,
}
#[derive(Deserialize)]
struct CodeBody {
    code: String,
}

async fn current(state: &AppState, principal: &Principal) -> ApiResult<User> {
    if principal.subject_kind != SubjectKind::User || principal.must_change_password {
        return Err(DomainError::Forbidden("请先以用户身份登录并完成首次改密".into()).into());
    }
    let id = principal.subject_id.ok_or_else(|| DomainError::Unauthenticated("缺少用户身份".into()))?;
    state
        .auth_backend
        .find_user(principal.identity_tenant, id)
        .await?
        .ok_or_else(|| DomainError::Unauthenticated("账号不存在".into()).into())
}

async fn reauthenticate(state: &AppState, principal: &Principal, user: &User, password: &str) -> ApiResult<()> {
    if user.idp == agf_core::user::IdentityProvider::Oidc {
        crate::routes::sso::verify_recent(state, principal, user.id).await?;
        return Ok(());
    }
    let record = state.auth_backend.find_user_with_secret(user.tenant_id, &user.username).await?;
    let Some(hash) = record.and_then(|r| r.password_hash) else {
        return Err(DomainError::Unauthenticated("请使用本地账号的当前口令确认".into()).into());
    };
    if !state.auth.hasher().verify(password, &hash)? {
        return Err(DomainError::Unauthenticated("当前口令错误".into()).into());
    }
    Ok(())
}

async fn status(State(state): State<AppState>, principal: Principal) -> ApiResult<Json<Value>> {
    let user = current(&state, &principal).await?;
    Ok(Json(
        json!({"enabled":user.mfa_enabled,"required":state.auth_backend.mfa_required(principal.identity_tenant).await?,
        "password_required":user.idp != agf_core::user::IdentityProvider::Oidc}),
    ))
}

async fn setup(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<PasswordBody>,
) -> ApiResult<Json<Value>> {
    let user = current(&state, &principal).await?;
    reauthenticate(&state, &principal, &user, &body.current_password).await?;
    if user.mfa_enabled {
        return Err(DomainError::Conflict("MFA 已开启；更换设备前先使用验证码或恢复码关闭".into()).into());
    }
    let service = TotpService::default();
    let secret = service.generate_secret();
    let uri = service.provisioning_uri(&user.username, &secret)?;
    let encrypted = crate::model_gateway::encrypt(&state, principal.identity_tenant, user.id, secret.clone())?;
    state
        .configurations
        .mutate::<Enrollment, _>(principal.identity_tenant, KIND, user.id, |record| {
            // 更换待绑定密钥时保留会话撤销时刻，防止关闭后重新绑定使旧 JWT 复活。
            if record.confirmed {
                return Err(DomainError::Conflict("MFA 已在另一个会话中开启".into()));
            }
            *record = Enrollment {
                secret: Some(encrypted),
                created_at: Timestamp::now().unix_secs(),
                confirmed_at: record.confirmed_at,
                ..Enrollment::default()
            };
            Ok(())
        })
        .await?;
    Ok(Json(json!({"secret":secret,"uri":uri,"expires_in_seconds":600})))
}

async fn confirm(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<CodeBody>,
) -> ApiResult<Json<Value>> {
    let mut user = current(&state, &principal).await?;
    let cipher = crate::model_gateway::cipher(&state)?;
    if let Some(db) = state.store.database() {
        let recovery = crate::mfa_store::confirm_sql(db, &cipher, principal.identity_tenant, &user, &body.code).await?;
        audit(&state, &principal, "开启 TOTP MFA").await?;
        return Ok(Json(
            json!({"enabled":true,"recovery_codes":recovery,"message":"恢复码只显示一次，请保存后重新登录"}),
        ));
    }
    let service = TotpService::default();
    let mut recovery = Vec::new();
    let confirmed_at = Timestamp::now().unix_millis();
    state
        .configurations
        .mutate::<Enrollment, _>(principal.identity_tenant, KIND, user.id, |record| {
            if record.confirmed {
                return Err(DomainError::Conflict("MFA 已确认，请重新登录".into()));
            }
            if Timestamp::now().unix_secs() - record.created_at > 600 {
                return Err(DomainError::PreconditionFailed("绑定已过期，请重新生成二维码".into()));
            }
            let secret = decrypt(&cipher, principal.identity_tenant, user.id, record)?;
            if !service.verify(&user.username, &secret, &body.code)? {
                return Err(DomainError::Validation("验证码错误".into()));
            }
            let (plain, hashes) = service.generate_recovery_codes(10, &user.id.to_string());
            record.confirmed = true;
            record.confirmed_at = confirmed_at;
            record.recovery_hashes = hashes;
            recovery = plain;
            Ok(())
        })
        .await?;
    user.mfa_enabled = true;
    user.mfa_secret_ref = Some(user.id);
    user.updated_at = Timestamp::now();
    if let Err(error) = state.auth_backend.save_user(&user, None).await {
        // Offline mode uses two in-memory stores. A concurrent login can advance
        // the account version; release this enrollment so the user can retry.
        state
            .configurations
            .mutate::<Enrollment, _>(principal.identity_tenant, KIND, user.id, |record| {
                if record.confirmed && record.confirmed_at == confirmed_at {
                    record.confirmed = false;
                    record.recovery_hashes.clear();
                }
                Ok(())
            })
            .await?;
        return Err(error.into());
    }
    audit(&state, &principal, "开启 TOTP MFA").await?;
    Ok(Json(json!({"enabled":true,"recovery_codes":recovery,"message":"恢复码只显示一次，请保存后重新登录"})))
}

async fn disable(
    State(state): State<AppState>,
    principal: Principal,
    ApiJson(body): ApiJson<PasswordBody>,
) -> ApiResult<Json<Value>> {
    let mut user = current(&state, &principal).await?;
    if state.auth_backend.mfa_required(principal.identity_tenant).await? {
        return Err(DomainError::Forbidden("租户强制 MFA，不能关闭；更换设备请联系管理员调整策略".into()).into());
    }
    reauthenticate(&state, &principal, &user, &body.current_password).await?;
    if let Some(db) = state.store.database() {
        let cipher = crate::model_gateway::cipher(&state)?;
        crate::mfa_store::disable_sql(db, &cipher, principal.identity_tenant, &user, body.code.as_deref()).await?;
        audit(&state, &principal, "关闭 TOTP MFA").await?;
        return Ok(Json(json!({"enabled":false})));
    }
    if !state.auth_backend.verify_mfa(principal.identity_tenant, &user, body.code.as_deref()).await? {
        return Err(DomainError::Unauthenticated("验证码或恢复码错误，已使用的码不可重用".into()).into());
    }
    user.mfa_enabled = false;
    user.mfa_secret_ref = None;
    user.updated_at = Timestamp::now();
    state.auth_backend.save_user(&user, None).await?;
    // 保留撤销时刻，避免关闭 MFA 后旧会话重新生效。
    state
        .configurations
        .put(
            principal.identity_tenant,
            KIND,
            user.id,
            &Enrollment { confirmed_at: Timestamp::now().unix_millis(), ..Enrollment::default() },
        )
        .await?;
    audit(&state, &principal, "关闭 TOTP MFA").await?;
    Ok(Json(json!({"enabled":false})))
}

async fn audit(state: &AppState, principal: &Principal, note: &str) -> ApiResult<()> {
    state
        .audit(
            principal.identity_tenant,
            agf_core::audit::AuditAction::Configure,
            agf_core::audit::AuditOutcome::Success,
            AppState::audit_actor(principal, "mfa"),
            agf_core::audit::AuditTarget::new("user", principal.subject_id.map(|id| id.to_string()), None),
            note,
        )
        .await?;
    Ok(())
}
