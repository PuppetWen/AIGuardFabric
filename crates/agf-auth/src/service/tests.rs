//! 由 `service.rs` 拆分：`SECRET`/`service` 等 17 项（纯搬移，逻辑不变）。

use crate::claims::TokenIssuer;
use agf_core::auth::PasswordPolicy;
use agf_core::error::DomainError;
use agf_core::ids::{Id, TenantId};
use agf_core::user::{User, UserState};

use super::*;

use crate::password::PasswordHasher;

pub(super) const SECRET: &str = "unit-test-secret-key-at-least-32-bytes-long";

pub(super) fn service() -> AuthService {
    let issuer = TokenIssuer::new(SECRET, "iss", "aud", 3600, 259_200);
    assert!(issuer.is_ok());
    AuthService::new(
        issuer.unwrap_or_else(|_| unreachable!()),
        PasswordPolicy {
            deny_list: vec![],
            min_length: 12,
            max_failures: 3,
            lockout_secs: 900,
            ..PasswordPolicy::default()
        },
        "test-salt",
    )
}

pub(super) fn backend_with_user(username: &str, password: &str, must_change: bool) -> (InMemoryAuthBackend, Id) {
    let backend = InMemoryAuthBackend::new();
    let hasher = PasswordHasher::new(PasswordPolicy { deny_list: vec![], min_length: 8, ..PasswordPolicy::default() });
    let mut user = User::new_local(TenantId::default_tenant(), username, format!("{username}@example.com"));
    user.must_change_password = must_change;
    let Ok(phc) = hasher.hash(password) else { unreachable!() };
    let id = user.id;
    assert!(backend.insert_user(user, Some(phc)).is_ok());
    assert!(backend.set_roles(id, vec!["soc-analyst".to_string()]).is_ok());
    (backend, id)
}

pub(super) fn request(username: &str, password: &str) -> LoginRequest {
    LoginRequest {
        username: username.to_string(),
        password: password.to_string(),
        mfa_code: None,
        source_ip: Some("10.0.0.9".to_string()),
        user_agent: Some("unit-test".to_string()),
        device: Some("cli".to_string()),
    }
}

#[tokio::test]
pub(super) async fn successful_login_returns_tokens() {
    let svc = service();
    let (backend, uid) = backend_with_user("alice", "Str0ng&Passw0rd!2026", false);
    let res = svc.login(&backend, TenantId::default_tenant(), &request("alice", "Str0ng&Passw0rd!2026")).await;
    assert!(res.is_ok(), "{:?}", res.err().map(|e| e.to_string()));
    let Ok(LoginOutcome::Success { tokens, user, .. }) = res else { panic!("应返回成功登录") };
    assert_eq!(user.id, uid);
    assert_eq!(tokens.token_type, "Bearer");
    assert!(svc.issuer().verify(&tokens.access_token).is_ok());
    assert_eq!(backend.last_attempt_success().ok().flatten(), Some(true));
    assert_eq!(backend.active_refresh_count().ok(), Some(1));
}

#[tokio::test]
pub(super) async fn wrong_password_counts_failure_and_locks() {
    let svc = service();
    let (backend, _) = backend_with_user("bob", "Str0ng&Passw0rd!2026", false);
    for _ in 0..3 {
        let res = svc.login(&backend, TenantId::default_tenant(), &request("bob", "wrong")).await;
        assert!(res.is_err());
    }
    // 第 3 次即达到阈值，账号锁定
    let res = svc.login(&backend, TenantId::default_tenant(), &request("bob", "Str0ng&Passw0rd!2026")).await;
    let msg = res.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(msg.contains("账号不可用") || msg.contains("锁定"), "锁定后应拒绝登录: {msg}");
}

#[tokio::test]
pub(super) async fn unknown_user_and_bad_password_are_indistinguishable() {
    let svc = service();
    let (backend, _) = backend_with_user("carol", "Str0ng&Passw0rd!2026", false);
    let e1 = svc
        .login(&backend, TenantId::default_tenant(), &request("nobody", "whatever"))
        .await
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    let e2 = svc
        .login(&backend, TenantId::default_tenant(), &request("carol", "wrong-password"))
        .await
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert_eq!(e1, e2, "不得通过错误信息区分账号是否存在");
    assert!(e1.contains("用户名或口令错误"));
}

#[tokio::test]
pub(super) async fn must_change_password_flow() {
    let svc = service();
    let (backend, uid) = backend_with_user("dave", "Str0ng&Passw0rd!2026", true);
    let res = svc.login(&backend, TenantId::default_tenant(), &request("dave", "Str0ng&Passw0rd!2026")).await;
    let Ok(LoginOutcome::MustChangePassword { change_token, .. }) = res else { panic!("应要求改密") };
    let claims = svc.issuer().verify(&change_token);
    assert!(claims.is_ok());
    assert!(claims.map(|c| c.must_change_password).unwrap_or(false));

    // 弱口令被拒
    assert!(svc.change_password(&backend, TenantId::default_tenant(), uid, "weak").await.is_err(), "弱口令应被拒绝");
    // 强口令成功
    assert!(svc.change_password(&backend, TenantId::default_tenant(), uid, "An0ther&Strong!Pass").await.is_ok());
    // 改密后可正常登录
    let res2 = svc.login(&backend, TenantId::default_tenant(), &request("dave", "An0ther&Strong!Pass")).await;
    assert!(matches!(res2, Ok(LoginOutcome::Success { .. })));
}

#[tokio::test]
pub(super) async fn refresh_rotates_token_and_revokes_old() {
    let svc = service();
    let (backend, _) = backend_with_user("erin", "Str0ng&Passw0rd!2026", false);
    let res = svc.login(&backend, TenantId::default_tenant(), &request("erin", "Str0ng&Passw0rd!2026")).await;
    let Ok(LoginOutcome::Success { tokens, .. }) = res else { panic!("登录失败") };
    let old_refresh = tokens.refresh_token.clone();

    let refreshed = svc.refresh(&backend, TenantId::default_tenant(), &old_refresh).await;
    assert!(refreshed.is_ok(), "{:?}", refreshed.err().map(|e| e.to_string()));
    // 旧刷新令牌已被吊销 → 再次使用必须失败
    let reuse = svc.refresh(&backend, TenantId::default_tenant(), &old_refresh).await;
    assert!(reuse.is_err(), "刷新令牌复用必须被拒绝（防重放）");
    assert_eq!(backend.active_refresh_count().ok(), Some(1));
}

#[tokio::test]
pub(super) async fn logout_revokes_refresh_token() {
    let svc = service();
    let (backend, _) = backend_with_user("frank", "Str0ng&Passw0rd!2026", false);
    let res = svc.login(&backend, TenantId::default_tenant(), &request("frank", "Str0ng&Passw0rd!2026")).await;
    let Ok(LoginOutcome::Success { tokens, .. }) = res else { panic!("登录失败") };
    assert!(svc.logout(&backend, TenantId::default_tenant(), &tokens.refresh_token).await.is_ok());
    assert_eq!(backend.active_refresh_count().ok(), Some(0));
    assert!(svc.refresh(&backend, TenantId::default_tenant(), &tokens.refresh_token).await.is_err());
}

#[tokio::test]
pub(super) async fn refresh_with_unknown_token_fails() {
    let svc = service();
    let backend = InMemoryAuthBackend::new();
    let res = svc.refresh(&backend, TenantId::default_tenant(), "not-a-real-token").await;
    assert!(res.is_err());
}

#[tokio::test]
pub(super) async fn mfa_required_and_validated() {
    let svc = service();
    let (backend, uid) = backend_with_user("grace", "Str0ng&Passw0rd!2026", false);
    // 开启 MFA
    let mut user =
        backend.find_user(TenantId::default_tenant(), uid).await.unwrap_or(None).unwrap_or_else(|| unreachable!());
    user.mfa_enabled = true;
    assert!(backend.save_user(&user, None).await.is_ok());
    assert!(backend.set_mfa_code(uid, "123456").is_ok());

    // 不提供验证码 → 失败
    let res = svc.login(&backend, TenantId::default_tenant(), &request("grace", "Str0ng&Passw0rd!2026")).await;
    assert!(res.is_err());

    // 提供错误验证码 → 失败
    let mut bad = request("grace", "Str0ng&Passw0rd!2026");
    bad.mfa_code = Some("000000".to_string());
    assert!(svc.login(&backend, TenantId::default_tenant(), &bad).await.is_err());

    // 正确验证码 → 成功
    let mut good = request("grace", "Str0ng&Passw0rd!2026");
    good.mfa_code = Some("123456".to_string());
    assert!(matches!(svc.login(&backend, TenantId::default_tenant(), &good).await, Ok(LoginOutcome::Success { .. })));
}

#[tokio::test]
pub(super) async fn disabled_account_rejected() {
    let svc = service();
    let (backend, uid) = backend_with_user("heidi", "Str0ng&Passw0rd!2026", false);
    let mut user =
        backend.find_user(TenantId::default_tenant(), uid).await.unwrap_or(None).unwrap_or_else(|| unreachable!());
    user.state = UserState::Disabled;
    assert!(backend.save_user(&user, None).await.is_ok());
    let res = svc.login(&backend, TenantId::default_tenant(), &request("heidi", "Str0ng&Passw0rd!2026")).await;
    assert!(res.is_err());
}

#[test]
pub(super) fn public_message_does_not_leak_existence() {
    assert_eq!(AuthError::InvalidCredentials.public_message(), AuthError::NotFound.public_message());
    assert!(AuthError::Locked { remaining_secs: 120 }.public_message().contains("分钟"));
}

#[test]
pub(super) fn auth_error_to_domain_error_mapping() {
    let e: DomainError = AuthError::PasswordChangeRequired.into();
    assert!(matches!(e, DomainError::PreconditionFailed(_)));
    let e2: DomainError = AuthError::WeakPassword("太短".into()).into();
    assert!(matches!(e2, DomainError::Validation(_)));
    let e3: DomainError = AuthError::Locked { remaining_secs: 1 }.into();
    assert!(matches!(e3, DomainError::Forbidden(_)));
}

#[tokio::test]
pub(super) async fn attempts_are_audited() {
    let svc = service();
    let (backend, _) = backend_with_user("ivan", "Str0ng&Passw0rd!2026", false);
    assert_eq!(backend.attempt_count().ok(), Some(0));
    let _ = svc.login(&backend, TenantId::default_tenant(), &request("ivan", "bad")).await;
    let _ = svc.login(&backend, TenantId::default_tenant(), &request("ivan", "Str0ng&Passw0rd!2026")).await;
    assert_eq!(backend.attempt_count().ok(), Some(2));
}

#[test]
pub(super) fn service_debug_hides_issuer_secret() {
    let svc = service();
    let dbg = format!("{svc:?}");
    assert!(dbg.contains("redacted"));
    assert!(!dbg.contains(SECRET));
}
