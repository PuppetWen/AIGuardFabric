//! 账号管理必须真实生效；凭据创建/吊销、降权、停用、跨租户及 MFA 回归。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_auth::service::{AuthBackend, InMemoryAuthBackend};
use agf_core::ids::Id;
use common::*;

#[tokio::test]
async fn created_account_can_change_password_and_login() {
    let h = setup().await;
    let body = json!({"username":"operator","email":"operator@example.test",
        "display_name":"运营测试","password":"Initial-Complex-493!","role":"analyst"});
    let created = h.post("/api/v1/users", body.clone()).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    assert_eq!(created.json()["role"], "analyst");
    assert_eq!(created.json()["version"], 1);
    let roster = h.get("/api/v1/users").await;
    assert!(roster.json().as_array().unwrap().iter().any(|u| u["username"] == "operator"));
    assert!(!roster.text.contains("password_hash"));
    assert_eq!(h.post("/api/v1/users", body).await.status, StatusCode::CONFLICT);
    let login = h
        .request(
            "POST",
            "/api/v1/auth/login",
            None,
            Some(json!({"username":"operator","password":"Initial-Complex-493!"})),
        )
        .await;
    assert_eq!(login.json()["must_change_password"], true);
    let changed = h
        .request(
            "POST",
            "/api/v1/auth/change-password",
            login.json()["change_token"].as_str(),
            Some(json!({"old_password":"Initial-Complex-493!","new_password":"Updated-Complex-594!"})),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    let login = h
        .request(
            "POST",
            "/api/v1/auth/login",
            None,
            Some(json!({"username":"operator","password":"Updated-Complex-594!"})),
        )
        .await;
    assert!(login.json()["tokens"]["access_token"].is_string(), "{}", login.text);
}

#[tokio::test]
async fn role_and_state_changes_apply_to_existing_jwt() {
    let h = setup().await;
    let user = h.state.auth_backend.find_user_with_secret(h.tenant, "viewer").await.unwrap().unwrap().user;
    let path = format!("/api/v1/users/{}", user.id);
    let mut version = user.version;
    assert_eq!(
        h.request("PATCH", &path, Some(&h.viewer), Some(json!({"role":"admin","expected_version":version})))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let updated =
        h.request("PATCH", &path, Some(&h.admin), Some(json!({"role":"admin","expected_version":version}))).await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.text);
    version = updated.json()["version"].as_u64().unwrap();
    assert_eq!(h.request("GET", "/api/v1/users", Some(&h.viewer), None).await.status, StatusCode::OK);
    let updated =
        h.request("PATCH", &path, Some(&h.admin), Some(json!({"role":"viewer","expected_version":version}))).await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.text);
    version = updated.json()["version"].as_u64().unwrap();
    assert_eq!(h.request("GET", "/api/v1/users", Some(&h.viewer), None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(
        h.request("PATCH", &path, Some(&h.admin), Some(json!({"status":"disabled","expected_version":version})))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(h.request("GET", "/api/v1/assets", Some(&h.viewer), None).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn stale_account_edit_cannot_restore_a_disabled_user_or_old_role() {
    let h = setup().await;
    let original = h.state.auth_backend.find_user_with_secret(h.tenant, "viewer").await.unwrap().unwrap().user;
    let path = format!("/api/v1/users/{}", original.id);
    assert_eq!(
        h.request("PATCH", &path, Some(&h.admin), Some(json!({"role":"admin"}))).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        h.request("PATCH", &path, Some(&h.admin), Some(json!({"expected_version":original.version}))).await.status,
        StatusCode::BAD_REQUEST
    );
    let changed = h
        .request(
            "PATCH",
            &path,
            Some(&h.admin),
            Some(json!({
                "role":"auditor","status":"disabled","expected_version":original.version
            })),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    assert_eq!(changed.json()["version"], original.version + 1);
    let stale = h
        .request(
            "PATCH",
            &path,
            Some(&h.admin),
            Some(json!({
                "role":"admin","status":"active","expected_version":original.version
            })),
        )
        .await;
    assert_eq!(stale.status, StatusCode::CONFLICT, "{}", stale.text);
    assert_eq!(h.state.auth_backend.save_user(&original, None).await.unwrap_err().status_code(), 409);
    let saved = h.state.auth_backend.find_user(h.tenant, original.id).await.unwrap().unwrap();
    assert_eq!(saved.state, agf_core::user::UserState::Disabled);
    assert_eq!(h.state.auth_backend.roles_of(h.tenant, original.id).await.unwrap(), vec!["auditor"]);
    assert_eq!(h.request("GET", "/api/v1/assets", Some(&h.viewer), None).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn issued_key_authenticates_and_revocation_removes_access() {
    let h = setup().await;
    let created = h
        .post("/api/v1/settings/api-keys", json!({"name":"collector","scopes":["assets:read"],"expires_in_secs":86400}))
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let value = created.json();
    let plaintext = value["plaintext"].as_str().unwrap();
    let headers = [("X-AGF-Key", plaintext)];
    assert_eq!(h.request_with("GET", "/api/v1/assets", &headers, None).await.status, StatusCode::OK);
    assert!(!h.get("/api/v1/api-keys").await.text.contains(plaintext));
    let path = format!("/api/v1/settings/api-keys/{}", value["api_key"]["id"].as_str().unwrap());
    let deleted = h.request("DELETE", &path, Some(&h.admin), None).await;
    assert_eq!(deleted.status, StatusCode::OK, "{}", deleted.text);
    assert_eq!(h.request_with("GET", "/api/v1/assets", &headers, None).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn memory_backend_isolates_users_roles_tokens_and_fails_closed_for_mfa() {
    use agf_core::user::{RefreshTokenRecord, User};
    let backend = InMemoryAuthBackend::new();
    let tenant = TenantId::new();
    let other = TenantId::new();
    let mut user = User::new_local(tenant, "isolation", "isolation@example.test");
    user.mfa_enabled = true;
    backend.save_account(&user, None, &["viewer".into()]).await.unwrap();
    assert!(backend.find_user(other, user.id).await.unwrap().is_none());
    assert!(backend.roles_of(other, user.id).await.unwrap().is_empty());
    assert!(!backend.verify_mfa(tenant, &user, Some("123456")).await.unwrap());
    assert!(!backend.verify_mfa(tenant, &user, None).await.unwrap());
    let token = RefreshTokenRecord {
        id: Id::new(),
        tenant_id: tenant,
        user_id: user.id,
        token_fingerprint: "unique-token".into(),
        expires_at: Timestamp::now().offset_secs(60),
        revoked: false,
        revoked_reason: None,
        device: None,
        created_at: Timestamp::now(),
    };
    backend.store_refresh(&token).await.unwrap();
    assert!(backend.find_refresh(other, "unique-token").await.unwrap().is_none());
    backend.revoke_refresh(other, token.id, "wrong tenant").await.unwrap();
    assert!(!backend.find_refresh(tenant, "unique-token").await.unwrap().unwrap().revoked);
}
