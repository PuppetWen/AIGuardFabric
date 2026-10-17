//! 工作租户切换不应改变账号归属或把个人安全配置写到别的组织。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;

async fn workspace(h: &Harness) -> String {
    let response = h.post("/api/v1/tenants", json!({"slug":"workspace-b","name":"Workspace B"})).await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
    response.json()["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn switched_superadmin_keeps_personal_profile_and_mfa_in_identity_tenant() {
    let h = setup().await;
    let other = workspace(&h).await;
    let bearer = format!("Bearer {}", h.admin);
    let headers = [("Authorization", bearer.as_str()), ("X-AGF-Tenant", other.as_str())];
    let me = h.request_with("GET", "/api/v1/auth/me", &headers, None).await;
    assert_eq!(me.status, StatusCode::OK, "{}", me.text);
    assert_eq!(me.json()["tenant_id"], other);
    assert_eq!(me.json()["identity_tenant_id"], h.tenant.to_string());
    assert_eq!(me.json()["user"]["username"], "admin");
    assert_eq!(me.json()["user"]["tenant_id"], h.tenant.to_string());
    let status = h.request_with("GET", "/api/v1/auth/mfa", &headers, None).await;
    assert_eq!(status.status, StatusCode::OK, "{}", status.text);
    let enrollment =
        h.request_with("POST", "/api/v1/auth/mfa/setup", &headers, Some(json!({"current_password":ADMIN_PWD}))).await;
    assert_eq!(enrollment.status, StatusCode::OK, "{}", enrollment.text);
    let secret = enrollment.json()["secret"].as_str().unwrap().to_owned();
    let code = agf_auth::mfa::TotpService::default().current_code("admin", &secret).unwrap();
    let confirmed = h.request_with("POST", "/api/v1/auth/mfa/confirm", &headers, Some(json!({"code":code}))).await;
    assert_eq!(confirmed.status, StatusCode::OK, "{}", confirmed.text);
    let user = h.state.auth_backend.find_user_with_secret(h.tenant, "admin").await.unwrap().unwrap().user;
    assert!(user.mfa_enabled);
    assert!(h.state.configurations.get::<Value>(h.tenant, "mfa-enrollment", user.id).await.unwrap().is_some());
    assert!(
        h.state
            .configurations
            .get::<Value>(TenantId::parse(&other).unwrap(), "mfa-enrollment", user.id)
            .await
            .unwrap()
            .is_none()
    );
    let logged_in = h
        .request(
            "POST",
            "/api/v1/auth/login",
            None,
            Some(json!({
                "username":"admin","password":ADMIN_PWD,"mfa_code":confirmed.json()["recovery_codes"][0]
            })),
        )
        .await;
    assert_eq!(logged_in.status, StatusCode::OK, "{}", logged_in.text);
}

#[tokio::test]
async fn switched_superadmin_can_change_own_password() {
    let h = setup().await;
    let other = workspace(&h).await;
    let bearer = format!("Bearer {}", h.admin);
    let changed = h
        .request_with(
            "POST",
            "/api/v1/auth/change-password",
            &[("Authorization", &bearer), ("X-AGF-Tenant", &other)],
            Some(json!({"current_password":ADMIN_PWD,"new_password":"New-Identity-Forest-47!"})),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    let old =
        h.request("POST", "/api/v1/auth/login", None, Some(json!({"username":"admin","password":ADMIN_PWD}))).await;
    assert_eq!(old.status, StatusCode::UNAUTHORIZED);
    let new = h
        .request(
            "POST",
            "/api/v1/auth/login",
            None,
            Some(json!({"username":"admin","password":"New-Identity-Forest-47!"})),
        )
        .await;
    assert_eq!(new.status, StatusCode::OK, "{}", new.text);
    assert_eq!(new.json()["user"]["tenant_id"], h.tenant.to_string());
}

#[tokio::test]
async fn logout_after_switch_revokes_refresh_in_identity_tenant() {
    let h = setup().await;
    let other = workspace(&h).await;
    let login = h
        .request("POST", "/api/v1/auth/login", None, Some(json!({"username":"admin","password":ADMIN_PWD})))
        .await
        .json();
    let bearer = format!("Bearer {}", login["tokens"]["access_token"].as_str().unwrap());
    let body = json!({"refresh_token":login["tokens"]["refresh_token"]});
    let logout = h
        .request_with(
            "POST",
            "/api/v1/auth/logout",
            &[("Authorization", &bearer), ("X-AGF-Tenant", &other)],
            Some(body.clone()),
        )
        .await;
    assert_eq!(logout.status, StatusCode::OK, "{}", logout.text);
    let refresh = h.request("POST", "/api/v1/auth/refresh", None, Some(body)).await;
    assert_eq!(refresh.status, StatusCode::UNAUTHORIZED, "{}", refresh.text);
}
