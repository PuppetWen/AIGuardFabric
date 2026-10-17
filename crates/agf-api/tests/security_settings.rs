//! 设置必须改变认证/配额行为，且绑定用途 JWT 不能绕过 MFA。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;

async fn enable_mfa(h: &Harness, token: &str, password: &str, username: &str) -> Vec<String> {
    let setup =
        h.request("POST", "/api/v1/auth/mfa/setup", Some(token), Some(json!({"current_password":password}))).await;
    assert_eq!(setup.status, StatusCode::OK, "{}", setup.text);
    let secret = setup.json()["secret"].as_str().unwrap().to_string();
    let code = agf_auth::mfa::TotpService::default().current_code(username, &secret).unwrap();
    let confirmed = h.request("POST", "/api/v1/auth/mfa/confirm", Some(token), Some(json!({"code":code}))).await;
    assert_eq!(confirmed.status, StatusCode::OK, "{}", confirmed.text);
    confirmed.json()["recovery_codes"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect()
}

#[tokio::test]
async fn encrypted_mfa_recovery_codes_and_mandatory_enrollment_work() {
    let h = setup().await;
    let recovery = enable_mfa(&h, &h.admin, ADMIN_PWD, "admin").await;
    assert_eq!(recovery.len(), 10);
    let admin = h.state.auth_backend.find_user_with_secret(h.tenant, "admin").await.unwrap().unwrap().user;
    let stored: Value = h.state.configurations.get(h.tenant, "mfa-enrollment", admin.id).await.unwrap().unwrap();
    assert!(stored["secret"].is_object());
    assert!(!stored.to_string().contains(&recovery[0]));
    let login = h
        .request(
            "POST",
            "/api/v1/auth/login",
            None,
            Some(json!({"username":"admin","password":ADMIN_PWD,"mfa_code":recovery[0]})),
        )
        .await;
    assert_eq!(login.status, StatusCode::OK, "{}", login.text);
    let replay = h
        .request(
            "POST",
            "/api/v1/auth/login",
            None,
            Some(json!({"username":"admin","password":ADMIN_PWD,"mfa_code":recovery[0]})),
        )
        .await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED, "{}", replay.text);
    let token = login.json()["tokens"]["access_token"].as_str().unwrap().to_string();
    let mut policy = h.request("GET", "/api/v1/settings/password-policy", Some(&token), None).await.json();
    policy["mfa_enforced"] = json!(true);
    let saved = h.request("PUT", "/api/v1/settings/password-policy", Some(&token), Some(policy)).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let login =
        h.request("POST", "/api/v1/auth/login", None, Some(json!({"username":"viewer","password":VIEWER_PWD}))).await;
    assert_eq!(login.status, StatusCode::OK, "{}", login.text);
    assert_eq!(login.json()["mfa_enrollment_required"], true);
    let limited = login.json()["tokens"]["access_token"].as_str().unwrap().to_string();
    assert_eq!(h.request("GET", "/api/v1/assets", Some(&limited), None).await.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(h.request("GET", "/api/v1/auth/mfa", Some(&limited), None).await.status, StatusCode::OK);
    enable_mfa(&h, &limited, VIEWER_PWD, "viewer").await;
    // 完成绑定后，旧的受限令牌被撤销，不能升级为业务会话。
    assert_eq!(h.request("GET", "/api/v1/assets", Some(&limited), None).await.status, StatusCode::UNAUTHORIZED);
    let refresh = h
        .request(
            "POST",
            "/api/v1/auth/refresh",
            None,
            Some(json!({"refresh_token":login.json()["tokens"]["refresh_token"]})),
        )
        .await;
    assert_eq!(refresh.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn password_rules_history_and_used_change_token_are_enforced() {
    let h = setup().await;
    let mut policy = h.get("/api/v1/settings/password-policy").await.json();
    policy["max_age_days"] = json!(0);
    policy["min_length"] = json!(14);
    policy["require_symbol"] = json!(true);
    let saved = h.request("PUT", "/api/v1/settings/password-policy", Some(&h.admin), Some(policy)).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.json()["version"], 1);
    let mut stale_policy = saved.json();
    stale_policy["expected_version"] = json!(0);
    stale_policy["min_length"] = json!(8);
    let stale = h.request("PUT", "/api/v1/settings/password-policy", Some(&h.admin), Some(stale_policy)).await;
    assert_eq!(stale.status, StatusCode::CONFLICT, "{}", stale.text);
    assert_eq!(h.get("/api/v1/settings/password-policy").await.json()["min_length"], 14);
    let login =
        h.request("POST", "/api/v1/auth/login", None, Some(json!({"username":"newbie","password":NEWBIE_PWD}))).await;
    assert_eq!(login.json()["must_change_password"], true, "0 天不过期不能关闭首登改密");
    let token = login.json()["change_token"].as_str().unwrap().to_string();
    let weak = h
        .request(
            "POST",
            "/api/v1/auth/change-password",
            Some(&token),
            Some(json!({"new_password":"LongEnough12345678"})),
        )
        .await;
    assert_eq!(weak.status, StatusCode::BAD_REQUEST);
    let changed = h
        .request(
            "POST",
            "/api/v1/auth/change-password",
            Some(&token),
            Some(json!({"new_password":"New-Forest-Cedar-47!"})),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    let reused = h
        .request(
            "POST",
            "/api/v1/auth/change-password",
            Some(&token),
            Some(json!({"new_password":"Next-Forest-Cedar-48!"})),
        )
        .await;
    assert_eq!(reused.status, StatusCode::UNAUTHORIZED, "{}", reused.text);
    let auth = agf_api::auth_policy::service(&h.state, h.tenant).await.unwrap();
    let user = h.state.auth_backend.find_user_with_secret(h.tenant, "newbie").await.unwrap().unwrap().user;
    assert!(auth.change_password(&*h.state.auth_backend, h.tenant, user.id, "New-Forest-Cedar-47!").await.is_err());
}

#[tokio::test]
async fn saved_quotas_block_gateway_before_upstream_and_branding_round_trips() {
    let h = setup().await;
    let profile = h
        .request(
            "PUT",
            "/api/v1/settings/tenant",
            Some(&h.admin),
            Some(json!({
        "name":"Test company","plan":"enterprise","region":"local","whiteLabel":{
            "productName":"Governance","logoText":"GOV","primaryColor":"#123abc"}})),
        )
        .await;
    assert_eq!(profile.status, StatusCode::OK, "{}", profile.text);
    assert_eq!(profile.json()["version"], 1);
    let stale_profile = h
        .request(
            "PUT",
            "/api/v1/settings/tenant",
            Some(&h.admin),
            Some(json!({
                "expectedVersion":0,"name":"Wrong name","plan":"standard","region":"local",
                "whiteLabel":{"productName":"Wrong","logoText":"BAD","primaryColor":"#123abc"}
            })),
        )
        .await;
    assert_eq!(stale_profile.status, StatusCode::CONFLICT, "{}", stale_profile.text);
    assert_eq!(h.get("/api/v1/tenants").await.json()[0]["white_label"]["product_name"], "Governance");
    h.post(
        "/api/v1/gateway/endpoints",
        json!({"name":"mock","provider":"mock","model":"m","base_url":"http://mock.invalid"}),
    )
    .await;
    let saved = h
        .request(
            "PUT",
            "/api/v1/settings/quotas",
            Some(&h.admin),
            Some(json!({
        "tenantTokensPerDay":100,"agentTokensPerHour":0,"sessionTokensPerTurn":5,"maxConcurrentSessions":1})),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.json()["version"], 1);
    let stale = h
        .request(
            "PUT",
            "/api/v1/settings/quotas",
            Some(&h.admin),
            Some(json!({
                "expectedVersion":0,"tenantTokensPerDay":10000,"agentTokensPerHour":0,
                "sessionTokensPerTurn":100,"maxConcurrentSessions":3
            })),
        )
        .await;
    assert_eq!(stale.status, StatusCode::CONFLICT, "{}", stale.text);
    let response = h
        .post(
            "/api/v1/chat/completions",
            json!({"model":"auto","max_tokens":20,"messages":[{"role":"user","content":"hello"}]}),
        )
        .await;
    assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS, "{}", response.text);
    assert!(h.state.meter.recent(100).is_empty());
}

#[tokio::test]
async fn disabling_then_starting_mfa_again_never_revives_old_sessions() {
    let h = setup().await;
    let recovery = enable_mfa(&h, &h.admin, ADMIN_PWD, "admin").await;
    let login = h
        .request(
            "POST",
            "/api/v1/auth/login",
            None,
            Some(json!({"username":"admin","password":ADMIN_PWD,"mfa_code":recovery[0]})),
        )
        .await;
    let token = login.json()["tokens"]["access_token"].as_str().unwrap().to_string();
    let disabled = h
        .request(
            "POST",
            "/api/v1/auth/mfa/disable",
            Some(&token),
            Some(json!({"current_password":ADMIN_PWD,"code":recovery[1]})),
        )
        .await;
    assert_eq!(disabled.status, StatusCode::OK, "{}", disabled.text);
    let login =
        h.request("POST", "/api/v1/auth/login", None, Some(json!({"username":"admin","password":ADMIN_PWD}))).await;
    let fresh = login.json()["tokens"]["access_token"].as_str().unwrap().to_string();
    assert_eq!(
        h.request("POST", "/api/v1/auth/mfa/setup", Some(&fresh), Some(json!({"current_password":ADMIN_PWD})))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(h.request("GET", "/api/v1/assets", Some(&h.admin), None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(h.request("GET", "/api/v1/assets", Some(&token), None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(h.request("GET", "/api/v1/assets", Some(&fresh), None).await.status, StatusCode::OK);
}
