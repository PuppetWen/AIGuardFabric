//! 认证状态机、授权与租户隔离、problem+json 错误契约。
//! 覆盖登录 / 锁定 / 首登改密 / 刷新 / 登出、401/403/跨租户、400/404 错误形状。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

mod common;

use common::*;

#[tokio::test]
async fn refresh_cannot_restore_a_session_revoked_by_password_change() {
    let h = setup().await;
    let login = h
        .request("POST", "/api/v1/auth/login", None, Some(json!({"username":"admin","password":ADMIN_PWD})))
        .await
        .json();
    let token = login["tokens"]["access_token"].as_str().unwrap();
    let changed = h
        .request(
            "POST",
            "/api/v1/auth/change-password",
            Some(token),
            Some(json!({"current_password":ADMIN_PWD,"new_password":"New-Forest-Cedar-47!"})),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    let refreshed = h
        .request("POST", "/api/v1/auth/refresh", None, Some(json!({"refresh_token":login["tokens"]["refresh_token"]})))
        .await;
    assert_eq!(refreshed.status, StatusCode::UNAUTHORIZED, "{}", refreshed.text);
}

// ===========================================================================
// 2. 认证状态机
// ===========================================================================

#[tokio::test]
async fn login_success_returns_token_pair_and_user() {
    let h = setup().await;
    let resp =
        h.request("POST", "/api/v1/auth/login", None, Some(json!({"username": "admin", "password": ADMIN_PWD}))).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    assert_eq!(body["must_change_password"], false);
    assert_eq!(body["tokens"]["token_type"], "Bearer");
    assert!(body["tokens"]["access_token"].as_str().is_some_and(|t| !t.is_empty()));
    assert_eq!(body["user"]["username"], "admin");
    assert!(body["password_policy"]["min_length"].as_u64().is_some_and(|n| n >= 8));
}

#[tokio::test]
async fn login_wrong_password_is_401_and_does_not_leak_account_existence() {
    let h = setup().await;
    let known = h
        .request("POST", "/api/v1/auth/login", None, Some(json!({"username": "admin", "password": "wrong-password"})))
        .await;
    let unknown = h
        .request("POST", "/api/v1/auth/login", None, Some(json!({"username": "ghost", "password": "wrong-password"})))
        .await;
    assert_eq!(known.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED);
    assert_eq!(known.json()["detail"], unknown.json()["detail"]);
    assert_eq!(known.code(), "unauthenticated");
}

#[tokio::test]
async fn login_locks_account_after_threshold_failures() {
    let h = setup().await;
    for _ in 0..3 {
        let _ = h
            .request("POST", "/api/v1/auth/login", None, Some(json!({"username": "admin", "password": "nope-nope"})))
            .await;
    }
    let locked =
        h.request("POST", "/api/v1/auth/login", None, Some(json!({"username": "admin", "password": ADMIN_PWD}))).await;
    assert_eq!(locked.status, StatusCode::FORBIDDEN, "锁定后必须拒绝: {}", locked.text);
}

#[tokio::test]
async fn first_login_forces_password_change_without_usable_token() {
    let h = setup().await;
    let resp = h
        .request("POST", "/api/v1/auth/login", None, Some(json!({"username": "newbie", "password": NEWBIE_PWD})))
        .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
    let body = resp.json();
    assert_eq!(body["must_change_password"], true);
    assert!(body["password_policy"]["min_length"].as_u64().is_some_and(|n| n >= 8));
    assert!(body.get("tokens").is_none(), "首登不得签发可用令牌: {body}");
    assert!(body["change_token"].as_str().is_some_and(|t| !t.is_empty()));
}

#[tokio::test]
async fn first_login_flow_change_password_then_login_succeeds() {
    let h = setup().await;
    let login = h
        .request("POST", "/api/v1/auth/login", None, Some(json!({"username": "newbie", "password": NEWBIE_PWD})))
        .await
        .json();
    let change_token = login["change_token"].as_str().unwrap_or_default().to_string();

    // 未改密前访问资源接口 → 412（前置条件不满足）
    let blocked = h.request("GET", "/api/v1/assets", Some(&change_token), None).await;
    assert_eq!(blocked.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(blocked.code(), "precondition_failed");

    // 弱口令被拒
    let weak = h
        .request("POST", "/api/v1/auth/change-password", Some(&change_token), Some(json!({"new_password": "weak"})))
        .await;
    assert_eq!(weak.status, StatusCode::BAD_REQUEST);

    // 强口令成功
    let changed = h
        .request(
            "POST",
            "/api/v1/auth/change-password",
            Some(&change_token),
            Some(json!({"new_password": "Yq8!vBn3@Zx5#Kd7"})),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);

    // 新口令可登录
    let again = h
        .request(
            "POST",
            "/api/v1/auth/login",
            None,
            Some(json!({"username": "newbie", "password": "Yq8!vBn3@Zx5#Kd7"})),
        )
        .await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(again.json()["must_change_password"], false);
}

#[tokio::test]
async fn missing_token_is_401_problem_json() {
    let h = setup().await;
    let resp = h.request("GET", "/api/v1/assets", None, None).await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    assert!(resp.content_type().starts_with("application/problem+json"));
    assert_eq!(resp.code(), "unauthenticated");
}

#[tokio::test]
async fn api_key_authentication_grants_declared_scopes_only() {
    let h = setup().await;
    let ok = h.request_with("GET", "/api/v1/assets", &[("x-agf-key", h.api_key.as_str())], None).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text);
    let denied = h.request_with("GET", "/api/v1/policies", &[("x-agf-key", h.api_key.as_str())], None).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN, "API Key 越权必须 403: {}", denied.text);
}

#[tokio::test]
async fn invalid_api_key_is_401() {
    let h = setup().await;
    let resp =
        h.request_with("GET", "/api/v1/assets", &[("x-agf-key", "agf_live_totallyboguskeyvalue1234")], None).await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_rotates_token_and_rejects_reuse() {
    let h = setup().await;
    let login = h
        .request("POST", "/api/v1/auth/login", None, Some(json!({"username": "admin", "password": ADMIN_PWD})))
        .await
        .json();
    let refresh = login["tokens"]["refresh_token"].as_str().unwrap_or_default().to_string();
    let first = h.post("/api/v1/auth/refresh", json!({"refresh_token": refresh})).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    let second = h.post("/api/v1/auth/refresh", json!({"refresh_token": refresh})).await;
    assert_eq!(second.status, StatusCode::UNAUTHORIZED, "刷新令牌复用必须被拒绝");
}

#[tokio::test]
async fn logout_revokes_refresh_token() {
    let h = setup().await;
    let login = h
        .request("POST", "/api/v1/auth/login", None, Some(json!({"username": "admin", "password": ADMIN_PWD})))
        .await
        .json();
    let refresh = login["tokens"]["refresh_token"].as_str().unwrap_or_default().to_string();
    let logout = h.post("/api/v1/auth/logout", json!({"refresh_token": refresh})).await;
    assert_eq!(logout.status, StatusCode::OK, "{}", logout.text);
    let reuse = h.post("/api/v1/auth/refresh", json!({"refresh_token": refresh})).await;
    assert_eq!(reuse.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn me_returns_permissions_and_identity() {
    let h = setup().await;
    let resp = h.get("/api/v1/auth/me").await;
    assert_eq!(resp.status, StatusCode::OK);
    let body = resp.json();
    assert_eq!(body["superadmin"], true);
    assert_eq!(body["read_only"], false);
    assert_eq!(body["subject_kind"], "user");
    assert!(body["permissions"].as_array().is_some_and(|p| !p.is_empty()));
    assert_eq!(body["user"]["username"], "admin");
}

// ===========================================================================
// 3. 授权与租户隔离
// ===========================================================================

#[tokio::test]
async fn viewer_write_is_forbidden() {
    let h = setup().await;
    let resp = h.request("GET", "/api/v1/assets", Some(&h.viewer), None).await;
    assert_eq!(resp.status, StatusCode::OK, "viewer 应可读: {}", resp.text);
    let write = h.request("POST", "/api/v1/assets/discovery", Some(&h.viewer), Some(json!({"assets": []}))).await;
    assert_eq!(write.status, StatusCode::FORBIDDEN);
    assert_eq!(write.code(), "forbidden");
}

#[tokio::test]
async fn cross_tenant_access_is_403_tenant_violation() {
    let h = setup().await;
    let resp = h
        .request_with(
            "GET",
            "/api/v1/assets",
            &[("authorization", &format!("Bearer {}", h.viewer)), ("x-agf-tenant", &h.other_tenant.to_string())],
            None,
        )
        .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.text);
    assert_eq!(resp.code(), "tenant_violation");
}

#[tokio::test]
async fn superadmin_can_switch_tenant() {
    let h = setup().await;
    let resp = h
        .request_with(
            "GET",
            "/api/v1/assets",
            &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &h.other_tenant.to_string())],
            None,
        )
        .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.text);
}

#[tokio::test]
async fn tampered_token_is_401() {
    let h = setup().await;
    let resp = h.request("GET", "/api/v1/assets", Some("not.a.jwt"), None).await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
}

// ===========================================================================
// 4. problem+json
// ===========================================================================

#[tokio::test]
async fn unknown_route_returns_problem_json_404() {
    let h = setup().await;
    let resp = h.get("/api/v1/does-not-exist").await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
    assert!(resp.content_type().starts_with("application/problem+json"));
    let body = resp.json();
    for field in ["type", "title", "status", "detail", "code"] {
        assert!(body.get(field).is_some(), "problem+json 缺少字段 {field}: {body}");
    }
    assert_eq!(body["status"], 404);
    assert_eq!(body["code"], "not_found");
    assert!(body["type"].as_str().unwrap_or_default().starts_with("https://"));
}

#[tokio::test]
async fn invalid_body_returns_problem_json_400() {
    let h = setup().await;
    let resp = h.post("/api/v1/auth/login", json!({"username": 42})).await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    assert!(resp.content_type().starts_with("application/problem+json"));
    assert_eq!(resp.code(), "validation_failed");
}

#[tokio::test]
async fn invalid_path_id_returns_problem_json_400() {
    let h = setup().await;
    let resp = h.get("/api/v1/assets/not-a-uuid").await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    assert_eq!(resp.code(), "validation_failed");
}

#[tokio::test]
async fn missing_resource_returns_404() {
    let h = setup().await;
    let resp = h.get("/api/v1/assets/018f0a1e-0000-7000-8000-000000000000").await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND);
    assert_eq!(resp.code(), "not_found");
}
