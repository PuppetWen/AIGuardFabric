//! 租户管理与登录/切换不能只更新控制台显示。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;

#[tokio::test]
async fn tenant_creation_login_switch_and_disable_are_enforced() {
    let h = setup().await;
    let create = h.post("/api/v1/tenants", json!({"slug":"enterprise-a","name":"企业 A"})).await;
    assert_eq!(create.status, StatusCode::CREATED, "{}", create.text);
    assert_eq!(create.json()["version"], 1);
    let id = create.json()["id"].as_str().unwrap().to_owned();
    let directory = h.request("GET", "/api/v1/tenants", Some(&h.admin), None).await;
    let row = directory.json().as_array().unwrap().iter().find(|row| row["id"] == id).unwrap().clone();
    assert_eq!(row["version"], 0, "企业资料版本与租户目录版本互不相同");
    assert_eq!(row["directory_version"], 1);
    assert_eq!(row["directory_name"], "企业 A");
    let headers = [("Authorization", format!("Bearer {}", h.admin)), ("X-AGF-Tenant", id.clone())];
    let pairs: Vec<_> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let created = h
        .request_with(
            "POST",
            "/api/v1/users",
            &pairs,
            Some(json!({
        "username":"manager","email":"manager@example.test","password":NEWBIE_PWD,"role":"admin"})),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let first = h
        .post("/api/v1/auth/login", json!({"tenant_slug":"enterprise-a","username":"manager","password":NEWBIE_PWD}))
        .await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    assert_eq!(first.json()["user"]["tenant_id"], id);
    let change = first.json()["change_token"].as_str().unwrap().to_owned();
    let changed =
        h.request("POST", "/api/v1/auth/change-password", Some(&change), Some(json!({"new_password":ADMIN_PWD}))).await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    let login = h
        .post("/api/v1/auth/login", json!({"tenant_slug":"enterprise-a","username":"manager","password":ADMIN_PWD}))
        .await;
    let token = login.json()["tokens"]["access_token"].as_str().unwrap().to_owned();
    let tenants = h.request("GET", "/api/v1/tenants", Some(&token), None).await;
    assert_eq!(tenants.json().as_array().unwrap().len(), 1);
    assert_eq!(tenants.json()[0]["slug"], "enterprise-a");
    let forbidden = h
        .request_with(
            "GET",
            "/api/v1/assets",
            &[("Authorization", &format!("Bearer {token}")), ("X-AGF-Tenant", &h.tenant.to_string())],
            None,
        )
        .await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);
    let denied =
        h.request("POST", "/api/v1/tenants", Some(&token), Some(json!({"slug":"attack","name":"invalid"}))).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    let disabled = h
        .request(
            "PATCH",
            &format!("/api/v1/tenants/{id}"),
            Some(&h.admin),
            Some(json!({"name":"企业 A","enabled":false,"expected_version":1})),
        )
        .await;
    assert_eq!(disabled.status, StatusCode::OK, "{}", disabled.text);
    assert_eq!(disabled.json()["version"], 2);
    let directory = h.request("GET", "/api/v1/tenants", Some(&h.admin), None).await;
    let row = directory.json().as_array().unwrap().iter().find(|row| row["id"] == id).unwrap().clone();
    assert_eq!(row["directory_version"], 2);
    assert_eq!(
        h.request(
            "PATCH",
            &format!("/api/v1/tenants/{id}"),
            Some(&h.admin),
            Some(json!({"name":"stale","enabled":true,"expected_version":1}))
        )
        .await
        .status,
        StatusCode::CONFLICT
    );
    assert_eq!(h.request("GET", "/api/v1/assets", Some(&token), None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(
        h.post("/api/v1/auth/login", json!({"tenant_slug":"enterprise-a","username":"manager","password":ADMIN_PWD}))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn duplicate_unknown_and_default_tenant_guards_work() {
    let h = setup().await;
    assert_eq!(
        h.post("/api/v1/tenants", json!({"slug":"default","name":"duplicate"})).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        h.request(
            "PATCH",
            &format!("/api/v1/tenants/{}", h.tenant),
            Some(&h.admin),
            Some(json!({"name":"default","enabled":false,"expected_version":1}))
        )
        .await
        .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        h.post("/api/v1/auth/login", json!({"tenant_slug":"missing","username":"admin","password":ADMIN_PWD}))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}
