//! QR login requires a second authenticated device and fresh platform MFA.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::ids::Id;
use common::*;

const START: &str = "/api/v1/auth/qr/start";
const STATUS: &str = "/api/v1/auth/qr/status";
const COMPLETE: &str = "/api/v1/auth/qr/complete";

async fn start(h: &Harness) -> Value {
    let response = h.request("POST", START, None, Some(json!({"tenant_slug":"default"}))).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    response.json()
}

fn claim(started: &Value) -> Value {
    json!({"tenant_slug":"default","state":started["state"],"binding":started["binding"]})
}

fn preview(started: &Value) -> String {
    format!("/api/v1/auth/qr/default/{}/preview", started["state"].as_str().unwrap())
}

fn approve(started: &Value) -> String {
    format!("/api/v1/auth/qr/default/{}/approve", started["state"].as_str().unwrap())
}

async fn viewer_phone_with_mfa(h: &Harness) -> (String, Vec<String>) {
    let setup = h
        .request("POST", "/api/v1/auth/mfa/setup", Some(&h.viewer), Some(json!({"current_password":VIEWER_PWD})))
        .await;
    assert_eq!(setup.status, StatusCode::OK, "{}", setup.text);
    let secret = setup.json()["secret"].as_str().unwrap().to_string();
    let code = agf_auth::mfa::TotpService::default().current_code("viewer", &secret).unwrap();
    let confirmed = h.request("POST", "/api/v1/auth/mfa/confirm", Some(&h.viewer), Some(json!({"code":code}))).await;
    assert_eq!(confirmed.status, StatusCode::OK, "{}", confirmed.text);
    let recovery: Vec<String> = confirmed.json()["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_string())
        .collect();
    let login = h
        .request(
            "POST",
            "/api/v1/auth/login",
            None,
            Some(json!({"username":"viewer","password":VIEWER_PWD,"mfa_code":recovery[0]})),
        )
        .await;
    assert_eq!(login.status, StatusCode::OK, "{}", login.text);
    (login.json()["tokens"]["access_token"].as_str().unwrap().to_string(), recovery)
}

#[tokio::test]
async fn phone_mfa_approves_bound_browser_once() {
    let h = setup().await;
    let spec = h.request("GET", "/api/v1/openapi.json", Some(&h.admin), None).await;
    assert_eq!(spec.status, StatusCode::OK);
    let document = spec.json();
    for path in [
        START,
        STATUS,
        COMPLETE,
        "/api/v1/auth/qr/{tenant_slug}/{state}/approve",
        "/api/v1/auth/saml/{tenant_slug}/acs",
    ] {
        assert!(document["paths"].get(path).is_some(), "missing OpenAPI path {path}");
    }
    let started = start(&h).await;
    let mut wrong = claim(&started);
    wrong["binding"] = json!("x".repeat(64));
    assert_eq!(h.request("POST", STATUS, None, Some(wrong.clone())).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(h.request("GET", &preview(&started), None, None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        h.request("GET", &preview(&started), Some(&h.viewer), None).await.status,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(h.request("GET", &preview(&started), Some(&h.api_key), None).await.status, StatusCode::FORBIDDEN);
    let (phone, recovery) = viewer_phone_with_mfa(&h).await;
    let phone_preview = h.request("GET", &preview(&started), Some(&phone), None).await;
    assert_eq!(phone_preview.status, StatusCode::OK, "{}", phone_preview.text);
    assert_eq!(phone_preview.json()["status"], "pending");
    assert_eq!(
        h.request("POST", &approve(&started), Some(&phone), Some(json!({"mfa_code":"invalid"}))).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(h.request("POST", STATUS, None, Some(claim(&started))).await.json()["status"], "pending");
    let approved = h.request("POST", &approve(&started), Some(&phone), Some(json!({"mfa_code":recovery[1]}))).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.text);
    assert_eq!(h.request("POST", STATUS, None, Some(claim(&started))).await.json()["status"], "approved");
    assert_eq!(h.request("POST", COMPLETE, None, Some(wrong)).await.status, StatusCode::UNAUTHORIZED);
    let login = h.request("POST", COMPLETE, None, Some(claim(&started))).await;
    assert_eq!(login.status, StatusCode::OK, "{}", login.text);
    assert_eq!(login.json()["user"]["username"], "viewer");
    assert_eq!(login.json()["roles"], json!(["viewer"]));
    let session = login.json();
    let token = session["tokens"]["access_token"].as_str().unwrap();
    assert_eq!(h.request("GET", "/api/v1/assets", Some(token), None).await.status, StatusCode::OK);
    assert_eq!(h.request("POST", COMPLETE, None, Some(claim(&started))).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        h.request("POST", &approve(&started), Some(&phone), Some(json!({"mfa_code":recovery[2]}))).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn expired_or_disabled_approval_never_issues_session() {
    let h = setup().await;
    let expired = start(&h).await;
    let id = Id::parse(expired["state"].as_str().unwrap()).unwrap();
    let mut stored: Value = h.state.configurations.get(h.tenant, "qr-login-flow", id).await.unwrap().unwrap();
    stored["expires_at"] = json!(Timestamp::now().unix_secs() - 1);
    h.state.configurations.put(h.tenant, "qr-login-flow", id, &stored).await.unwrap();
    assert_eq!(h.request("POST", STATUS, None, Some(claim(&expired))).await.status, StatusCode::UNAUTHORIZED);
    let (phone, recovery) = viewer_phone_with_mfa(&h).await;
    let started = start(&h).await;
    assert_eq!(
        h.request("POST", &approve(&started), Some(&phone), Some(json!({"mfa_code":recovery[1]}))).await.status,
        StatusCode::OK
    );
    let mut viewer = h.state.auth_backend.find_user_with_secret(h.tenant, "viewer").await.unwrap().unwrap().user;
    viewer.state = agf_core::user::UserState::Disabled;
    h.state.auth_backend.save_user(&viewer, None).await.unwrap();
    assert_eq!(h.request("POST", COMPLETE, None, Some(claim(&started))).await.status, StatusCode::FORBIDDEN);
}
