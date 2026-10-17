//! OIDC end-to-end contracts against a local mock IdP with actual signed tokens.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]
mod common;
#[path = "common/oidc_provider.rs"]
mod provider;
use agf_core::{ids::Id, user::UserState};
use common::*;
const SETTINGS: &str = "/api/v1/settings/identity/oidc";
const START: &str = "/api/v1/auth/oidc/start";
const EXCHANGE: &str = "/api/v1/auth/oidc/exchange";
const COMPLETE: &str = "/api/v1/auth/oidc/complete";

async fn configure(h: &Harness, p: &provider::Provider) {
    let mut config = p.config();
    config["expected_revision"] = h.get(SETTINGS).await.json()["revision"].clone();
    let result = h.request("PUT", SETTINGS, Some(&h.admin), Some(config)).await;
    assert_eq!(result.status, StatusCode::OK, "{}", result.text);
    assert!(!result.text.contains("local-test-secret"));
    assert_eq!(result.json()["credential_configured"], true);
}
async fn begin(h: &Harness, p: &provider::Provider, overrides: Value) -> Value {
    let result = h.request("POST", START, None, Some(json!({"tenant_slug":"default"}))).await;
    assert_eq!(result.status, StatusCode::OK, "{}", result.text);
    p.authorize(&result.json(), overrides)
}
async fn finish(h: &Harness, body: Value) -> Resp {
    let exchanged = h.request("POST", EXCHANGE, None, Some(body.clone())).await;
    assert_eq!(exchanged.status, StatusCode::OK, "{}", exchanged.text);
    h.request("POST", COMPLETE, None, Some(body)).await
}

#[tokio::test]
async fn oidc_pkce_browser_binding_roles_revocation_and_replay() {
    let h = setup().await;
    let p = provider::Provider::start().await;
    assert_eq!(h.request("PUT", SETTINGS, Some(&h.viewer), Some(p.config())).await.status, StatusCode::FORBIDDEN);
    configure(&h, &p).await;
    let body = begin(&h, &p, json!({})).await;
    let mut bad = body.clone();
    bad["binding"] = json!("a".repeat(64));
    assert_eq!(h.request("POST", EXCHANGE, None, Some(bad)).await.status, StatusCode::UNAUTHORIZED);
    let first = finish(&h, body.clone()).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    assert_eq!(first.json()["roles"], json!(["viewer"]));
    assert_eq!(first.json()["user"]["is_superadmin"], false);
    let token = first.json()["tokens"]["access_token"].as_str().unwrap().to_owned();
    assert_eq!(h.request("PUT", SETTINGS, Some(&token), Some(p.config())).await.status, StatusCode::FORBIDDEN);
    assert_eq!(h.request("POST", EXCHANGE, None, Some(body.clone())).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(h.request("POST", COMPLETE, None, Some(body)).await.status, StatusCode::UNAUTHORIZED);
    let id = Id::parse(first.json()["user"]["id"].as_str().unwrap()).unwrap();
    let mut user = h.state.auth_backend.find_user(h.tenant, id).await.unwrap().unwrap();
    h.state.auth_backend.save_account(&user, None, &["auditor".into()]).await.unwrap();
    let mut config = p.config();
    config["expected_revision"] = h.get(SETTINGS).await.json()["revision"].clone();
    config["auto_provision"] = json!(false);
    config["client_secret"] = Value::Null;
    assert_eq!(h.request("PUT", SETTINGS, Some(&h.admin), Some(config)).await.status, StatusCode::OK);
    let second = finish(&h, begin(&h, &p, json!({})).await).await;
    assert_eq!(second.json()["roles"], json!(["auditor"]));
    assert_eq!(second.json()["user"]["id"], json!(id));
    let outsider = begin(&h, &p, json!({"sub":"not-yet-managed","email":"new@example.test"})).await;
    assert_eq!(h.request("POST", EXCHANGE, None, Some(outsider)).await.status, StatusCode::FORBIDDEN);
    user = h.state.auth_backend.find_user(h.tenant, id).await.unwrap().unwrap();
    user.state = UserState::Disabled;
    h.state.auth_backend.save_user(&user, None).await.unwrap();
    let disabled = begin(&h, &p, json!({})).await;
    assert_eq!(h.request("POST", EXCHANGE, None, Some(disabled)).await.status, StatusCode::FORBIDDEN);
    assert!(!h.request("GET", "/api/v1/assets", Some(&token), None).await.status.is_success());
}

#[tokio::test]
async fn oidc_rejects_invalid_claims_unverified_domains_and_stale_configuration() {
    let h = setup().await;
    let p = provider::Provider::start().await;
    configure(&h, &p).await;
    for claims in [
        json!({"iss":"https://attacker.invalid"}),
        json!({"fault":"signature"}),
        json!({"fault":"unknown-key"}),
        json!({"aud":"another-client"}),
        json!({"nonce":"wrong"}),
        json!({"sub":""}),
        json!({"azp":"another-client"}),
        json!({"aud":["console","other"]}),
        json!({"exp":Timestamp::now().unix_secs()-120}),
        json!({"iat":Timestamp::now().unix_secs()+120}),
        json!({"email_verified":false}),
        json!({"email":"person@untrusted.test"}),
    ] {
        let body = begin(&h, &p, claims.clone()).await;
        let result = h.request("POST", EXCHANGE, None, Some(body)).await;
        assert!(
            [StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN].contains(&result.status),
            "{claims}: {}",
            result.text
        );
    }
    let stale = begin(&h, &p, json!({})).await;
    configure(&h, &p).await;
    assert_eq!(h.request("POST", EXCHANGE, None, Some(stale)).await.status, StatusCode::UNAUTHORIZED);
    let ready = begin(&h, &p, json!({})).await;
    assert_eq!(h.request("POST", EXCHANGE, None, Some(ready.clone())).await.status, StatusCode::OK);
    let mut config = p.config();
    config["expected_revision"] = h.get(SETTINGS).await.json()["revision"].clone();
    config["enabled"] = json!(false);
    assert_eq!(h.request("PUT", SETTINGS, Some(&h.admin), Some(config)).await.status, StatusCode::OK);
    assert_eq!(h.request("POST", COMPLETE, None, Some(ready)).await.status, StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn oidc_requires_tls_exact_callback_and_low_privilege_default_role() {
    let h = setup().await;
    let p = provider::Provider::start().await;
    for (field, value) in [
        ("issuer", json!("http://id.example.test")),
        ("redirect_uri", json!("https://ui.example.test/arbitrary")),
        ("redirect_uri", json!("https://ui.example.test/login/oidc/callback?redirect=https://bad.test")),
        ("default_role", json!("tenant-admin")),
        ("default_role", json!("superadmin")),
    ] {
        let mut config = p.config();
        config[field] = value;
        assert_eq!(h.request("PUT", SETTINGS, Some(&h.admin), Some(config)).await.status, StatusCode::BAD_REQUEST);
    }
    configure(&h, &p).await;
    let raw: Vec<Value> = h.state.configurations.list(h.tenant, "oidc-provider").await.unwrap();
    assert!(!serde_json::to_string(&raw).unwrap().contains("local-test-secret"));
    let mut wrong_tenant = begin(&h, &p, json!({})).await;
    wrong_tenant["tenant_slug"] = json!(h.other_tenant.to_string());
    assert!(!h.request("POST", EXCHANGE, None, Some(wrong_tenant)).await.status.is_success());
}

#[tokio::test]
async fn oidc_mandatory_mfa_enrollment_and_recovery_are_usable_without_a_local_password() {
    let h = setup().await;
    let p = provider::Provider::start().await;
    configure(&h, &p).await;
    let mut policy = agf_api::auth_policy::TenantPolicy::load(&h.state, h.tenant).await.unwrap();
    policy.view.mfa_enforced = true;
    h.state
        .configurations
        .put(h.tenant, agf_api::auth_policy::KIND, agf_api::model_routes::tenant_record_id(h.tenant), &policy)
        .await
        .unwrap();
    let login = finish(&h, begin(&h, &p, json!({})).await).await.json();
    assert_eq!(login["mfa_enrollment_required"], true);
    let token = login["tokens"]["access_token"].as_str().unwrap();
    assert_eq!(h.request("GET", "/api/v1/assets", Some(token), None).await.status, StatusCode::PRECONDITION_FAILED);
    let setup = h.request("POST", "/api/v1/auth/mfa/setup", Some(token), Some(json!({}))).await;
    assert_eq!(setup.status, StatusCode::OK, "{}", setup.text);
    let username = login["user"]["username"].as_str().unwrap();
    let setup_data = setup.json();
    let code =
        agf_auth::mfa::TotpService::default().current_code(username, setup_data["secret"].as_str().unwrap()).unwrap();
    let confirm = h.request("POST", "/api/v1/auth/mfa/confirm", Some(token), Some(json!({"code":code}))).await;
    assert_eq!(confirm.status, StatusCode::OK, "{}", confirm.text);
    assert_eq!(h.request("GET", "/api/v1/assets", Some(token), None).await.status, StatusCode::UNAUTHORIZED);
    let recovery = confirm.json()["recovery_codes"][0].as_str().unwrap().to_owned();
    let mut callback = begin(&h, &p, json!({})).await;
    let exchanged = h.request("POST", EXCHANGE, None, Some(callback.clone())).await;
    assert_eq!(exchanged.json()["mfa_required"], true);
    callback["mfa_code"] = json!("wrong-code");
    assert_eq!(h.request("POST", COMPLETE, None, Some(callback.clone())).await.status, StatusCode::UNAUTHORIZED);
    callback["mfa_code"] = json!(recovery);
    let login = h.request("POST", COMPLETE, None, Some(callback)).await;
    assert_eq!(login.status, StatusCode::OK, "{}", login.text);
    assert_eq!(login.json()["mfa_enrollment_required"], false);
    let mut replay = begin(&h, &p, json!({})).await;
    replay["mfa_code"] = json!(recovery);
    assert_eq!(finish(&h, replay).await.status, StatusCode::UNAUTHORIZED);
}
