//! LDAP configuration contract: TLS-only, tenant-scoped, encrypted and versioned.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;

const SETTINGS: &str = "/api/v1/settings/identity/ldap";
const LOGIN: &str = "/api/v1/auth/ldap/login";

fn config() -> Value {
    json!({"expected_revision":null, "enabled":true, "name":"Test AD", "bind_password":"directory-test-secret",
    "auto_provision":true, "default_role":"viewer", "config":{
        "url":"ldaps://127.0.0.1:9", "start_tls":false, "base_dn":"dc=example,dc=test",
        "bind_dn":"cn=reader,dc=example,dc=test",
        "user_filter":"(&(objectClass=user)(sAMAccountName={username}))",
        "id_attribute":"objectGUID", "email_attribute":"mail", "name_attribute":"displayName",
        "ca_pem":""
    }})
}

#[tokio::test]
async fn ldap_settings_require_write_permission_tls_secret_and_revision() {
    let h = setup().await;
    let before = h
        .request(
            "POST",
            LOGIN,
            None,
            Some(json!({"tenant_slug":"default",
        "username":"alice","password":"test-password"})),
        )
        .await;
    assert_eq!(before.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(h.request("PUT", SETTINGS, Some(&h.viewer), Some(config())).await.status, StatusCode::FORBIDDEN);
    let mut insecure = config();
    insecure["config"]["url"] = json!("ldap://127.0.0.1:389");
    assert_eq!(h.request("PUT", SETTINGS, Some(&h.admin), Some(insecure)).await.status, StatusCode::BAD_REQUEST);
    let mut privileged = config();
    privileged["default_role"] = json!("tenant-admin");
    assert_eq!(h.request("PUT", SETTINGS, Some(&h.admin), Some(privileged)).await.status, StatusCode::BAD_REQUEST);
    let saved = h.request("PUT", SETTINGS, Some(&h.admin), Some(config())).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.json()["credential_configured"], true);
    assert!(!saved.text.contains("directory-test-secret"));
    let read = h.request("GET", SETTINGS, Some(&h.admin), None).await;
    assert_eq!(read.status, StatusCode::OK);
    assert!(!read.text.contains("directory-test-secret"));
    let raw: Vec<Value> = h.state.configurations.list(h.tenant, "ldap-provider").await.unwrap();
    assert!(!serde_json::to_string(&raw).unwrap().contains("directory-test-secret"));
    let mut stale = config();
    stale["bind_password"] = Value::Null;
    assert_eq!(h.request("PUT", SETTINGS, Some(&h.admin), Some(stale)).await.status, StatusCode::BAD_REQUEST);
    let mut next = config();
    next["expected_revision"] = read.json()["revision"].clone();
    next["bind_password"] = Value::Null;
    let updated = h.request("PUT", SETTINGS, Some(&h.admin), Some(next.clone())).await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.text);
    assert_eq!(updated.json()["credential_configured"], true);
    assert_eq!(h.request("PUT", SETTINGS, Some(&h.admin), Some(next)).await.status, StatusCode::CONFLICT);
    let mut changed_target = config();
    changed_target["expected_revision"] = updated.json()["revision"].clone();
    changed_target["config"]["url"] = json!("ldaps://other.example.test:636");
    changed_target["bind_password"] = Value::Null;
    assert_eq!(
        h.request("PUT", SETTINGS, Some(&h.admin), Some(changed_target)).await.status,
        StatusCode::BAD_REQUEST,
        "Changing directory target must require a new service password"
    );
}

#[tokio::test]
async fn ldap_login_fails_closed_when_directory_unavailable() {
    let h = setup().await;
    let saved = h.request("PUT", SETTINGS, Some(&h.admin), Some(config())).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let result = h
        .request(
            "POST",
            LOGIN,
            None,
            Some(json!({"tenant_slug":"default",
        "username":"alice", "password":"test-password"})),
        )
        .await;
    assert!(matches!(result.status, StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE));
    assert!(!result.text.contains("directory-test-secret"));
    assert_eq!(
        h.request(
            "POST",
            LOGIN,
            None,
            Some(json!({"tenant_slug":h.other_tenant.to_string(),
        "username":"alice", "password":"test-password"}))
        )
        .await
        .status,
        StatusCode::PRECONDITION_FAILED
    );
}

#[tokio::test]
#[ignore = "requires the project-local LDAP mock from tests/support/ldap-mock"]
async fn ldap_directory_bind_tls_roles_and_disabled_account() {
    let h = setup().await;
    let ca = std::fs::read_to_string(std::env::var("AGF_TEST_LDAP_CA_FILE").unwrap()).unwrap();
    let admin_password = std::env::var("AGF_TEST_LDAP_ADMIN_PASSWORD").unwrap();
    let user_password = std::env::var("AGF_TEST_LDAP_USER_PASSWORD").unwrap();
    let mut settings = config();
    settings["config"]["url"] = json!("ldaps://127.0.0.1:1636");
    settings["config"]["base_dn"] = json!("ou=People,dc=example,dc=test");
    settings["config"]["bind_dn"] = json!("cn=admin,dc=example,dc=test");
    settings["config"]["user_filter"] = json!("(&(objectClass=inetOrgPerson)(uid={username}))");
    settings["config"]["id_attribute"] = json!("entryUUID");
    settings["config"]["name_attribute"] = json!("cn");
    settings["bind_password"] = json!(admin_password);
    let without_ca = h.request("PUT", SETTINGS, Some(&h.admin), Some(settings.clone())).await;
    assert_eq!(without_ca.status, StatusCode::OK, "{}", without_ca.text);
    let body = |name: &str, password: &str| json!({"tenant_slug":"default", "username":name, "password":password});
    let denied = h.request("POST", LOGIN, None, Some(body("alice", &user_password))).await;
    assert!(matches!(denied.status, StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE));
    settings["expected_revision"] = without_ca.json()["revision"].clone();
    settings["config"]["ca_pem"] = json!(ca);
    settings["bind_password"] = Value::Null;
    let saved = h.request("PUT", SETTINGS, Some(&h.admin), Some(settings)).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let wrong = h.request("POST", LOGIN, None, Some(body("alice", "wrong-password"))).await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED, "{}", wrong.text);
    assert_eq!(
        h.request("POST", LOGIN, None, Some(body("alice*)(uid=*)", &user_password))).await.status,
        StatusCode::UNAUTHORIZED
    );
    let first = h.request("POST", LOGIN, None, Some(body("alice", &user_password))).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    let first_body = first.json();
    assert_eq!(first_body["roles"], json!(["viewer"]));
    assert_eq!(first_body["user"]["idp"], json!("ldap"));
    assert_eq!(first_body["user"]["email"], json!("alice@example.test"));
    let token = first_body["tokens"]["access_token"].as_str().unwrap();
    assert_eq!(h.request("GET", "/api/v1/assets", Some(token), None).await.status, StatusCode::OK);
    let id = agf_core::ids::Id::parse(first_body["user"]["id"].as_str().unwrap()).unwrap();
    let mut user = h.state.auth_backend.find_user(h.tenant, id).await.unwrap().unwrap();
    user.state = agf_core::user::UserState::Disabled;
    h.state.auth_backend.save_user(&user, None).await.unwrap();
    assert_eq!(h.request("POST", LOGIN, None, Some(body("alice", &user_password))).await.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[ignore = "requires the project-local LDAP mock from tests/support/ldap-mock"]
async fn ldap_starttls_directory_bind() {
    let h = setup().await;
    let ca = std::fs::read_to_string(std::env::var("AGF_TEST_LDAP_CA_FILE").unwrap()).unwrap();
    let admin_password = std::env::var("AGF_TEST_LDAP_ADMIN_PASSWORD").unwrap();
    let user_password = std::env::var("AGF_TEST_LDAP_USER_PASSWORD").unwrap();
    let mut settings = config();
    settings["config"]["url"] = json!("ldap://127.0.0.1:1389");
    settings["config"]["start_tls"] = json!(true);
    settings["config"]["base_dn"] = json!("ou=People,dc=example,dc=test");
    settings["config"]["bind_dn"] = json!("cn=admin,dc=example,dc=test");
    settings["config"]["user_filter"] = json!("(&(objectClass=inetOrgPerson)(uid={username}))");
    settings["config"]["id_attribute"] = json!("entryUUID");
    settings["config"]["name_attribute"] = json!("cn");
    settings["config"]["ca_pem"] = json!(ca);
    settings["bind_password"] = json!(admin_password);
    let saved = h.request("PUT", SETTINGS, Some(&h.admin), Some(settings)).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let login = h
        .request(
            "POST",
            LOGIN,
            None,
            Some(json!({
                "tenant_slug":"default", "username":"alice", "password":user_password
            })),
        )
        .await;
    assert_eq!(login.status, StatusCode::OK, "{}", login.text);
    assert_eq!(login.json()["roles"], json!(["viewer"]));
}
