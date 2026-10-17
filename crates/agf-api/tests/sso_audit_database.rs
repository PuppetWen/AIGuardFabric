//! Identity configuration and success audit must commit or roll back together.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_storage::{AuditRepo, Database, Store, objectstore::MemoryObjectStore};
use common::*;

const SETTINGS: &str = "/api/v1/settings/identity/ldap";
const OIDC_SETTINGS: &str = "/api/v1/settings/identity/oidc";

fn configuration() -> Value {
    json!({"expected_revision":null, "enabled":true, "name":"Atomic test directory",
        "bind_password":"test-only-service-password", "auto_provision":true, "default_role":"viewer",
        "config":{"url":"ldaps://ad.example.test:636", "start_tls":false,
            "base_dn":"dc=example,dc=test", "bind_dn":"cn=reader,dc=example,dc=test",
            "user_filter":"(uid={username})", "id_attribute":"entryUUID",
            "email_attribute":"mail", "name_attribute":"cn", "ca_pem":""}})
}

fn oidc_configuration() -> Value {
    json!({"expected_revision":null, "enabled":false, "name":"Atomic test OIDC",
        "issuer":"https://issuer.example.test", "client_id":"test-client", "client_auth":"none",
        "client_secret":null, "redirect_uri":"https://console.example.test/login/oidc/callback",
        "auto_provision":false, "default_role":"viewer", "email_domains":[]})
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn sso_settings_rollback_if_audit_cannot_commit() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap();
    let database = Database::from_pool(pool.clone());
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(store)));
    let tenant = agf_api::tenant_directory::new(format!("ldap-sql-{}", TenantId::new()), "LDAP SQL test".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.app = build_router(h.state.clone());
    let token = format!("Bearer {}", h.admin);
    let tenant_id = tenant.id.to_string();
    let headers = [("authorization", token.as_str()), ("x-agf-tenant", tenant_id.as_str())];
    let created = h.request_with("PUT", SETTINGS, &headers, Some(configuration())).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    let revision = created.json()["revision"].clone();
    let oidc_created = h.request_with("PUT", OIDC_SETTINGS, &headers, Some(oidc_configuration())).await;
    assert_eq!(oidc_created.status, StatusCode::OK, "{}", oidc_created.text);
    let oidc_revision = oidc_created.json()["revision"].clone();
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    let before = AuditRepo::chain_stats(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    let constraint = format!("agf_test_ldap_audit_{}", agf_core::ids::Id::new().as_uuid().simple());
    let sql = format!(
        "ALTER TABLE audit_logs ADD CONSTRAINT {constraint} CHECK (tenant_id <> '{}'::uuid) NOT VALID",
        tenant.id
    );
    sqlx::query(&sql).execute(&pool).await.unwrap();
    let mut changed = configuration();
    changed["expected_revision"] = revision.clone();
    changed["name"] = json!("must roll back");
    changed["bind_password"] = Value::Null;
    let rejected = h.request_with("PUT", SETTINGS, &headers, Some(changed)).await;
    assert!(!rejected.status.is_success(), "{}", rejected.text);
    let mut oidc_changed = oidc_configuration();
    oidc_changed["expected_revision"] = oidc_revision.clone();
    oidc_changed["name"] = json!("must roll back OIDC");
    let oidc_rejected = h.request_with("PUT", OIDC_SETTINGS, &headers, Some(oidc_changed)).await;
    assert!(!oidc_rejected.status.is_success(), "{}", oidc_rejected.text);
    sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}")).execute(&pool).await.unwrap();
    let current = h.request_with("GET", SETTINGS, &headers, None).await;
    assert_eq!(current.status, StatusCode::OK, "{}", current.text);
    assert_eq!(current.json()["revision"], revision);
    assert_eq!(current.json()["name"], "Atomic test directory");
    let oidc_current = h.request_with("GET", OIDC_SETTINGS, &headers, None).await;
    assert_eq!(oidc_current.status, StatusCode::OK, "{}", oidc_current.text);
    assert_eq!(oidc_current.json()["revision"], oidc_revision);
    assert_eq!(oidc_current.json()["name"], "Atomic test OIDC");
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    assert_eq!(AuditRepo::chain_stats(&mut tx).await.unwrap(), before);
    tx.commit().await.unwrap();
    pool.close().await;
}
