//! Concurrent administrative edits must not silently relax a password policy.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
#[path = "common/oidc_provider.rs"]
mod provider;
use agf_core::ids::Id;
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use common::*;

async fn setup_sql() -> (Harness, Arc<Store>) {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap();
    let database = Database::from_pool(pool);
    database.migrate().await.unwrap();
    let db = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
    let tenant = agf_api::tenant_directory::new(format!("settings-durability-{}", Id::new()), "Settings SQL".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.tenant = tenant.id;
    h.app = build_router(h.state.clone());
    (h, db)
}

async fn call(h: &Harness, method: &str, path: &str, body: Option<Value>) -> Resp {
    h.request_with(
        method,
        path,
        &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &h.tenant.to_string())],
        body,
    )
    .await
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn password_policy_versions_prevent_cross_instance_overwrite() {
    let (h, db) = setup_sql().await;
    let mut h2 = h.clone();
    h2.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h2.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db)));
    h2.app = build_router(h2.state.clone());
    let uri = "/api/v1/settings/password-policy";
    let mut first_policy = call(&h, "GET", uri, None).await.json();
    first_policy["min_length"] = json!(13);
    first_policy["expected_version"] = json!(0);
    let created = call(&h, "PUT", uri, Some(first_policy)).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    assert_eq!(created.json()["version"], 1);
    let mut stronger = created.json();
    stronger["expected_version"] = json!(1);
    stronger["min_length"] = json!(16);
    let mut weaker = created.json();
    weaker["expected_version"] = json!(1);
    weaker["min_length"] = json!(8);
    let (a, b) = tokio::join!(call(&h, "PUT", uri, Some(stronger)), call(&h2, "PUT", uri, Some(weaker)));
    assert_eq!(u8::from(a.status == StatusCode::OK) + u8::from(b.status == StatusCode::OK), 1);
    assert_eq!(u8::from(a.status == StatusCode::CONFLICT) + u8::from(b.status == StatusCode::CONFLICT), 1);
    let latest = call(&h2, "GET", uri, None).await.json();
    assert_eq!(latest["version"], 2);
    assert!(latest["min_length"] == 16 || latest["min_length"] == 8);
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn oidc_revisions_prevent_cross_instance_provider_overwrite() {
    let (h, db) = setup_sql().await;
    let mut h2 = h.clone();
    h2.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h2.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db)));
    h2.app = build_router(h2.state.clone());
    let provider = provider::Provider::start().await;
    let uri = "/api/v1/settings/identity/oidc";
    let created = call(&h, "PUT", uri, Some(provider.config())).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    let revision = created.json()["revision"].clone();
    let body = |name: &str| {
        let mut config = provider.config();
        config["expected_revision"] = revision.clone();
        config["client_secret"] = Value::Null;
        config["name"] = json!(name);
        config
    };
    let (a, b) = tokio::join!(
        call(&h, "PUT", uri, Some(body("first provider"))),
        call(&h2, "PUT", uri, Some(body("second provider"))),
    );
    assert_eq!(u8::from(a.status == StatusCode::OK) + u8::from(b.status == StatusCode::OK), 1);
    assert_eq!(u8::from(a.status == StatusCode::CONFLICT) + u8::from(b.status == StatusCode::CONFLICT), 1);
    let latest = call(&h2, "GET", uri, None).await.json();
    assert_ne!(latest["revision"], revision);
    assert_eq!(latest["credential_configured"], true);
    assert!(latest["name"] == "first provider" || latest["name"] == "second provider");
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn concurrent_audit_appends_keep_one_postgres_hash_chain() {
    let (h, db) = setup_sql().await;
    let append = |label: &'static str| {
        let store = db.clone();
        async move {
            store
                .with_tenant(h.tenant, |tx| {
                    Box::pin(async move {
                        let actor = agf_core::audit::AuditActor {
                            id: None,
                            kind: "test".into(),
                            name: label.into(),
                            source_ip: None,
                            user_agent: None,
                            session_id: None,
                        };
                        let target = agf_core::audit::AuditTarget::new("test", None, Some(label.into()));
                        agf_storage::AuditRepo::append(
                            tx,
                            agf_core::audit::AuditAction::Configure,
                            agf_core::audit::AuditOutcome::Success,
                            actor,
                            target,
                            None,
                            None,
                            Vec::new(),
                            label,
                        )
                        .await
                    })
                })
                .await
        }
    };
    let (first, second) = tokio::join!(append("first"), append("second"));
    assert!(first.is_ok(), "{first:?}");
    assert!(second.is_ok(), "{second:?}");
    let entries = db
        .with_tenant(h.tenant, |tx| Box::pin(async move { agf_storage::AuditRepo::load_chain(tx, 0, 10).await }))
        .await
        .unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].sequence, 1);
    assert_eq!(entries[1].sequence, 2);
    assert_eq!(entries[0].prev_hash, agf_core::audit::GENESIS_HASH);
    assert!(agf_core::audit::verify_chain(&entries).passed);
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn committed_audit_is_immediately_visible_across_api_instances() {
    use agf_core::audit::{AuditAction, AuditActor, AuditOutcome, AuditTarget};
    let (h, db) = setup_sql().await;
    let mut h2 = h.clone();
    h2.state.store = Arc::new(agf_api::store::ApiStore::with_database(db));
    h2.app = build_router(h2.state.clone());
    let entry = |name: &str| {
        (
            AuditActor {
                id: None,
                kind: "test".into(),
                name: name.into(),
                source_ip: None,
                user_agent: None,
                session_id: None,
            },
            AuditTarget::new("test", None, Some(name.into())),
        )
    };
    let (actor_a, target_a) = entry("instance-a");
    let (actor_b, mut target_b) = entry("instance-b");
    target_b.id = Some("cross-instance-target-7".into());
    let (first, second) = tokio::join!(
        h.state.audit(h.tenant, AuditAction::Configure, AuditOutcome::Success, actor_a, target_a, "first write"),
        h2.state.audit(h.tenant, AuditAction::Configure, AuditOutcome::Success, actor_b, target_b, "second write")
    );
    assert!(first.is_ok(), "{first:?}");
    assert!(second.is_ok(), "{second:?}");
    let rows = h2.state.store.audit_chain_durable(h.tenant, 0, 10).await.unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!((rows[0].sequence, rows[1].sequence), (1, 2));
    assert!(agf_core::audit::verify_chain(&rows).passed);
    let listed = call(&h2, "GET", "/api/v1/audit", None).await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.text);
    assert_eq!(listed.json()["total"], 2);
    let filtered = call(&h2, "GET", "/api/v1/audit?actor=instance-b&q=second%20write&page_size=1", None).await;
    assert_eq!(filtered.status, StatusCode::OK, "{}", filtered.text);
    assert_eq!(filtered.json()["total"], 1);
    assert_eq!(filtered.json()["items"][0]["actor"]["name"], "instance-b");
    let by_target = call(&h, "GET", "/api/v1/audit?q=cross-instance-target-7", None).await;
    assert_eq!(by_target.status, StatusCode::OK, "{}", by_target.text);
    assert_eq!(by_target.json()["total"], 1);
    assert_eq!(by_target.json()["items"][0]["target"]["id"], "cross-instance-target-7");
    let verified = call(&h, "GET", "/api/v1/audit/verify", None).await;
    assert_eq!(verified.status, StatusCode::OK, "{}", verified.text);
    assert_eq!(verified.json()["passed"], true);
    assert_eq!(verified.json()["chain"]["source"], "postgres");
    assert_eq!(verified.json()["memory_chain"], Value::Null);

    let mut policy = call(&h, "GET", "/api/v1/settings/password-policy", None).await.json();
    policy["min_length"] = json!(13);
    policy["expected_version"] = json!(0);
    let updated = call(&h, "PUT", "/api/v1/settings/password-policy", Some(policy)).await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.text);
    let after = call(&h2, "GET", "/api/v1/audit", None).await;
    assert_eq!(after.json()["total"], 3, "业务接口返回前应提交审计: {}", after.text);
}
