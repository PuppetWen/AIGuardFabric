//! 可复现的真实 PostgreSQL 认证持久化验收；仅运行于专用测试数据库。
#![allow(clippy::unwrap_used, clippy::expect_used)]
use agf_api::auth_store::SqlAuthBackend;
use agf_auth::service::AuthBackend;
use agf_core::{
    ids::{Id, TenantId},
    time::Timestamp,
    user::{RefreshTokenRecord, User},
};
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use std::sync::Arc;

#[tokio::test]
#[ignore = "requires AGF_TEST_DATABASE_URL pointing to an isolated test database"]
async fn accounts_roles_and_sessions_survive_backend_recreation() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").expect("AGF_TEST_DATABASE_URL");
    let database_name = url::Url::parse(&url).unwrap().path().to_string();
    assert!(database_name.starts_with("/agf_requirements_test_"), "Refuse non-task database");
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(4).connect(&url).await.unwrap();
    let db = Database::from_pool(pool.clone());
    db.migrate().await.unwrap();
    let store = Arc::new(Store::new(db, None, Arc::new(MemoryObjectStore::new())));
    let tenant = TenantId::default_tenant();
    let name = format!("restart-{}", Id::new());
    let mut user = User::new_local(tenant, &name, format!("{name}@example.test"));
    user.must_change_password = false;
    let backend = SqlAuthBackend::new(store.clone());
    backend.save_account(&user, Some("test-phc-value"), &["viewer".into()]).await.unwrap();
    let token = RefreshTokenRecord {
        id: Id::new(),
        tenant_id: tenant,
        user_id: user.id,
        token_fingerprint: format!("restart-{}", Id::new()),
        expires_at: Timestamp::now().offset_secs(600),
        revoked: false,
        revoked_reason: None,
        device: None,
        created_at: Timestamp::now(),
    };
    backend.store_refresh(&token).await.unwrap();
    drop(backend);
    let backend = SqlAuthBackend::new(store.clone());
    let found = backend.find_user_with_secret(tenant, &name.to_uppercase()).await.unwrap().unwrap();
    assert_eq!(found.password_hash.as_deref(), Some("test-phc-value"));
    assert_eq!(backend.roles_of(tenant, user.id).await.unwrap(), vec!["viewer"]);
    assert!(backend.find_user(TenantId::new(), user.id).await.unwrap().is_none());
    assert!(backend.find_refresh(TenantId::new(), &token.token_fingerprint).await.unwrap().is_none());
    backend.revoke_refresh(tenant, token.id, "logout").await.unwrap();
    drop(backend);
    let backend = SqlAuthBackend::new(store.clone());
    assert!(backend.find_refresh(tenant, &token.token_fingerprint).await.unwrap().unwrap().revoked);
    assert!(backend.list_users(tenant).await.unwrap().iter().any(|row| row.id == user.id));
    let user = backend.find_user(tenant, user.id).await.unwrap().unwrap();
    backend.save_user(&user, Some("second-test-phc")).await.unwrap();
    assert_eq!(backend.password_history(tenant, user.id).await.unwrap(), vec!["test-phc-value"]);
    // Two instances may receive the same user's first OIDC callback concurrently.
    let other = SqlAuthBackend::new(store);
    let mut external = User::new_local(tenant, format!("oidc-{}", Id::new()), format!("{}@example.test", Id::new()));
    external.idp = agf_core::user::IdentityProvider::Oidc;
    external.external_subject = Some(format!("[\"https://id.example.test\",\"{}\"]", Id::new()));
    external.email = user.email.clone();
    external.must_change_password = false;
    let roles = vec!["viewer".into()];
    let (a, b) =
        tokio::join!(backend.provision_federated(&external, &roles), other.provision_federated(&external, &roles));
    a.unwrap();
    b.unwrap();
    let stale = other.find_user(tenant, external.id).await.unwrap().unwrap();
    let mut managed = backend.find_user(tenant, external.id).await.unwrap().unwrap();
    managed.state = agf_core::user::UserState::Disabled;
    backend.save_account(&managed, None, &["auditor".into()]).await.unwrap();
    assert!(matches!(other.save_user(&stale, None).await, Err(agf_core::error::DomainError::Conflict(_))));
    assert!(matches!(
        other.save_account(&stale, None, &["viewer".into()]).await,
        Err(agf_core::error::DomainError::Conflict(_))
    ));
    other.provision_federated(&external, &roles).await.unwrap();
    assert_eq!(other.find_user(tenant, external.id).await.unwrap().unwrap().state, agf_core::user::UserState::Disabled);
    assert_eq!(other.roles_of(tenant, external.id).await.unwrap(), vec!["auditor"]);
    let concurrent = User::new_local(tenant, format!("race-{}", Id::new()), format!("{}@example.test", Id::new()));
    backend.save_account(&concurrent, None, &["viewer".into()]).await.unwrap();
    let mut left = backend.find_user(tenant, concurrent.id).await.unwrap().unwrap();
    let mut right = other.find_user(tenant, concurrent.id).await.unwrap().unwrap();
    left.display_name = "left".into();
    right.display_name = "right".into();
    let viewer_roles = ["viewer".to_string()];
    let auditor_roles = ["auditor".to_string()];
    let (a, b) = tokio::join!(
        backend.save_account(&left, None, &viewer_roles),
        other.save_account(&right, None, &auditor_roles),
    );
    assert_ne!(a.is_ok(), b.is_ok(), "exactly one concurrent admin edit may commit");
    let winner = other.find_user(tenant, concurrent.id).await.unwrap().unwrap();
    assert_eq!(winner.version, 2);
    assert_eq!(
        other.roles_of(tenant, concurrent.id).await.unwrap(),
        if winner.display_name == "left" { vec!["viewer"] } else { vec!["auditor"] }
    );
    for _ in 0..2 {
        let mut no_email = User::new_local(tenant, format!("oidc-{}", Id::new()), "");
        no_email.idp = agf_core::user::IdentityProvider::Oidc;
        no_email.external_subject = Some(format!("[\"https://id.example.test\",\"{}\"]", Id::new()));
        other.provision_federated(&no_email, &roles).await.unwrap();
    }
    pool.close().await;
}
