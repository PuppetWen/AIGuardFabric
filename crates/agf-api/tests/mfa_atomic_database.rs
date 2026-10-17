//! A failed MFA transition must leave the account and secret record in one state.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use agf_api::{
    auth_store::SqlAuthBackend,
    config_store::ConfigStore,
    mfa_store::{Enrollment, KIND, confirm_sql, disable_sql},
};
use agf_auth::{mfa::TotpService, service::AuthBackend};
use agf_core::{
    credential::KeyBackend,
    error::DomainError,
    ids::{Id, TenantId},
    time::Timestamp,
    user::User,
};
use agf_storage::{Database, Store, crypto::FieldCipher, objectstore::MemoryObjectStore};
use secrecy::SecretString;
use std::sync::Arc;

#[tokio::test]
#[ignore = "requires AGF_TEST_DATABASE_URL pointing to an isolated test database"]
async fn mfa_account_and_enrollment_commit_or_roll_back_together() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").expect("AGF_TEST_DATABASE_URL");
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(4).connect(&url).await.unwrap();
    let db = Database::from_pool(pool.clone());
    db.migrate().await.unwrap();
    let store = Arc::new(Store::new(db, None, Arc::new(MemoryObjectStore::new())));
    let backend = SqlAuthBackend::new(store.clone());
    let configs = ConfigStore::new(Some(store.clone()));
    let tenant = TenantId::default_tenant();
    let user = User::new_local(tenant, format!("mfa-{}", Id::new()), format!("{}@example.test", Id::new()));
    backend.save_account(&user, None, &["viewer".into()]).await.unwrap();
    let cipher = FieldCipher::new(&[7; 32], "test-mfa", KeyBackend::LocalFile).unwrap();
    let secret = TotpService::default().generate_secret();
    let encrypted =
        cipher.encrypt(&SecretString::new(secret.clone().into()), &FieldCipher::make_aad(&tenant, &user.id)).unwrap();
    configs
        .put(
            tenant,
            KIND,
            user.id,
            &Enrollment { secret: Some(encrypted), created_at: Timestamp::now().unix_secs(), ..Enrollment::default() },
        )
        .await
        .unwrap();
    let code = TotpService::default().current_code(&user.username, &secret).unwrap();

    let stale = backend.find_user(tenant, user.id).await.unwrap().unwrap();
    backend.save_user(&stale, None).await.unwrap();
    assert!(matches!(confirm_sql(&store, &cipher, tenant, &stale, &code).await, Err(DomainError::Conflict(_))));
    assert!(!configs.get::<Enrollment>(tenant, KIND, user.id).await.unwrap().unwrap().confirmed);
    assert!(!backend.find_user(tenant, user.id).await.unwrap().unwrap().mfa_enabled);

    let fresh = backend.find_user(tenant, user.id).await.unwrap().unwrap();
    let recovery = confirm_sql(&store, &cipher, tenant, &fresh, &code).await.unwrap();
    assert_eq!(recovery.len(), 10);
    assert!(configs.get::<Enrollment>(tenant, KIND, user.id).await.unwrap().unwrap().confirmed);
    assert!(backend.find_user(tenant, user.id).await.unwrap().unwrap().mfa_enabled);

    let stale = backend.find_user(tenant, user.id).await.unwrap().unwrap();
    backend.save_user(&stale, None).await.unwrap();
    assert!(matches!(
        disable_sql(&store, &cipher, tenant, &stale, Some(&recovery[0])).await,
        Err(DomainError::Conflict(_))
    ));
    assert!(configs.get::<Enrollment>(tenant, KIND, user.id).await.unwrap().unwrap().confirmed);
    assert!(backend.find_user(tenant, user.id).await.unwrap().unwrap().mfa_enabled);

    let fresh = backend.find_user(tenant, user.id).await.unwrap().unwrap();
    disable_sql(&store, &cipher, tenant, &fresh, Some(&recovery[0])).await.unwrap();
    let disabled = configs.get::<Enrollment>(tenant, KIND, user.id).await.unwrap().unwrap();
    assert!(!disabled.confirmed);
    assert!(disabled.confirmed_at > 0);
    assert!(!backend.find_user(tenant, user.id).await.unwrap().unwrap().mfa_enabled);
    pool.close().await;
}
