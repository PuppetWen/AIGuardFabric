//! Check exact task ownership before migrations or any ignored MSE SQL write.
use crate::configuration_audit_support::SqlCase;

pub(crate) async fn open(label: &str) -> SqlCase {
    let url = std::env::var("AGF_TEST_DATABASE_URL").expect("owned MSE database URL is required");
    let owner = std::env::var("AGF_MSE_DATABASE_OWNER").expect("owned MSE database marker is required");
    let run = owner.strip_prefix("AIGuardFabric MSE inventory SQL ").expect("unexpected MSE database owner");
    assert!(run.len() == 32 && run.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    let expected = format!("agf_requirements_test_mse_{}", &run[..12]);
    let parsed = url::Url::parse(&url).expect("valid owned database URL");
    assert_eq!(parsed.path(), format!("/{expected}"));
    let pool =
        sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&url).await.expect("owned database connection");
    let identity: (String,Option<String>) = sqlx::query_as(
        "SELECT current_database(), shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()")
        .fetch_one(&pool).await.expect("readonly database ownership check");
    pool.close().await;
    assert_eq!(identity.0, expected);
    assert_eq!(identity.1.as_deref(), Some(owner.as_str()));
    SqlCase::open(label).await
}
