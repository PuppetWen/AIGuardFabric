//! Exact owned database identity is checked before migrations, fixtures or fault injection.
use crate::configuration_audit_support::SqlCase;

pub(crate) const OWNER_ENV: &str = "AGF_POLICY_PUBLICATION_DATABASE_OWNER";
const PREFIX: &str = "AIGuardFabric policy publication SQL ";

pub(crate) fn identity() -> (String, String) {
    let owner = std::env::var(OWNER_ENV).expect("owned policy database marker required");
    let run = owner.strip_prefix(PREFIX).expect("unexpected policy database owner");
    assert!(run.len() == 32 && run.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    (format!("agf_requirements_test_policy_publication_{}", &run[..12]), owner)
}

pub(crate) async fn check(pool: &sqlx::PgPool) {
    let actual:(String,Option<String>)=sqlx::query_as("SELECT current_database(),shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()")
        .fetch_one(pool).await.expect("readonly policy database ownership check");
    let (database, owner) = identity();
    assert_eq!(actual, (database, Some(owner)));
}

pub(crate) async fn open(label: &str) -> SqlCase {
    assert!(!label.is_empty() && label.len() + 37 <= 64, "tenant label + UUID must fit the actual slug contract");
    let url = std::env::var("AGF_TEST_DATABASE_URL").expect("owned policy database URL required");
    let (database, _) = identity();
    assert_eq!(url::Url::parse(&url).unwrap().path(), format!("/{database}"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&url).await.unwrap();
    check(&pool).await;
    pool.close().await;
    SqlCase::open(label).await
}
