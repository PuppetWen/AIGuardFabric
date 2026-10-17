use crate::{cms_queue_support as queue, common::*, configuration_audit_support::SqlCase};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
pub(crate) mod authority;
pub(crate) mod engine;
pub(crate) mod fault;
mod wire;
pub(crate) use wire::Pending;
pub(crate) struct Case {
    pub(crate) inner: SqlCase,
    oid: i64,
    name: String,
    owner: String,
}
fn identity() -> DomainResult<(String, String)> {
    let owner = std::env::var("AGF_CMS_QUEUE_DATABASE_OWNER").map_err(|_| error("exact CMS SQL owner is required"))?;
    let run = owner
        .strip_prefix("AIGuardFabric CMS queue SQL ")
        .filter(|run| run.len() == 32 && run.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .ok_or_else(|| error("invalid CMS SQL owner"))?;
    Ok((format!("agf_requirements_test_cms_queue_{}", &run[..12]), owner))
}
pub(crate) fn error(reason: &str) -> DomainError {
    DomainError::PreconditionFailed(format!("owned CMS SQL: {reason}"))
}
pub(crate) fn sql(_: sqlx::Error) -> DomainError {
    DomainError::Internal("owned CMS SQL operation failed".into())
}
async fn inspect(pool: &sqlx::PgPool) -> DomainResult<(String, i64, Option<String>)> {
    sqlx::query_as("SELECT datname,oid::bigint,shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()")
        .fetch_one(pool).await.map_err(sql)
}
impl Case {
    pub(crate) async fn open(label: &str) -> DomainResult<Self> {
        let (name, owner) = identity()?;
        let raw = std::env::var("AGF_TEST_DATABASE_URL").map_err(|_| error("owned database URL is required"))?;
        let url = url::Url::parse(&raw)?;
        if url.scheme() != "postgres" && url.scheme() != "postgresql" {
            return Err(error("database scheme differs"));
        }
        if url.host_str() != Some("127.0.0.1")
            || url.port() != Some(5432)
            || url.path() != format!("/{name}")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(error("database is not the exact owned local target"));
        }
        let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&raw).await.map_err(sql)?;
        let result = inspect(&pool).await;
        pool.close().await;
        let (actual, oid, comment) = result?;
        if actual != name || comment.as_deref() != Some(&owner) {
            return Err(error("database owner differs before migration"));
        }
        let inner = SqlCase::open(label).await;
        let case = Self { inner, oid, name, owner };
        case.check().await?;
        Ok(case)
    }
    pub(crate) async fn check(&self) -> DomainResult<()> {
        let (name, oid, owner) = inspect(&self.inner.pool).await?;
        if (name, oid, owner) != (self.name.clone(), self.oid, Some(self.owner.clone())) {
            return Err(error("database owner/OID changed"));
        }
        Ok(())
    }
}
pub(crate) async fn state(h: &Harness) -> DomainResult<Value> {
    queue::get(h, queue::BASE).await
}
pub(crate) async fn snapshot(h: &Harness) -> DomainResult<Value> {
    queue::snapshot(h).await
}
pub(crate) async fn enqueue(h: &Harness) -> DomainResult<Id> {
    let receipt = queue::enqueue(h, Id::new(), 1, false).await?;
    serde_json::from_value(receipt["itemIds"][0].clone()).map_err(Into::into)
}
pub(crate) async fn send(h: &Harness, item: Id, request: Id) -> DomainResult<Value> {
    queue::post(h, &format!("{}/send", queue::BASE), queue::send_input(h, item, request).await?).await
}
pub(crate) async fn receipt(h: &Harness, request: Id) -> DomainResult<Value> {
    queue::get(h, &format!("{}/requests/{request}", queue::BASE)).await
}
pub(crate) async fn recovered(h: &Harness, item: Id) -> DomainResult<Value> {
    queue::post(h, &format!("{}/items/{item}/recover-local", queue::BASE), json!({})).await
}
pub(crate) async fn chain(h: &Harness) -> DomainResult<()> {
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    Ok(())
}
