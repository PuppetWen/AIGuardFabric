//! Exact ownership is established before the shared SQL fixture can migrate or write.
use crate::{common::*, configuration_audit_support::SqlCase};
use agf_core::error::{DomainError, DomainResult};
use sqlx::{PgPool, postgres::PgPoolOptions};

pub(crate) const FACT: &str = "gateway-attempt-fact-v1";
pub(crate) const PENDING: &str = "gateway-settlement-pending-v1";
pub(crate) const ACTIVE: &str = "gateway-attempt-active-v1";
pub(crate) const REJECTION: &str = "gateway-rejection-fact-v1";
pub(crate) fn invalid() -> DomainError {
    DomainError::PreconditionFailed("Owned gateway settlement SQL fixture assertion failed".into())
}
pub(super) fn sql(error: &sqlx::Error) -> DomainError {
    agf_storage::map_sqlx_err("owned_gateway_settlement_fixture", error)
}

#[derive(Clone)]
pub(crate) struct Ownership {
    owner: String,
    name: String,
    oid: i64,
}
impl Ownership {
    async fn capture(pool: &PgPool) -> DomainResult<Self> {
        let owner = std::env::var("AGF_GATEWAY_SETTLEMENT_DATABASE_OWNER").map_err(|_| invalid())?;
        let run = owner.strip_prefix("AIGuardFabric gateway settlement SQL ").ok_or_else(invalid)?;
        if run.len() != 32 || !run.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
            return Err(invalid());
        }
        let name = format!("agf_requirements_test_gateway_settlement_{}", &run[..12]);
        let row:(String,i64,Option<String>)=sqlx::query_as("SELECT current_database(),oid::bigint,shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()")
            .fetch_one(pool).await.map_err(|e|sql(&e))?;
        if row.0 != name || row.2.as_deref() != Some(owner.as_str()) || row.1 <= 0 {
            return Err(invalid());
        }
        Ok(Self { owner, name, oid: row.1 })
    }
    pub(crate) async fn verify(&self, pool: &PgPool) -> DomainResult<()> {
        let actual = Self::capture(pool).await?;
        if (actual.name, actual.owner, actual.oid) != (self.name.clone(), self.owner.clone(), self.oid) {
            return Err(invalid());
        }
        Ok(())
    }
}
pub(crate) struct Owned {
    pub(crate) case: SqlCase,
    pub(crate) ownership: Ownership,
}
impl Owned {
    pub(crate) async fn open(label: &str) -> DomainResult<Self> {
        // Host, port, name and COMMENT/OID are checked BEFORE SqlCase's migration or tenant insertion.
        if label.len() > 24 {
            return Err(invalid());
        }
        let raw = std::env::var("AGF_TEST_DATABASE_URL").map_err(|_| invalid())?;
        let url = url::Url::parse(&raw).map_err(|_| invalid())?;
        if !matches!(url.scheme(), "postgres" | "postgresql")
            || url.host_str() != Some("127.0.0.1")
            || url.port() != Some(5432)
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid());
        }
        let preflight = PgPoolOptions::new().max_connections(1).connect(&raw).await.map_err(|e| sql(&e))?;
        let ownership = Ownership::capture(&preflight).await?;
        if url.path() != format!("/{}", ownership.name) {
            preflight.close().await;
            return Err(invalid());
        }
        preflight.close().await;
        let case = SqlCase::open(label).await;
        ownership.verify(&case.pool).await?;
        Ok(Self { case, ownership })
    }
    pub(crate) async fn rows(&self) -> DomainResult<Value> {
        self.ownership.verify(&self.case.pool).await?;
        let rows:Vec<(String,uuid::Uuid,Value,Option<chrono::DateTime<chrono::Utc>>)>=sqlx::query_as("SELECT kind,id,payload,deleted_at FROM console_configurations WHERE tenant_id=$1 AND kind=ANY($2) ORDER BY kind,id")
            .bind(self.case.h.tenant.as_uuid()).bind(vec![FACT,PENDING,ACTIVE,REJECTION,"gateway-ledger","runtime-quota-ledger","model-usage","gateway-meter-checkpoint-v1"]).fetch_all(&self.case.pool).await.map_err(|e|sql(&e))?;
        Ok(serde_json::to_value(rows)?)
    }
    pub(crate) async fn chain(&self) -> DomainResult<()> {
        assert!(self.case.h.state.store.audit_verify_durable(self.case.h.tenant).await?.passed);
        Ok(())
    }
}
