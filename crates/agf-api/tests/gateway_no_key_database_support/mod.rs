//! Validate exact ownership before reusing the existing migration fixture; no test tree is included.
use crate::{common::*, configuration_audit_support::SqlCase};
use agf_core::{
    audit::AuditLog,
    error::{DomainError, DomainResult},
    ids::Id,
};
use sqlx::{PgPool, postgres::PgPoolOptions};

pub(crate) struct Owned {
    case: SqlCase,
    owner: String,
    name: String,
    oid: i64,
}
fn invalid() -> DomainError {
    DomainError::PreconditionFailed("No-key gateway SQL requires its exact owned database".into())
}
fn sql(error: sqlx::Error) -> DomainError {
    agf_storage::map_sqlx_err("owned_no_key_gateway", &error)
}
async fn identity(pool: &PgPool) -> DomainResult<(String, i64, Option<String>)> {
    sqlx::query_as("SELECT current_database(),oid::bigint,shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()")
        .fetch_one(pool).await.map_err(sql)
}
impl Owned {
    pub(crate) async fn open(label: &str) -> DomainResult<Self> {
        let owner = std::env::var("AGF_NO_KEY_DATABASE_OWNER").map_err(|_| invalid())?;
        let run = owner.strip_prefix("AIGuardFabric no key gateway SQL ").ok_or_else(invalid)?;
        if run.len() != 32 || !run.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
            return Err(invalid());
        }
        let name = format!("agf_requirements_test_gateway_no_key_{}", &run[..12]);
        let raw = std::env::var("AGF_TEST_DATABASE_URL").map_err(|_| invalid())?;
        let url = url::Url::parse(&raw).map_err(|_| invalid())?;
        if !matches!(url.scheme(), "postgres" | "postgresql")
            || url.host_str() != Some("127.0.0.1")
            || url.port() != Some(5432)
            || url.path() != format!("/{name}")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid());
        }
        let pool = PgPoolOptions::new().max_connections(1).connect(&raw).await.map_err(sql)?;
        let before = identity(&pool).await?;
        pool.close().await;
        if before.0 != name || before.1 <= 0 || before.2.as_deref() != Some(owner.as_str()) {
            return Err(invalid());
        }
        // Migration starts only after the exact name, COMMENT and OID have been checked.
        let case = SqlCase::open(label).await;
        let owned = Self { case, owner, name, oid: before.1 };
        owned.verify().await?;
        Ok(owned)
    }
    pub(crate) async fn verify(&self) -> DomainResult<()> {
        let actual = identity(&self.case.pool).await?;
        if actual != (self.name.clone(), self.oid, Some(self.owner.clone())) {
            return Err(invalid());
        }
        Ok(())
    }
    pub(crate) async fn live_instance(&self, restart: bool) -> DomainResult<Harness> {
        self.verify().await?;
        let mut h = if restart { self.case.second_instance().await } else { self.case.h.clone() };
        Arc::make_mut(&mut h.state.config).mock_mode = false;
        let tenant = h.tenant;
        h.app =
            build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
                request.headers_mut().insert("x-agf-tenant", tenant.to_string().parse().unwrap());
                async move { request }
            }));
        Ok(h)
    }
    pub(crate) async fn terminal(&self, h: &Harness, id: Id) -> DomainResult<Vec<AuditLog>> {
        self.verify().await?;
        Ok(h.state
            .store
            .audit_chain_durable(h.tenant, 0, i64::MAX)
            .await?
            .into_iter()
            .filter(|row| {
                row.target.kind == "gateway-attempt" && row.target.id.as_deref() == Some(id.to_string().as_str())
            })
            .collect())
    }
    pub(crate) async fn rows(&self, h: &Harness) -> DomainResult<Value> {
        self.verify().await?;
        let rows: Vec<(String, uuid::Uuid, Value, Option<chrono::DateTime<chrono::Utc>>)> = sqlx::query_as(
            "SELECT kind,id,payload,deleted_at FROM console_configurations WHERE tenant_id=$1 AND kind=ANY($2) ORDER BY kind,id")
            .bind(h.tenant.as_uuid()).bind(vec!["gateway-attempt-fact-v1","gateway-settlement-pending-v1","gateway-attempt-active-v1",
                "gateway-ledger","runtime-quota-ledger","model-usage","gateway-meter-checkpoint-v1","gateway-rejection-fact-v1"])
            .fetch_all(&self.case.pool).await.map_err(sql)?;
        Ok(serde_json::to_value(rows)?)
    }
}
