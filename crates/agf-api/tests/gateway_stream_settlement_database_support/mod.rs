//! New owned namespace; the reused SQL fixture is called only after exact identity checks.
use crate::{common::*, configuration_audit_support::SqlCase};
use agf_core::{
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::Id,
};
use secrecy::ExposeSecret;
use sqlx::PgPool;
use std::time::Duration;
const WAIT: Duration = Duration::from_secs(20);
pub(crate) const FACT: &str = "gateway-attempt-fact-v1";
pub(crate) const PENDING: &str = "gateway-settlement-pending-v1";
const REJECTION: &str = "gateway-rejection-fact-v1";
mod fault;
mod gate;
mod owner;
mod platform;
mod provider;
pub(crate) use fault::{Fault, with_fault};
pub(crate) use gate::{Reading, with_gate};
pub(crate) use platform::attempt;
pub(crate) use platform::{Fixture, RequestBody};
pub(crate) use provider::{Provider, Reply};
pub(crate) fn invalid() -> DomainError {
    DomainError::PreconditionFailed("Owned stream settlement fixture invariant failed".into())
}
fn sql(error: sqlx::Error) -> DomainError {
    agf_storage::map_sqlx_err("owned_stream_settlement", &error)
}
pub(crate) struct Owned {
    pub(crate) case: SqlCase,
    owner: owner::Owner,
}
impl Owned {
    pub(crate) async fn open(label: &str) -> DomainResult<Self> {
        if label.len() > 24 {
            return Err(invalid());
        }
        let (preflight, owner) = owner::Owner::preflight().await?;
        preflight.close().await;
        let case = SqlCase::open(label).await;
        owner.verify(&case.pool).await?;
        Ok(Self { case, owner })
    }
    pub(crate) async fn verify(&self) -> DomainResult<()> {
        self.owner.verify(&self.case.pool).await
    }
    pub(crate) async fn rows(&self) -> DomainResult<Value> {
        self.verify().await?;
        let rows: Vec<(String, uuid::Uuid, Value, Option<chrono::DateTime<chrono::Utc>>)> = sqlx::query_as("SELECT kind,id,payload,deleted_at FROM console_configurations WHERE tenant_id=$1 AND kind=ANY($2) ORDER BY kind,id")
            .bind(self.case.h.tenant.as_uuid()).bind(vec![FACT,PENDING,REJECTION,"gateway-ledger","runtime-quota-ledger","model-usage","gateway-meter-checkpoint-v1","gateway-attempt-active-v1"]).fetch_all(&self.case.pool).await.map_err(sql)?;
        Ok(serde_json::to_value(rows)?)
    }
    pub(crate) async fn body(&self, h: &Harness, id: Id, kind: &str) -> DomainResult<Value> {
        self.verify().await?;
        let stored: SecretMaterial = h.state.configurations.get(h.tenant, kind, id).await?.ok_or_else(invalid)?;
        if stored.aad.as_deref() != Some(format!("agf.gateway-settlement.preview.v1:{kind}:{}:{id}", h.tenant).as_str())
        {
            return Err(invalid());
        }
        let clear = agf_api::model_gateway::cipher(&h.state)?.decrypt(&stored)?;
        serde_json::from_str(clear.expose_secret()).map_err(|_| invalid())
    }
    pub(crate) async fn chain(&self) -> DomainResult<()> {
        assert!(self.case.h.state.store.audit_verify_durable(self.case.h.tenant).await?.passed);
        Ok(())
    }
    pub(crate) async fn audit(&self, id: Id) -> DomainResult<Vec<agf_core::audit::AuditLog>> {
        self.verify().await?;
        let id = id.to_string();
        Ok(self
            .case
            .h
            .state
            .store
            .audit_chain_durable(self.case.h.tenant, 0, i64::MAX)
            .await?
            .into_iter()
            .filter(|row| row.target.kind == "gateway-attempt" && row.target.id.as_deref() == Some(id.as_str()))
            .collect())
    }
}
