//! Exact owner/OID preflight precedes migration; all SQL faults belong to this disposable database.
use crate::{common::*, configuration_audit_support::SqlCase};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use tokio::task::JoinHandle;
mod authority;
mod gate;
mod owner;
pub(crate) use authority::{key, revoke, short_token, wait_expired};
pub(crate) use gate::Gate;
use owner::Owner;
pub(crate) const KIND: &str = "model-route-policy";

pub(crate) struct Case {
    pub(crate) sql: SqlCase,
    owner: Owner,
    id: Id,
}
impl Case {
    pub(crate) async fn open(label: &str) -> DomainResult<Self> {
        let owner = Owner::preflight().await?;
        let sql = SqlCase::open(label).await;
        owner.verify(&sql.pool).await?;
        Ok(Self { sql, owner, id: Id::new() })
    }
    pub(crate) fn id(&self) -> Id {
        self.id
    }
    pub(crate) fn uri(&self) -> String {
        format!("/api/v1/models/route-policies/{}", self.id)
    }
    pub(crate) async fn verify(&self) -> DomainResult<()> {
        self.owner.verify(&self.sql.pool).await
    }
    pub(crate) async fn body(&self) -> DomainResult<Value> {
        let response = self
            .sql
            .h
            .post(
                "/api/v1/gateway/endpoints",
                json!({"name":"owned-route-source",
            "model":"owned-route-source","provider":"mock","base_url":"http://mock.invalid/v1"}),
            )
            .await;
        assert_eq!(response.status, StatusCode::CREATED);
        Ok(json!({"expectedVersion":0,"name":"owned-route","primaryEndpointId":response.json()["id"],
            "enabled":true,"strategy":"priority"}))
    }
    pub(crate) async fn snapshot(&self) -> DomainResult<Value> {
        Ok(json!({"routes":self.sql.h.state.configurations.list::<Value>(self.sql.h.tenant,KIND).await?,
            "endpoints":self.sql.h.state.configurations.list::<Value>(self.sql.h.tenant,"model-endpoint").await?,
            "projection":self.sql.h.state.store.route_policy_list(self.sql.h.tenant)?,
            "audit":self.sql.h.state.store.audit_stats_durable(self.sql.h.tenant).await?}))
    }
    pub(crate) async fn wait_blocked(&self, pid: i32) -> DomainResult<i32> {
        self.verify().await?;
        tokio::time::timeout(std::time::Duration::from_secs(20),async {
            loop {
                let row:Option<i32>=sqlx::query_scalar(
                    "SELECT w.pid FROM pg_locks w JOIN pg_locks h ON w.locktype=h.locktype AND w.database=h.database AND w.classid=h.classid AND w.objid=h.objid AND w.objsubid=h.objsubid WHERE w.locktype='advisory' AND NOT w.granted AND h.granted AND h.pid=$1 AND w.pid<>h.pid AND w.database=(SELECT oid FROM pg_database WHERE datname=current_database()) LIMIT 1"
                ).bind(pid).fetch_optional(&self.sql.pool).await.map_err(sql_error)?;
                if let Some(pid)=row {return Ok(pid);}
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }).await.map_err(|_|invalid())?
    }
    pub(crate) async fn fault(&self) -> DomainResult<String> {
        self.verify().await?;
        let name = format!("agf_rp_fault_{}", Id::new().as_uuid().simple());
        let tenant = self.sql.h.tenant;
        sqlx::query(&format!("ALTER TABLE audit_logs ADD CONSTRAINT {name} CHECK (tenant_id<>'{tenant}'::uuid OR target->>'kind'<>'model-route-policy') NOT VALID"))
            .execute(&self.sql.pool).await.map_err(sql_error)?;
        Ok(name)
    }
    pub(crate) async fn unfault(&self, name: &str) -> DomainResult<()> {
        self.verify().await?;
        if !name.starts_with("agf_rp_fault_") || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_') {
            return Err(invalid());
        }
        sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {name}"))
            .execute(&self.sql.pool)
            .await
            .map_err(sql_error)?;
        Ok(())
    }
}
pub(crate) async fn joined(mut task: JoinHandle<Resp>) -> DomainResult<Resp> {
    match tokio::time::timeout(std::time::Duration::from_secs(20), &mut task).await {
        Ok(result) => result.map_err(|_| invalid()),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(invalid())
        }
    }
}
pub(crate) fn invalid() -> DomainError {
    DomainError::Internal("Owned route policy fixture boundary failed".into())
}
pub(crate) fn sql_error(error: sqlx::Error) -> DomainError {
    agf_storage::map_sqlx_err("owned_route_policy_fixture", &error)
}
