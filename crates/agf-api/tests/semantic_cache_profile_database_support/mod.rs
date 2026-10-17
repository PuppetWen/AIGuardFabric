//! Owned SQL configuration CAS fixtures, without provider requests or shared DDL changes.
use crate::{common::*, configuration_audit_support::SqlCase};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, deterministic_id},
};
use tokio::task::JoinHandle;
mod authority;
mod gate;
mod owner;
pub(crate) use authority::{key, revoke, short_token, wait_expired};
pub(crate) use gate::Gate;
use owner::Owner;
pub(crate) const PROFILE: &str = "/api/v1/models/semantic-cache/profile";
pub(crate) const KIND: &str = "semantic-cache-profile";
pub(crate) struct Case {
    pub(crate) sql: SqlCase,
    owner: Owner,
}
impl Case {
    pub(crate) async fn open(label: &str) -> DomainResult<Self> {
        let owner = Owner::preflight().await?;
        if label.is_empty() || label.len() + 37 > 64 {
            return Err(invalid());
        }
        // Ownership is fully established before the legacy helper may call migrate().
        let sql = SqlCase::open(label).await;
        owner.verify(&sql.pool).await?;
        Ok(Self { sql, owner })
    }
    pub(crate) async fn verify(&self) -> DomainResult<()> {
        self.owner.verify(&self.sql.pool).await
    }
    pub(crate) async fn body(&self) -> DomainResult<Value> {
        let mut ids = Vec::new();
        for model in ["owned-profile-chat", "owned-profile-embedding"] {
            let response=self.sql.h.post("/api/v1/gateway/endpoints",json!({"name":model,"model":model,"provider":"mock","base_url":"http://mock.invalid/v1","local_deployment":true})).await;
            assert_eq!(response.status, StatusCode::CREATED);
            ids.push(response.json()["id"].clone());
        }
        Ok(json!({"expected_version":0,"enabled":true,"settings":{
            "chat_endpoint_id":ids[0],"chat_model":"owned-profile-chat","chat_model_revision":"chat-pin-v1",
            "embedding_endpoint_id":ids[1],"embedding_model":"owned-profile-embedding","embedding_model_revision":"local-pin-v1",
            "dimensions":64,"send_dimensions":false,"max_input_tokens":8192,
            "embedding_micro_per_1k":0,"threshold_ppm":950_000,"ttl_seconds":300,
            "classification_floor":"internal","mode":"mock_vector"}}))
    }
    pub(crate) async fn snapshot(&self) -> DomainResult<Value> {
        Ok(json!({"profiles":self.sql.h.state.configurations.list::<Value>(self.sql.h.tenant,KIND).await?,
            "endpoints":self.sql.h.state.configurations.list::<Value>(self.sql.h.tenant,"model-endpoint").await?,
            "audit":self.sql.h.state.store.audit_stats_durable(self.sql.h.tenant).await?}))
    }
    pub(crate) async fn wait_blocked(&self, pid: i32) -> DomainResult<i32> {
        self.verify().await?;
        tokio::time::timeout(std::time::Duration::from_secs(20),async {
            loop {
                let blocked:Option<i32>=sqlx::query_scalar(
                    "SELECT w.pid FROM pg_locks w JOIN pg_locks h ON w.locktype=h.locktype AND w.database=h.database AND w.classid=h.classid AND w.objid=h.objid AND w.objsubid=h.objsubid WHERE w.locktype='advisory' AND NOT w.granted AND h.granted AND h.pid=$1 AND w.pid<>h.pid AND w.database=(SELECT oid FROM pg_database WHERE datname=current_database()) LIMIT 1"
                ).bind(pid).fetch_optional(&self.sql.pool).await.map_err(sql_error)?;
                if let Some(waiter)=blocked {return Ok(waiter);}
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }).await.map_err(|_|invalid())?
    }
    pub(crate) async fn fault(&self) -> DomainResult<String> {
        self.verify().await?;
        let name = format!("agf_sp_fault_{}", Id::new().as_uuid().simple());
        let tenant = self.sql.h.tenant;
        sqlx::query(&format!("ALTER TABLE audit_logs ADD CONSTRAINT {name} CHECK (tenant_id<>'{tenant}'::uuid OR target->>'kind'<>'semantic-cache-profile') NOT VALID"))
            .execute(&self.sql.pool).await.map_err(sql_error)?;
        Ok(name)
    }
    pub(crate) async fn unfault(&self, name: &str) -> DomainResult<()> {
        self.verify().await?;
        if !name.starts_with("agf_sp_fault_") || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(invalid());
        }
        sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {name}"))
            .execute(&self.sql.pool)
            .await
            .map_err(sql_error)?;
        Ok(())
    }
    pub(crate) fn id(&self) -> Id {
        deterministic_id("agf.semantic-cache.profile.v1", &self.sql.h.tenant.to_string())
    }
}
pub(crate) async fn joined(mut task: JoinHandle<Resp>) -> DomainResult<Resp> {
    match tokio::time::timeout(std::time::Duration::from_secs(20), &mut task).await {
        Ok(response) => response.map_err(|_| invalid()),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(invalid())
        }
    }
}
pub(crate) fn invalid() -> DomainError {
    DomainError::Internal("Owned semantic profile fixture boundary failed".into())
}
pub(crate) fn sql_error(error: sqlx::Error) -> DomainError {
    agf_storage::map_sqlx_err("owned_semantic_profile_fixture", &error)
}
