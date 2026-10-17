//! Reuse exact-owner SQL and a genuine priced HTTP provider, never their test functions.
use crate::common::*;
mod ownership;
pub(crate) use ownership::{Owned, invalid};
use ownership::{Ownership, sql};
use sqlx::PgPool;
// The reused fault helper contains no tests; the old feature test subtree is not registered.
#[path = "../gateway_settlement_database_support/fault.rs"]
mod fault;
use agf_core::{error::DomainResult, ids::Id};
pub(crate) use fault::{AuditFault, with_fault};
pub(crate) const LOOKUP: &str = "/api/v1/gateway/attempts/by-idempotency-key";
pub(crate) const INDEX: &str = "gateway-admission-key-v1";
pub(crate) const CAPACITY: &str = "gateway-admission-key-capacity-v1";
mod gate;
pub(crate) use gate::Gate;
mod authority;
pub(crate) use authority::{short_token, wait_expired};
pub(crate) fn body(text: &str) -> Value {
    json!({"model":crate::agentteams_quota_scope_support::MODEL,"messages":[{"role":"user","content":text}],
        "temperature":0.7,"max_tokens":16})
}
pub(crate) async fn post(h: &Harness, token: &str, key: &str, path: &str, body: Value) -> Resp {
    let bearer = format!("Bearer {token}");
    h.request_with("POST", path, &[("authorization", bearer.as_str()), ("idempotency-key", key)], Some(body)).await
}
pub(crate) async fn lookup(h: &Harness, token: &str, key: &str) -> Resp {
    let bearer = format!("Bearer {token}");
    h.request_with("GET", LOOKUP, &[("authorization", bearer.as_str()), ("idempotency-key", key)], None).await
}
pub(crate) fn attempt(response: &Resp) -> DomainResult<Id> {
    Id::parse(&response.header("x-agf-attempt-id")).map_err(|_| invalid())
}
pub(crate) async fn by_key(h: &Harness, key: &str, method: &str, id: Id, body: Option<Value>) -> Resp {
    let bearer = format!("Bearer {key}");
    let path = format!("/api/v1/gateway/attempts/{id}{}", if method == "POST" { "/recover" } else { "" });
    h.request_with(method, &path, &[("authorization", bearer.as_str())], body).await
}
pub(crate) async fn terminal_count(h: &Harness, id: Id) -> DomainResult<usize> {
    let rows = h.state.store.audit_chain_durable(h.tenant, 0, i64::MAX).await?;
    Ok(rows
        .iter()
        .filter(|row| row.target.kind == "gateway-attempt" && row.target.id.as_deref() == Some(id.to_string().as_str()))
        .count())
}
pub(crate) async fn rows(owned: &Owned) -> DomainResult<Value> {
    owned.ownership.verify(&owned.case.pool).await?;
    let keys: Vec<(String,uuid::Uuid,Value,Option<chrono::DateTime<chrono::Utc>>)> = sqlx::query_as(
        "SELECT kind,id,payload,deleted_at FROM console_configurations WHERE tenant_id=$1 AND kind=ANY($2) ORDER BY kind,id")
        .bind(owned.case.h.tenant.as_uuid()).bind(vec![INDEX,CAPACITY]).fetch_all(&owned.case.pool).await
            .map_err(|error|agf_storage::map_sqlx_err("owned_admission_key_snapshot",&error))?;
    Ok(json!({"settlement":owned.rows().await?,"keys":keys}))
}

pub(crate) struct Pending(Option<tokio::task::JoinHandle<Resp>>);
impl Pending {
    pub(crate) fn start(h: Harness, token: String, key: &'static str, body: Value) -> Self {
        Self(Some(tokio::spawn(async move { post(&h, &token, key, "/v1/chat/completions", body).await })))
    }
    pub(crate) async fn finish(mut self) -> Resp {
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(20), self.0.as_mut().unwrap()).await.unwrap().unwrap();
        self.0.take();
        result
    }
    pub(crate) async fn cancel(mut self) {
        let task = self.0.take().unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}
