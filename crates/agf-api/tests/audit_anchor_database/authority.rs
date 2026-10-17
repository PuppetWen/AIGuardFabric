//! 真实路由已完成入口认证后等待链锁，再改变原身份；不能提交旧 Principal。
use super::*;
use agf_core::error::DomainError;
use std::time::Duration;

#[derive(Clone, Copy)]
enum Change {
    Revoke,
    Tenant,
    Agent,
    Binding,
    Scope,
}
struct Pending(tokio::task::JoinHandle<Resp>);
impl Drop for Pending {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn invalid() -> DomainError {
    DomainError::Internal("独占锚点身份等待回归未达到预期边界".into())
}
fn sql(error: sqlx::Error) -> DomainError {
    agf_storage::map_sqlx_err("audit_anchor_authority_test", &error)
}

async fn wait_then_change(change: Change) -> DomainResult<()> {
    let owned = Owned::open("anchor-authority-wait").await?;
    let h = &owned.case.h;
    let (token, agent) = key(h).await;
    let initial = AgentAuditBatch { chain_id: Id::new(), previous: None, entries: Vec::new() };
    let response = append(h, &token, &initial).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let checkpoint: SignedAuditAnchor = serde_json::from_value(response.json()["checkpoint"].clone())?;
    let key_id = h
        .state
        .store
        .api_key_list_durable(h.tenant)
        .await?
        .into_iter()
        .find(|key| key.bound_agent_id == Some(agent) && key.name == "owned-anchor-agent")
        .ok_or_else(invalid)?
        .id;
    let mut entry = record(h.tenant);
    entry.actor.id = Some(agent);
    entry.actor.kind = "agent".into();
    entry.sequence = 1;
    entry.seal();
    let batch =
        AgentAuditBatch { chain_id: initial.chain_id, previous: Some(checkpoint.clone()), entries: vec![entry] };
    owned.verify().await?;
    let mut blocker = owned.case.pool.begin().await.map_err(sql)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("{}:agent-audit:{agent}", h.tenant))
        .execute(&mut *blocker)
        .await
        .map_err(sql)?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *blocker).await.map_err(sql)?;
    let request_h = (*h).clone();
    let mut pending = Pending(tokio::spawn(async move { append(&request_h, &token, &batch).await }));
    tokio::time::timeout(Duration::from_secs(20),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%pg_advisory_xact_lock%')")
                .bind(pid).fetch_one(&owned.case.pool).await.map_err(sql)?;
            if waiting { return Ok::<_,DomainError>(()); }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await.map_err(|_|invalid())??;
    // 已证明 route 正在本用例精确持有的锁上等待；更改在释放锁前提交。
    let changed = match change {
        Change::Revoke => {
            sqlx::query("UPDATE api_keys SET revoked=true WHERE tenant_id=$1 AND id=$2")
                .bind(h.tenant.as_uuid())
                .bind(key_id.as_uuid())
                .execute(&mut *blocker)
                .await
        }
        Change::Tenant => {
            sqlx::query("UPDATE tenants SET enabled=false,version=version+1 WHERE id=$1")
                .bind(h.tenant.as_uuid())
                .execute(&mut *blocker)
                .await
        }
        Change::Agent => {
            sqlx::query("UPDATE assets SET deleted_at=now() WHERE tenant_id=$1 AND id=$2")
                .bind(h.tenant.as_uuid())
                .bind(agent.as_uuid())
                .execute(&mut *blocker)
                .await
        }
        Change::Binding => {
            sqlx::query("UPDATE api_keys SET bound_agent_id=NULL WHERE tenant_id=$1 AND id=$2")
                .bind(h.tenant.as_uuid())
                .bind(key_id.as_uuid())
                .execute(&mut *blocker)
                .await
        }
        Change::Scope => {
            sqlx::query("UPDATE api_keys SET scopes='[]'::jsonb WHERE tenant_id=$1 AND id=$2")
                .bind(h.tenant.as_uuid())
                .bind(key_id.as_uuid())
                .execute(&mut *blocker)
                .await
        }
    }
    .map_err(sql)?;
    assert_eq!(changed.rows_affected(), 1);
    blocker.commit().await.map_err(sql)?;
    let result = tokio::time::timeout(Duration::from_secs(20), &mut pending.0)
        .await
        .map_err(|_| invalid())?
        .map_err(|_| invalid())?;
    assert_eq!(result.status, StatusCode::FORBIDDEN, "{}", result.text);
    let entries: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM agent_runtime_audit_entries WHERE tenant_id=$1 AND agent_id=$2")
            .bind(h.tenant.as_uuid())
            .bind(agent.as_uuid())
            .fetch_one(&owned.case.pool)
            .await
            .map_err(sql)?;
    let anchors: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_chain_anchors WHERE tenant_id=$1 AND agent_id=$2")
            .bind(h.tenant.as_uuid())
            .bind(agent.as_uuid())
            .fetch_one(&owned.case.pool)
            .await
            .map_err(sql)?;
    assert_eq!(entries, 0);
    assert_eq!(anchors, 1);
    let envelope: String =
        sqlx::query_scalar("SELECT signed_envelope FROM audit_chain_anchors WHERE tenant_id=$1 AND agent_id=$2")
            .bind(h.tenant.as_uuid())
            .bind(agent.as_uuid())
            .fetch_one(&owned.case.pool)
            .await
            .map_err(sql)?;
    let actual: SignedAuditAnchor = serde_json::from_str(&envelope)?;
    assert_eq!(actual.witness_hash(), checkpoint.witness_hash());
    assert_eq!(owned.witness(Some(agent))?.read()?.ok_or_else(invalid)?.witness_hash(), checkpoint.witness_hash());
    owned.verify().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned AGF_AUDIT_ANCHOR_DATABASE_OWNER, AGF_AUDIT_ANCHOR_DATA_DIR and AGF_TEST_DATABASE_URL"]
async fn revoked_original_key_during_chain_lock_wait_cannot_append_or_advance_witness() -> DomainResult<()> {
    wait_then_change(Change::Revoke).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned AGF_AUDIT_ANCHOR_DATABASE_OWNER, AGF_AUDIT_ANCHOR_DATA_DIR and AGF_TEST_DATABASE_URL"]
async fn disabled_tenant_during_chain_lock_wait_cannot_append_or_advance_witness() -> DomainResult<()> {
    wait_then_change(Change::Tenant).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned AGF_AUDIT_ANCHOR_DATABASE_OWNER, AGF_AUDIT_ANCHOR_DATA_DIR and AGF_TEST_DATABASE_URL"]
async fn deleted_bound_agent_during_chain_lock_wait_cannot_append_or_advance_witness() -> DomainResult<()> {
    wait_then_change(Change::Agent).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned AGF_AUDIT_ANCHOR_DATABASE_OWNER, AGF_AUDIT_ANCHOR_DATA_DIR and AGF_TEST_DATABASE_URL"]
async fn removed_original_binding_during_chain_lock_wait_cannot_append_or_advance_witness() -> DomainResult<()> {
    wait_then_change(Change::Binding).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned AGF_AUDIT_ANCHOR_DATABASE_OWNER, AGF_AUDIT_ANCHOR_DATA_DIR and AGF_TEST_DATABASE_URL"]
async fn removed_current_scope_during_chain_lock_wait_cannot_append_or_advance_witness() -> DomainResult<()> {
    wait_then_change(Change::Scope).await
}
