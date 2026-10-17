//! 以数据库实际 advisory wait 作为同步点，不能用固定 sleep 猜测撤 Key 时序。
use super::*;
use agf_core::error::DomainError;

struct Pending(tokio::task::JoinHandle<Resp>);
impl Drop for Pending {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) async fn revoked_during_audit_wait(owned: &Owned, h: &Harness) -> DomainResult<()> {
    owned.verify().await?;
    let (id, key) = bound_key(h).await;
    let before = snapshot(h).await;
    let mut blocker = owned.case.pool.begin().await.map_err(sql)?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *blocker).await.map_err(sql)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("{}:audit-chain", h.tenant))
        .execute(&mut *blocker)
        .await
        .map_err(sql)?;
    let request = h.clone();
    let mut pending = Pending(tokio::spawn(async move {
        request
            .request_with(
                "POST",
                "/api/v1/runtime/mcp/check",
                &[("X-AGF-Key", &key)],
                Some(json!({"session_id":"owned-audit-wait-revoke",
                "frame":{"jsonrpc":"2.0","id":1,"method":"tools/list"}})),
            )
            .await
    }));
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity
                WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))
                AND query LIKE '%pg_advisory_xact_lock%')",
            )
            .bind(pid)
            .fetch_one(&owned.case.pool)
            .await
            .map_err(sql)?;
            if waiting {
                return Ok::<(), DomainError>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("真实 MCP 路由必须到达本 Owned 连接持有的审计锁")?;
    // 直接改本用例的精确 Key 行；调用公开撤销路由会等待同一审计锁，不能用来建立此时序。
    let changed = sqlx::query("UPDATE api_keys SET revoked=true WHERE tenant_id=$1 AND id=$2")
        .bind(h.tenant.as_uuid())
        .bind(id.as_uuid())
        .execute(&mut *blocker)
        .await
        .map_err(sql)?;
    assert_eq!(changed.rows_affected(), 1);
    blocker.commit().await.map_err(sql)?;
    let response = tokio::time::timeout(Duration::from_secs(20), &mut pending.0)
        .await
        .expect("撤销后的事务必须结束")
        .expect("Owned 请求任务正常返回");
    assert_eq!(response.status, StatusCode::FORBIDDEN, "{}", response.text);
    assert_ne!(response.json()["allowed"], true);
    assert_eq!(snapshot(h).await, before, "撤 Key 后不得提交事实或管理审计");
    owned.verify().await
}

fn sql(error: sqlx::Error) -> DomainError {
    agf_storage::map_sqlx_err("owned_runtime_authority_wait", &error)
}
