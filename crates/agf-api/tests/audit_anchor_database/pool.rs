//! 原事务身份复核不能借第二条池连接；不同 Agent 的见证锁不能掩盖租户治理锁的饥饿。
use super::*;
use agf_core::{audit::AuditChainKind, error::DomainError};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;

struct Pending(tokio::task::JoinHandle<Resp>);
impl Drop for Pending {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn sql(error: sqlx::Error) -> DomainError {
    agf_storage::map_sqlx_err("audit_anchor_pool_test", &error)
}
async fn identity(pool: &PgPool) -> (String, i64, Option<String>, String, String) {
    sqlx::query_as("SELECT current_database(),oid::bigint,shobj_description(oid,'pg_database'),pg_get_userbyid(datdba),current_user::text FROM pg_database WHERE datname=current_database()")
        .fetch_one(pool).await.unwrap()
}

async fn prepared(h: &Harness) -> DomainResult<(String, Id, AgentAuditBatch)> {
    let fingerprint = format!("owned-anchor-pool-{}", Id::new());
    let response = h
        .post(
            "/api/v1/assets/discovery",
            json!({"source":"agent-report","assets":[{
                "kind":"agent","name":fingerprint,"fingerprint":fingerprint,"endpoint":"127.0.0.1","vendor":"owned"
            }]}),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let agent = h
        .state
        .store
        .asset_list_all(h.tenant)?
        .into_iter()
        .find(|row| row.kind == AssetKind::Agent && row.fingerprint == fingerprint)
        .unwrap()
        .id;
    let response = h
        .post(
            "/api/v1/settings/api-keys",
            json!({
                "name":fingerprint,"scopes":["policies:read"],"bound_agent_id":agent,"expires_in_secs":3600
            }),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
    let key = response.json()["plaintext"].as_str().unwrap().to_owned();
    let initial = AgentAuditBatch { chain_id: Id::new(), previous: None, entries: Vec::new() };
    let bootstrap = Box::pin(append(h, &key, &initial)).await;
    assert_eq!(bootstrap.status, StatusCode::OK, "{}", bootstrap.text);
    let previous: SignedAuditAnchor = serde_json::from_value(bootstrap.json()["checkpoint"].clone())?;
    let mut entry = record(h.tenant);
    entry.actor.id = Some(agent);
    entry.actor.kind = "agent".into();
    entry.sequence = 1;
    entry.prev_hash.clone_from(&previous.anchor.tail_hash);
    entry.seal();
    Ok((key, agent, AgentAuditBatch { chain_id: initial.chain_id, previous: Some(previous), entries: vec![entry] }))
}

async fn committed(owned: &Owned, agent: Id, batch: &AgentAuditBatch, response: &Resp) -> DomainResult<()> {
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.json()["durable"], true);
    assert_eq!(response.json()["replayed"], false);
    let checkpoint: SignedAuditAnchor = serde_json::from_value(response.json()["checkpoint"].clone())?;
    owned.signer()?.verify(&checkpoint, owned.case.h.tenant, AuditChainKind::AgentRuntime, Some(agent))?;
    checkpoint.follows(batch.previous.as_ref())?;
    assert_eq!(checkpoint.anchor.up_to_sequence, 1);
    assert_eq!(checkpoint.anchor.tail_hash, batch.entries[0].entry_hash);
    assert_eq!(owned.witness(Some(agent))?.read()?.unwrap().witness_hash(), checkpoint.witness_hash());
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM agent_runtime_audit_entries WHERE tenant_id=$1 AND agent_id=$2")
            .bind(owned.case.h.tenant.as_uuid())
            .bind(agent.as_uuid())
            .fetch_one(&owned.case.pool)
            .await
            .map_err(sql)?;
    assert_eq!(count, 1);
    Ok(())
}

/// 保留原 exact ignored 名称，在原子回滚/重启用例内串行增加真实 HTTP 子场景。
pub(super) async fn authority_uses_original_connection(owned: &Owned) -> DomainResult<()> {
    owned.verify().await?;
    let h = &owned.case.h;
    let (key, agent, batch) = Box::pin(prepared(h)).await?;
    // SqlCase 明确 max_connections(8)；持有七个连接，只剩一个可供完整认证及提交。
    let mut held = Vec::new();
    for _ in 0..7 {
        held.push(owned.case.pool.acquire().await.map_err(sql)?);
    }
    let response = tokio::time::timeout(Duration::from_secs(15), Box::pin(append(h, &key, &batch)))
        .await
        .expect("只剩一条池连接时，真实 Agent 追加不得借第二条连接");
    drop(held);
    committed(owned, agent, &batch, &response).await?;
    Box::pin(different_agents(owned)).await?;
    owned.verify().await
}

async fn different_agents(owned: &Owned) -> DomainResult<()> {
    let h = &owned.case.h;
    let first = Box::pin(prepared(h)).await?;
    let second = Box::pin(prepared(h)).await?;
    assert_ne!(first.1, second.1, "必须是不同 Agent，不能被同一见证 try_lock 提前拒绝");
    owned.verify().await?;
    let expected = identity(&owned.case.pool).await;
    // 仅在现有 Owned 身份校验后连接同一字面 loopback URL；不迁移、不创建数据库。
    let observer = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("AGF_TEST_DATABASE_URL").unwrap())
        .await
        .map_err(sql)?;
    assert_eq!(identity(&observer).await, expected, "观察连接必须具有相同 OID、COMMENT 及 owner");
    let mut blocker = observer.begin().await.map_err(sql)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("agf.asset-governance:{}", h.tenant))
        .execute(&mut *blocker)
        .await
        .map_err(sql)?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *blocker).await.map_err(sql)?;
    // 原应用池仅剩两条连接，两个不同 Agent 必须各持一条事务并等待同一个治理锁。
    let mut held = Vec::new();
    for _ in 0..6 {
        held.push(owned.case.pool.acquire().await.map_err(sql)?);
    }
    let (key1, agent1, batch1) = first;
    let (key2, agent2, batch2) = second;
    let request1 = ((*h).clone(), key1, batch1.clone());
    let request2 = ((*h).clone(), key2, batch2.clone());
    let mut pending1 =
        Pending(tokio::spawn(Box::pin(async move { Box::pin(append(&request1.0, &request1.1, &request1.2)).await })));
    let mut pending2 =
        Pending(tokio::spawn(Box::pin(async move { Box::pin(append(&request2.0, &request2.1, &request2.2)).await })));
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            // 同一持锁事务内必须丢弃统计快照，否则首次未等待的活动视图可能一直缓存。
            sqlx::query("SELECT pg_stat_clear_snapshot()")
                .execute(&mut *blocker).await.map_err(sql)?;
            let waiting: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%pg_advisory_xact_lock%'")
                .bind(pid).fetch_one(&mut *blocker).await.map_err(sql)?;
            if waiting == 2 { return Ok::<_, DomainError>(()); }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await.expect("必须实际观测两个不同 Agent 持有应用池连接等待本用例治理锁")?;
    assert_eq!(owned.case.pool.num_idle(), 0, "释放治理锁前应用池不得有额外可借连接");
    blocker.commit().await.map_err(sql)?;
    // 第一位提交者仍与另一位等待者共同占满池；同事务复核须完成后才可释放连接。
    let response1 = tokio::time::timeout(Duration::from_secs(15), &mut pending1.0)
        .await
        .expect("第一位不同 Agent 不得因第二次借连接饥饿")
        .unwrap();
    let response2 = tokio::time::timeout(Duration::from_secs(15), &mut pending2.0)
        .await
        .expect("第二位不同 Agent 必须在治理锁释放后提交")
        .unwrap();
    drop(held);
    committed(owned, agent1, &batch1, &response1).await?;
    committed(owned, agent2, &batch2, &response2).await?;
    assert_eq!(identity(&observer).await, expected);
    observer.close().await;
    Ok(())
}
