use super::*;
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned AGF_AUDIT_ANCHOR_DATABASE_OWNER, AGF_AUDIT_ANCHOR_DATA_DIR and AGF_TEST_DATABASE_URL"]
async fn agent_entries_and_checkpoint_rollback_together_then_exact_retry_survives_fresh_state() -> DomainResult<()> {
    let owned = Owned::open("anchor-agent-atomic").await?;
    let h = &owned.case.h;
    let (key, agent) = key(h).await;
    let mut batch = AgentAuditBatch { chain_id: Id::new(), previous: None, entries: Vec::new() };
    let bootstrap = append(h, &key, &batch).await;
    assert_eq!(bootstrap.status, StatusCode::OK, "{}", bootstrap.text);
    assert_eq!(bootstrap.json()["durable"], true);
    let previous: SignedAuditAnchor = serde_json::from_value(bootstrap.json()["checkpoint"].clone())?;
    let mut entry = record(h.tenant);
    entry.actor.id = Some(agent);
    entry.actor.kind = "agent".into();
    entry.sequence = 1;
    entry.seal();
    batch.entries.push(entry);
    batch.previous = Some(previous.clone());
    let fault = format!("owned_anchor_failure_{}", Id::new().as_uuid().simple());
    owned.verify().await?;
    let absent: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM pg_proc WHERE proname=$1) AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgname=$1)")
        .bind(&fault).fetch_one(&owned.case.pool).await.unwrap();
    assert!(absent);
    // CHECK 违反属于输入校验错误；这里注入仅本租户非空检查点的持久化故障。
    let result = AssertUnwindSafe(async {
        sqlx::query(&format!("CREATE FUNCTION {fault}() RETURNS trigger LANGUAGE plpgsql AS $owned$ BEGIN IF NEW.tenant_id='{}'::uuid AND NEW.up_to_sequence>0 THEN RAISE EXCEPTION USING ERRCODE='XX000',MESSAGE='owned anchor persistence fault'; END IF; RETURN NEW; END; $owned$",h.tenant)).execute(&owned.case.pool).await.unwrap();
        sqlx::query(&format!("CREATE TRIGGER {fault} BEFORE INSERT ON audit_chain_anchors FOR EACH ROW EXECUTE FUNCTION {fault}()"))
            .execute(&owned.case.pool).await.unwrap();
        let failed = append(h, &key, &batch).await;
        assert!(failed.status.is_server_error(), "{} {}", failed.status, failed.text);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_runtime_audit_entries WHERE tenant_id=$1")
            .bind(h.tenant.as_uuid())
            .fetch_one(&owned.case.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
        assert_eq!(owned.witness(Some(agent))?.read()?.unwrap().witness_hash(), previous.witness_hash());
        Ok::<(), agf_core::error::DomainError>(())
    }).catch_unwind().await;
    // 即使断言或读取失败，也只删除预检不存在、由本用例创建的精确对象。
    let trigger_cleanup =
        sqlx::query(&format!("DROP TRIGGER IF EXISTS {fault} ON audit_chain_anchors")).execute(&owned.case.pool).await;
    let function_cleanup = sqlx::query(&format!("DROP FUNCTION IF EXISTS {fault}()")).execute(&owned.case.pool).await;
    trigger_cleanup.unwrap();
    function_cleanup.unwrap();
    match result {
        Ok(result) => result?,
        Err(panic) => std::panic::resume_unwind(panic),
    }
    let committed = append(h, &key, &batch).await;
    assert_eq!(committed.status, StatusCode::OK, "{}", committed.text);
    // 新 AppState 及配置缓存从 PostgreSQL 读取已提交的协议状态。
    let fresh = owned.fresh().await?;
    // 绑定 Key 本身由数据库提供，保留原租户身份，不使用覆盖参数。
    let retry = append(&fresh, &key, &batch).await;
    assert_eq!(retry.status, StatusCode::OK, "{}", retry.text);
    assert_eq!(retry.json()["replayed"], true);
    assert_eq!(retry.json()["checkpoint"], committed.json()["checkpoint"]);
    let mut forged = batch.clone();
    forged.entries[0].note = "Admin hash rewrite".into();
    forged.entries[0].seal();
    assert!(!append(&fresh, &key, &forged).await.status.is_success());
    Box::pin(super::pool::authority_uses_original_connection(&owned)).await?;
    owned.verify().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned AGF_AUDIT_ANCHOR_DATABASE_OWNER, AGF_AUDIT_ANCHOR_DATA_DIR and AGF_TEST_DATABASE_URL"]
async fn agent_history_rehash_and_foreign_tenant_sql_cannot_bypass_signed_prefix() -> DomainResult<()> {
    let owned = Owned::open("anchor-agent-rls").await?;
    let h = &owned.case.h;
    let (key, agent) = key(h).await;
    let mut batch = AgentAuditBatch { chain_id: Id::new(), previous: None, entries: Vec::new() };
    let bootstrap = append(h, &key, &batch).await;
    assert_eq!(bootstrap.status, StatusCode::OK, "{}", bootstrap.text);
    let previous: SignedAuditAnchor = serde_json::from_value(bootstrap.json()["checkpoint"].clone())?;
    let mut entry = record(h.tenant);
    entry.actor.id = Some(agent);
    entry.actor.kind = "agent".into();
    entry.sequence = 1;
    entry.seal();
    batch.entries.push(entry.clone());
    batch.previous = Some(previous);
    let committed = append(h, &key, &batch).await;
    assert_eq!(committed.status, StatusCode::OK, "{}", committed.text);
    let checkpoint: SignedAuditAnchor = serde_json::from_value(committed.json()["checkpoint"].clone())?;
    let foreign = owned.case.foreign_instance().await;
    let database = h.state.store.database().unwrap();
    let mut tx = database.db().begin_tenant(foreign.tenant).await?;
    let visible: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_runtime_audit_entries WHERE agent_id=$1")
        .bind(agent.as_uuid())
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(visible, 0);
    let anchors: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_chain_anchors WHERE agent_id=$1")
        .bind(agent.as_uuid())
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(anchors, 0);
    let denied=sqlx::query("INSERT INTO agent_runtime_audit_entries(id,tenant_id,agent_id,chain_id,sequence,entry_hash,payload) VALUES($1,$2,$3,$4,9,$5,$6)")
        .bind(Id::new().as_uuid()).bind(h.tenant.as_uuid()).bind(agent.as_uuid()).bind(batch.chain_id.as_uuid()).bind(&entry.entry_hash).bind(serde_json::to_string(&entry)?).execute(&mut *tx).await;
    assert!(denied.is_err());
    tx.rollback().await?;
    entry.note = "Database administrator rewrote and rehashed one complete local record".into();
    entry.seal();
    sqlx::query("UPDATE agent_runtime_audit_entries SET entry_hash=$1,payload=$2 WHERE tenant_id=$3 AND id=$4")
        .bind(&entry.entry_hash)
        .bind(serde_json::to_string(&entry)?)
        .bind(h.tenant.as_uuid())
        .bind(entry.id.as_uuid())
        .execute(&owned.case.pool)
        .await
        .unwrap();
    let mut next = record(h.tenant);
    next.actor.id = Some(agent);
    next.actor.kind = "agent".into();
    next.sequence = 2;
    next.prev_hash = checkpoint.anchor.tail_hash.clone();
    next.seal();
    let append_tampered = append(
        h,
        &key,
        &AgentAuditBatch { chain_id: batch.chain_id, previous: Some(checkpoint.clone()), entries: vec![next] },
    )
    .await;
    assert!(append_tampered.status.is_server_error());
    assert_eq!(owned.witness(Some(agent))?.read()?.unwrap().witness_hash(), checkpoint.witness_hash());
    owned.verify().await
}
