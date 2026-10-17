use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned AGF_AUDIT_ANCHOR_DATABASE_OWNER, AGF_AUDIT_ANCHOR_DATA_DIR and AGF_TEST_DATABASE_URL"]
async fn management_first_checkpoint_restart_and_whole_chain_rehash_are_distinguished() -> DomainResult<()> {
    let owned = Owned::open("anchor-rehash").await?;
    add(&owned).await?;
    sqlx::query("INSERT INTO audit_chain_anchors(id,tenant_id,chain_id,up_to_sequence,tail_hash,entry_count,signature) VALUES($1,$2,$2,0,$3,0,'unsigned-legacy')")
        .bind(Id::new().as_uuid()).bind(owned.case.h.tenant.as_uuid()).bind(GENESIS_HASH).execute(&owned.case.pool).await.unwrap();
    let initial = owned.case.h.get("/api/v1/audit/verify").await;
    assert_eq!(initial.json()["anchoring"]["initial_checkpoint_required"], true);
    assert_eq!(initial.json()["anchoring"]["unsigned_legacy_checkpoints"], 1);
    let mut signed = owned.checkpoint().await?;
    let verified = owned.case.h.get("/api/v1/audit/verify").await;
    assert_eq!(verified.status, StatusCode::OK, "{}", verified.text);
    assert_eq!(verified.json()["anchoring"]["fully_anchored"], true);
    let fresh = owned.fresh().await?;
    assert_eq!(fresh.get("/api/v1/audit/verify").await.json()["anchoring"]["latest"], serde_json::to_value(&signed)?);
    // 模拟数据库已提交、见证尚未写入的崩溃窗口：祖先见证仍有效，但不是完全锚定。
    add(&owned).await?;
    let witness = owned.witness(None)?;
    let previous = witness.read()?;
    let signer = owned.signer()?;
    let database = owned.case.h.state.store.database().unwrap();
    let mut tx = database.db().begin_tenant(owned.case.h.tenant).await?;
    let unwitnessed = agf_storage::audit_anchor::checkpoint_management(&mut tx, &signer, previous.as_ref()).await?;
    tx.commit().await?;
    drop(witness);
    let lagging = fresh.get("/api/v1/audit/verify").await;
    assert_eq!(lagging.status, StatusCode::OK, "{}", lagging.text);
    assert_eq!(lagging.json()["anchoring"]["valid"], true);
    assert_eq!(lagging.json()["anchoring"]["fully_anchored"], false);
    signed = owned.checkpoint().await?;
    assert_eq!(signed.witness_hash(), unwitnessed.witness_hash());
    assert_eq!(fresh.get("/api/v1/audit/verify").await.json()["anchoring"]["fully_anchored"], true);
    let mut rows = owned.case.h.state.store.audit_chain_durable(owned.case.h.tenant, 0, i64::MAX).await?;
    let mut previous = GENESIS_HASH.to_owned();
    for row in &mut rows {
        row.note = "Admin rewrote and rehashed history".into();
        row.prev_hash = previous;
        row.seal();
        previous = row.entry_hash.clone();
        sqlx::query("UPDATE audit_logs SET note=$1,prev_hash=$2,entry_hash=$3 WHERE tenant_id=$4 AND id=$5")
            .bind(&row.note)
            .bind(&row.prev_hash)
            .bind(&row.entry_hash)
            .bind(row.tenant_id.as_uuid())
            .bind(row.id.as_uuid())
            .execute(&owned.case.pool)
            .await
            .unwrap();
    }
    assert!(
        owned.case.h.state.store.audit_verify_durable(owned.case.h.tenant).await?.passed,
        "The attacker made a self-consistent chain"
    );
    let verified = owned.case.h.get("/api/v1/audit/verify").await;
    assert_eq!(verified.status, StatusCode::OK);
    assert_eq!(verified.json()["passed"], false);
    assert_eq!(verified.json()["anchoring"]["valid"], false);
    assert!(owned.checkpoint().await.is_err());
    assert_eq!(owned.witness(None)?.read()?.unwrap().witness_hash(), signed.witness_hash());
    owned.verify().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned AGF_AUDIT_ANCHOR_DATABASE_OWNER, AGF_AUDIT_ANCHOR_DATA_DIR and AGF_TEST_DATABASE_URL"]
async fn deleted_all_database_history_cannot_be_resigned_past_the_external_witness() -> DomainResult<()> {
    let owned = Owned::open("anchor-delete").await?;
    add(&owned).await?;
    let signed = owned.checkpoint().await?;
    for table in ["audit_logs", "audit_chain_anchors"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE tenant_id=$1"))
            .bind(owned.case.h.tenant.as_uuid())
            .execute(&owned.case.pool)
            .await
            .unwrap();
    }
    assert!(owned.checkpoint().await.is_err());
    assert!(owned.case.h.get("/api/v1/audit/verify").await.status.is_server_error());
    assert_eq!(owned.witness(None)?.read()?.unwrap().witness_hash(), signed.witness_hash());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_chain_anchors WHERE tenant_id=$1")
        .bind(owned.case.h.tenant.as_uuid())
        .fetch_one(&owned.case.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    owned.verify().await
}
