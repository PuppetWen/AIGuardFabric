use super::{AuditAnchorSigner, invalid, sql};
use crate::{TenantTransaction, map_sqlx_err};
use agf_core::{
    audit::{
        AgentAuditAcknowledgement, AgentAuditBatch, AuditChainKind, AuditLog, GENESIS_HASH, SignedAuditAnchor,
        verify_agent_segment,
    },
    error::DomainResult,
    ids::Id,
};
use sqlx::Row;

/// 获取 Agent 追加锁，供调用方在等待结束后执行同事务身份围栏。
///
/// # Errors
/// Agent 身份无效或数据库锁失败。
pub async fn lock_agent_chain(tx: &mut TenantTransaction<'_>, agent: Id) -> DomainResult<()> {
    if agent.is_nil() {
        return Err(invalid());
    }
    sql::lock(tx, Some(agent)).await
}

/// 原子追加已绑定 Agent 的完整连续记录段及签名检查点。
/// 调用方先提交事务，再推进外部见证并返回确认。
///
/// # Errors
/// 已认证链、前序检查点、存储历史、载荷或签名无效。
pub async fn append_agent(
    tx: &mut TenantTransaction<'_>,
    signer: &AuditAnchorSigner,
    agent: Id,
    batch: &AgentAuditBatch,
    witness: Option<&SignedAuditAnchor>,
) -> DomainResult<AgentAuditAcknowledgement> {
    if agent.is_nil() || batch.chain_id.is_nil() {
        return Err(invalid());
    }
    lock_agent_chain(tx, agent).await?;
    // 已绑定的 Agent 仅拥有一条链，删除本地状态不得静默重置服务端链。
    let other: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM audit_chain_anchors WHERE chain_kind='agent-runtime' AND agent_id=$1 AND chain_id<>$2)")
        .bind(agent.as_uuid()).bind(batch.chain_id.as_uuid()).fetch_one(&mut **tx).await
        .map_err(|error|map_sqlx_err("agent_audit_chain_identity",&error))?;
    if other {
        return Err(invalid());
    }
    let (latest, _) =
        sql::verify_checkpoint_history(tx, signer, AuditChainKind::AgentRuntime, Some(agent), batch.chain_id, witness)
            .await?;
    verify_entries(tx, agent, batch.chain_id, latest.as_ref()).await?;
    if let Some(previous) = &batch.previous {
        signer.verify(previous, tx.tenant(), AuditChainKind::AgentRuntime, Some(agent))?;
        if previous.chain_id != batch.chain_id {
            return Err(invalid());
        }
    }
    let (start, hash) = batch
        .previous
        .as_ref()
        .map_or((0, GENESIS_HASH), |value| (value.anchor.up_to_sequence, value.anchor.tail_hash.as_str()));
    let (end, tail) = verify_agent_segment(&batch.entries, tx.tenant(), agent, start, hash)?;
    if let Some(current) = latest.as_ref() {
        if current.anchor.up_to_sequence == end && current.anchor.tail_hash == tail {
            verify_replay(tx, agent, batch).await?;
            return Ok(AgentAuditAcknowledgement { checkpoint: current.clone(), durable: true, replayed: true });
        }
        if batch.previous.as_ref().map(SignedAuditAnchor::witness_hash) != Some(current.witness_hash()) {
            return Err(invalid());
        }
        if batch.entries.is_empty() {
            return Err(invalid());
        }
    } else if batch.previous.is_some() || !batch.entries.is_empty() {
        // 初始化从已认证凭据取得租户及资产身份。
        return Err(invalid());
    }
    for entry in &batch.entries {
        sqlx::query("INSERT INTO agent_runtime_audit_entries(id,tenant_id,agent_id,chain_id,sequence,entry_hash,payload) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(entry.id.as_uuid()).bind(tx.tenant().as_uuid()).bind(agent.as_uuid()).bind(batch.chain_id.as_uuid())
            .bind(entry.sequence).bind(&entry.entry_hash).bind(serde_json::to_string(entry)?)
            .execute(&mut **tx).await.map_err(|error|map_sqlx_err("append_agent_audit",&error))?;
    }
    let checkpoint =
        sql::make(tx, signer, AuditChainKind::AgentRuntime, batch.chain_id, Some(agent), (end, tail), latest.as_ref())
            .await?;
    sql::insert(tx, &checkpoint).await?;
    Ok(AgentAuditAcknowledgement { checkpoint, durable: true, replayed: false })
}

async fn verify_replay(tx: &mut TenantTransaction<'_>, agent: Id, batch: &AgentAuditBatch) -> DomainResult<()> {
    for entry in &batch.entries {
        let payload: Option<String> = sqlx::query_scalar(
            "SELECT payload FROM agent_runtime_audit_entries WHERE agent_id=$1 AND chain_id=$2 AND sequence=$3",
        )
        .bind(agent.as_uuid())
        .bind(batch.chain_id.as_uuid())
        .bind(entry.sequence)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| map_sqlx_err("replay_agent_audit", &error))?;
        if payload.as_deref() != Some(serde_json::to_string(entry)?.as_str()) {
            return Err(invalid());
        }
    }
    Ok(())
}

async fn verify_entries(
    tx: &mut TenantTransaction<'_>,
    agent: Id,
    chain: Id,
    latest: Option<&SignedAuditAnchor>,
) -> DomainResult<()> {
    let mut sequence = 0;
    let mut hash = GENESIS_HASH.to_owned();
    loop {
        let rows=sqlx::query("SELECT id,sequence,entry_hash,payload FROM agent_runtime_audit_entries WHERE agent_id=$1 AND chain_id=$2 AND sequence>$3 ORDER BY sequence LIMIT 256")
            .bind(agent.as_uuid()).bind(chain.as_uuid()).bind(sequence).fetch_all(&mut **tx).await
            .map_err(|error|map_sqlx_err("verify_agent_audit",&error))?;
        if rows.is_empty() {
            break;
        }
        let mut entries = Vec::with_capacity(rows.len());
        for row in rows {
            let entry: AuditLog = serde_json::from_str(&row.try_get::<String, _>("payload").map_err(|_| invalid())?)?;
            if row.try_get::<uuid::Uuid, _>("id").map_err(|_| invalid())? != entry.id.as_uuid()
                || row.try_get::<i64, _>("sequence").map_err(|_| invalid())? != entry.sequence
                || row.try_get::<String, _>("entry_hash").map_err(|_| invalid())? != entry.entry_hash
            {
                return Err(invalid());
            }
            entries.push(entry);
        }
        (sequence, hash) = verify_agent_segment(&entries, tx.tenant(), agent, sequence, &hash)?;
    }
    let (expected, tail) =
        latest.map_or((0, GENESIS_HASH), |anchor| (anchor.anchor.up_to_sequence, anchor.anchor.tail_hash.as_str()));
    if sequence != expected || hash != tail {
        return Err(invalid());
    }
    // 检查每一个签名前缀，不能只校验最近的链尾。
    let mut after = -1;
    loop {
        let checkpoints = sql::page(tx, AuditChainKind::AgentRuntime, Some(agent), chain, after).await?;
        if checkpoints.is_empty() {
            break;
        }
        for checkpoint in checkpoints {
            if checkpoint.anchor.up_to_sequence > 0 {
                let stored:Option<String>=sqlx::query_scalar("SELECT entry_hash FROM agent_runtime_audit_entries WHERE agent_id=$1 AND chain_id=$2 AND sequence=$3")
                    .bind(agent.as_uuid()).bind(chain.as_uuid()).bind(checkpoint.anchor.up_to_sequence)
                    .fetch_optional(&mut **tx).await.map_err(|error|map_sqlx_err("verify_agent_prefix",&error))?;
                if stored.as_deref() != Some(checkpoint.anchor.tail_hash.as_str()) {
                    return Err(invalid());
                }
            }
            after = checkpoint.anchor.up_to_sequence;
        }
    }
    Ok(())
}
