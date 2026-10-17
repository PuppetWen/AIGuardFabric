//! 管理与 Agent 检查点共用、带身份约束的 SQL 操作。
use super::{AuditAnchorSigner, invalid};
use crate::{TenantTransaction, map_sqlx_err};
use agf_core::{
    audit::{AuditChainAnchor, AuditChainKind, SignedAuditAnchor},
    error::DomainResult,
    ids::{Id, TenantId},
    time::Timestamp,
};
use sqlx::{Row, postgres::PgRow};

pub(super) async fn lock(tx: &mut TenantTransaction<'_>, agent: Option<Id>) -> DomainResult<()> {
    let name =
        agent.map_or_else(|| format!("{}:audit-chain", tx.tenant()), |id| format!("{}:agent-audit:{id}", tx.tenant()));
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(name)
        .execute(&mut **tx)
        .await
        .map_err(|error| map_sqlx_err("audit_anchor_lock", &error))?;
    Ok(())
}

/// 读取指定已认证审计链的最近签名检查点。
///
/// # Errors
/// SQL 执行或解码失败，或 SQL 列与封装中的重复字段不一致。
pub async fn latest_anchor(
    tx: &mut TenantTransaction<'_>,
    kind: AuditChainKind,
    agent: Option<Id>,
    chain: Id,
) -> DomainResult<Option<SignedAuditAnchor>> {
    let row = sqlx::query("SELECT * FROM audit_chain_anchors WHERE chain_kind=$1 AND chain_id=$2 AND agent_id IS NOT DISTINCT FROM $3 AND signed_envelope IS NOT NULL ORDER BY up_to_sequence DESC LIMIT 1")
        .bind(kind.as_str()).bind(chain.as_uuid()).bind(agent.map(|id| id.as_uuid()))
        .fetch_optional(&mut **tx).await.map_err(|error| map_sqlx_err("latest_audit_anchor", &error))?;
    row.as_ref().map(decode).transpose()
}

pub(super) async fn page(
    tx: &mut TenantTransaction<'_>,
    kind: AuditChainKind,
    agent: Option<Id>,
    chain: Id,
    after: i64,
) -> DomainResult<Vec<SignedAuditAnchor>> {
    let rows = sqlx::query("SELECT * FROM audit_chain_anchors WHERE chain_kind=$1 AND chain_id=$2 AND agent_id IS NOT DISTINCT FROM $3 AND signed_envelope IS NOT NULL AND up_to_sequence>$4 ORDER BY up_to_sequence LIMIT 1000")
        .bind(kind.as_str()).bind(chain.as_uuid()).bind(agent.map(|id| id.as_uuid())).bind(after)
        .fetch_all(&mut **tx).await.map_err(|error| map_sqlx_err("page_audit_anchors", &error))?;
    rows.iter().map(decode).collect()
}

fn decode(row: &PgRow) -> DomainResult<SignedAuditAnchor> {
    let envelope: SignedAuditAnchor =
        serde_json::from_str(&row.try_get::<String, _>("signed_envelope").map_err(|_| invalid())?)?;
    let anchor = &envelope.anchor;
    let timestamp: chrono::DateTime<chrono::Utc> = row.try_get("created_at").map_err(|_| invalid())?;
    if row.try_get::<uuid::Uuid, _>("id").map_err(|_| invalid())? != anchor.id.as_uuid()
        || row.try_get::<uuid::Uuid, _>("tenant_id").map_err(|_| invalid())? != anchor.tenant_id.as_uuid()
        || row.try_get::<uuid::Uuid, _>("chain_id").map_err(|_| invalid())? != envelope.chain_id.as_uuid()
        || row.try_get::<Option<uuid::Uuid>, _>("agent_id").map_err(|_| invalid())?
            != envelope.agent_id.map(|id| id.as_uuid())
        || row.try_get::<String, _>("chain_kind").map_err(|_| invalid())? != envelope.kind.as_str()
        || row.try_get::<i64, _>("up_to_sequence").map_err(|_| invalid())? != anchor.up_to_sequence
        || row.try_get::<i64, _>("entry_count").map_err(|_| invalid())? != anchor.entry_count
        || row.try_get::<String, _>("tail_hash").map_err(|_| invalid())? != anchor.tail_hash
        || row.try_get::<String, _>("signature").map_err(|_| invalid())? != anchor.signature
        || timestamp != anchor.created_at.as_datetime()
    {
        return Err(invalid());
    }
    Ok(envelope)
}

pub(super) async fn make(
    tx: &mut TenantTransaction<'_>,
    signer: &AuditAnchorSigner,
    kind: AuditChainKind,
    chain: Id,
    agent: Option<Id>,
    position: (i64, String),
    previous: Option<&SignedAuditAnchor>,
) -> DomainResult<SignedAuditAnchor> {
    let now: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await
        .map_err(|error| map_sqlx_err("audit_anchor_time", &error))?;
    let mut envelope = SignedAuditAnchor {
        kind,
        chain_id: chain,
        agent_id: agent,
        previous_anchor_id: previous.map(|old| old.anchor.id),
        previous_anchor_hash: previous.map(SignedAuditAnchor::witness_hash),
        anchor: AuditChainAnchor {
            id: Id::new(),
            tenant_id: tx.tenant(),
            up_to_sequence: position.0,
            tail_hash: position.1,
            entry_count: position.0,
            created_at: Timestamp::from_datetime(now),
            signature: String::new(),
        },
    };
    envelope.follows(previous)?;
    signer.sign(&mut envelope)?;
    Ok(envelope)
}

pub(super) async fn insert(tx: &mut TenantTransaction<'_>, envelope: &SignedAuditAnchor) -> DomainResult<()> {
    let anchor = &envelope.anchor;
    sqlx::query("INSERT INTO audit_chain_anchors(id,tenant_id,up_to_sequence,tail_hash,entry_count,signature,created_at,chain_kind,chain_id,agent_id,signed_envelope) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
        .bind(anchor.id.as_uuid()).bind(anchor.tenant_id.as_uuid()).bind(anchor.up_to_sequence).bind(&anchor.tail_hash)
        .bind(anchor.entry_count).bind(&anchor.signature).bind(anchor.created_at.as_datetime()).bind(envelope.kind.as_str())
        .bind(envelope.chain_id.as_uuid()).bind(envelope.agent_id.map(|id| id.as_uuid())).bind(serde_json::to_string(envelope)?)
        .execute(&mut **tx).await.map_err(|error|map_sqlx_err("insert_audit_anchor", &error))?;
    Ok(())
}

pub(super) async fn verify_checkpoint_history(
    tx: &mut TenantTransaction<'_>,
    signer: &AuditAnchorSigner,
    kind: AuditChainKind,
    agent: Option<Id>,
    chain: Id,
    witness: Option<&SignedAuditAnchor>,
) -> DomainResult<(Option<SignedAuditAnchor>, usize)> {
    let tenant: TenantId = tx.tenant();
    if let Some(value) = witness {
        signer.verify(value, tenant, kind, agent)?;
        if value.chain_id != chain {
            return Err(invalid());
        }
    }
    let mut found = witness.is_none();
    let mut count = 0;
    let mut last: Option<SignedAuditAnchor> = None;
    let mut cursor = -1;
    loop {
        let rows = page(tx, kind, agent, chain, cursor).await?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            signer.verify(&row, tenant, kind, agent)?;
            row.follows(last.as_ref())?;
            if last.is_none() && kind == AuditChainKind::AgentRuntime && row.anchor.up_to_sequence != 0 {
                return Err(invalid());
            }
            if witness.is_some_and(|value| value.witness_hash() == row.witness_hash()) {
                found = true;
            }
            cursor = row.anchor.up_to_sequence;
            last = Some(row);
            count += 1;
        }
        if cursor == i64::MAX {
            break;
        }
    }
    if !found {
        return Err(invalid());
    }
    Ok((last, count))
}
