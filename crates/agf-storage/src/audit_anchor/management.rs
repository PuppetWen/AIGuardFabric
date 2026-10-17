//! 持有既有追加锁，仅为已验证且已提交的管理链建立检查点。
use super::{AnchoredChainVerification, AuditAnchorSigner, invalid, sql};
use crate::{AuditRepo, TenantTransaction};
use agf_core::{
    audit::{AuditChainKind, ChainVerifier, GENESIS_HASH, SignedAuditAnchor},
    error::DomainResult,
    ids::Id,
};

/// 验证完整已提交链及全部签名检查点，不创建检查点。
///
/// # Errors
/// SQL 执行或存储封装解码失败，或外部见证不可信。
pub async fn verify_management(
    tx: &mut TenantTransaction<'_>,
    signer: &AuditAnchorSigner,
    witness: Option<&SignedAuditAnchor>,
) -> DomainResult<AnchoredChainVerification> {
    sql::lock(tx, None).await?;
    verify_locked(tx, signer, witness).await
}

async fn verify_locked(
    tx: &mut TenantTransaction<'_>,
    signer: &AuditAnchorSigner,
    witness: Option<&SignedAuditAnchor>,
) -> DomainResult<AnchoredChainVerification> {
    let chain = Id::from_uuid(tx.tenant().as_uuid());
    let (latest, anchors_checked) =
        sql::verify_checkpoint_history(tx, signer, AuditChainKind::Management, None, chain, witness).await?;
    let unsigned:i64=sqlx::query_scalar("SELECT COUNT(*) FROM audit_chain_anchors WHERE chain_kind='management' AND chain_id=$1 AND signed_envelope IS NULL")
        .bind(chain.as_uuid()).fetch_one(&mut **tx).await.map_err(|error|crate::map_sqlx_err("unsigned_audit_anchors",&error))?;
    let unsigned_legacy_checkpoints = usize::try_from(unsigned).map_err(|_| invalid())?;
    let mut verifier = ChainVerifier::new();
    let mut cursor = 0;
    loop {
        let rows = AuditRepo::load_chain(tx, cursor, 1000).await?;
        if rows.is_empty() {
            break;
        }
        for row in &rows {
            verifier.push(row);
        }
        let last = rows.last().map_or(cursor, |row| row.sequence);
        if rows.len() < 1000 || last == i64::MAX {
            break;
        }
        cursor = last.checked_add(1).ok_or_else(invalid)?;
    }
    let chain_report = verifier.finish();
    let mut violations = Vec::new();
    let mut anchor_cursor = -1;
    loop {
        let anchors = sql::page(tx, AuditChainKind::Management, None, chain, anchor_cursor).await?;
        if anchors.is_empty() {
            break;
        }
        for envelope in anchors {
            let anchor = &envelope.anchor;
            let matching = if anchor.up_to_sequence == 0 {
                anchor.tail_hash == GENESIS_HASH
            } else {
                AuditRepo::load_chain(tx, anchor.up_to_sequence, 1).await?.first().is_some_and(|entry| {
                    entry.sequence == anchor.up_to_sequence && entry.entry_hash == anchor.tail_hash && entry.verify()
                })
            };
            if !matching {
                violations.push(format!("Checkpoint {} does not match its committed record", anchor.id));
            }
            anchor_cursor = anchor.up_to_sequence;
        }
        if anchor_cursor == i64::MAX {
            break;
        }
    }
    let fully_anchored = latest.as_ref().is_some_and(|value| {
        value.anchor.up_to_sequence == chain_report.last_sequence.unwrap_or(0)
            && witness.is_some_and(|saved| saved.witness_hash() == value.witness_hash())
    }) && chain_report.passed
        && violations.is_empty();
    Ok(AnchoredChainVerification {
        chain: chain_report,
        anchors_valid: violations.is_empty(),
        anchors_checked,
        unsigned_legacy_checkpoints,
        latest,
        fully_anchored,
        violations,
    })
}

/// 创建明确的首个检查点，或推进既有签名链。
/// 调用方仅在事务提交后保存外部见证。
///
/// # Errors
/// 哈希链、任一检查点、见证或 SQL 操作无效。
pub async fn checkpoint_management(
    tx: &mut TenantTransaction<'_>,
    signer: &AuditAnchorSigner,
    witness: Option<&SignedAuditAnchor>,
) -> DomainResult<SignedAuditAnchor> {
    sql::lock(tx, None).await?;
    let checked = verify_locked(tx, signer, witness).await?;
    if !checked.chain.passed || !checked.anchors_valid {
        return Err(invalid());
    }
    let (count, tail) = AuditRepo::chain_stats(tx).await?;
    if count != checked.chain.last_sequence.unwrap_or(0) || usize::try_from(count).ok() != Some(checked.chain.checked) {
        return Err(invalid());
    }
    if let Some(latest) = &checked.latest {
        if latest.anchor.up_to_sequence == count {
            return Ok(latest.clone());
        }
    }
    let chain = Id::from_uuid(tx.tenant().as_uuid());
    let anchor =
        sql::make(tx, signer, AuditChainKind::Management, chain, None, (count, tail), checked.latest.as_ref()).await?;
    sql::insert(tx, &anchor).await?;
    Ok(anchor)
}
