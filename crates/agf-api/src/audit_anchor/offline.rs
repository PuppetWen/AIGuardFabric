//! 明确为临时状态的 Mock 存储，复用生产哈希及签名校验。
use super::{AppState, invalid};
use agf_core::{
    audit::{
        AgentAuditAcknowledgement, AgentAuditBatch, AuditChainAnchor, AuditChainKind, AuditLog, GENESIS_HASH,
        SignedAuditAnchor, verify_agent_segment, verify_chain,
    },
    error::DomainResult,
    ids::{Id, TenantId},
    time::Timestamp,
};
use agf_storage::audit_anchor::{AnchoredChainVerification, AuditAnchorSigner};
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize)]
struct AgentLedger {
    chain: Option<Id>,
    entries: Vec<AuditLog>,
    anchors: Vec<SignedAuditAnchor>,
}
#[derive(Default, Serialize, Deserialize)]
struct ManagementLedger {
    anchors: Vec<SignedAuditAnchor>,
}

pub(super) async fn append(
    state: &AppState,
    signer: &AuditAnchorSigner,
    tenant: TenantId,
    agent: Id,
    batch: AgentAuditBatch,
) -> DomainResult<AgentAuditAcknowledgement> {
    let mut replayed = false;
    let ledger = state
        .configurations
        .mutate::<AgentLedger, _>(tenant, "agent-audit-anchor-mock", agent, |ledger| {
            if batch.chain_id.is_nil() || ledger.chain.is_some_and(|id| id != batch.chain_id) {
                return Err(invalid());
            }
            validate_anchors(signer, tenant, AuditChainKind::AgentRuntime, Some(agent), &ledger.anchors)?;
            let mut sequence = 0;
            let mut hash = GENESIS_HASH.to_owned();
            for chunk in ledger.entries.chunks(256) {
                (sequence, hash) = verify_agent_segment(chunk, tenant, agent, sequence, &hash)?;
            }
            let latest = ledger.anchors.last();
            if latest.is_some_and(|value| value.anchor.up_to_sequence != sequence || value.anchor.tail_hash != hash) {
                return Err(invalid());
            }
            if let Some(previous) = &batch.previous {
                signer.verify(previous, tenant, AuditChainKind::AgentRuntime, Some(agent))?;
                if previous.chain_id != batch.chain_id {
                    return Err(invalid());
                }
            }
            let (start, previous_hash) = batch
                .previous
                .as_ref()
                .map_or((0, GENESIS_HASH), |value| (value.anchor.up_to_sequence, value.anchor.tail_hash.as_str()));
            let (end, tail) = verify_agent_segment(&batch.entries, tenant, agent, start, previous_hash)?;
            if let Some(current) = latest {
                if current.anchor.up_to_sequence == end && current.anchor.tail_hash == tail {
                    for entry in &batch.entries {
                        let stored =
                            ledger.entries.iter().find(|value| value.sequence == entry.sequence).ok_or_else(invalid)?;
                        if serde_json::to_vec(stored)? != serde_json::to_vec(entry)? {
                            return Err(invalid());
                        }
                    }
                    replayed = true;
                    return Ok(());
                }
                if batch.previous.as_ref().map(SignedAuditAnchor::witness_hash) != Some(current.witness_hash())
                    || batch.entries.is_empty()
                {
                    return Err(invalid());
                }
            } else if batch.previous.is_some() || !batch.entries.is_empty() {
                return Err(invalid());
            }
            if ledger.entries.len().saturating_add(batch.entries.len()) > 100_000 {
                return Err(invalid());
            }
            let checkpoint =
                make(signer, tenant, AuditChainKind::AgentRuntime, batch.chain_id, Some(agent), (end, tail), latest)?;
            ledger.chain = Some(batch.chain_id);
            ledger.entries.extend(batch.entries);
            ledger.anchors.push(checkpoint);
            Ok(())
        })
        .await?;
    Ok(AgentAuditAcknowledgement {
        checkpoint: ledger.anchors.last().cloned().ok_or_else(invalid)?,
        durable: false,
        replayed,
    })
}

pub(super) async fn verify(
    state: &AppState,
    signer: &AuditAnchorSigner,
    tenant: TenantId,
) -> DomainResult<AnchoredChainVerification> {
    let rows = state.store.audit_chain_durable(tenant, 0, i64::MAX).await?;
    let ledger = state
        .configurations
        .get::<ManagementLedger>(tenant, "management-audit-anchor-mock", tenant.as_id())
        .await?
        .unwrap_or_default();
    report(signer, tenant, &rows, &ledger)
}

pub(super) async fn checkpoint(state: &AppState, signer: &AuditAnchorSigner, tenant: TenantId) -> DomainResult<()> {
    let rows = state.store.audit_chain_durable(tenant, 0, i64::MAX).await?;
    state
        .configurations
        .mutate::<ManagementLedger, _>(tenant, "management-audit-anchor-mock", tenant.as_id(), |ledger| {
            let checked = report(signer, tenant, &rows, ledger)?;
            if !checked.chain.passed || !checked.anchors_valid {
                return Err(invalid());
            }
            let sequence = checked.chain.last_sequence.unwrap_or(0);
            if ledger.anchors.last().is_some_and(|value| value.anchor.up_to_sequence == sequence) {
                return Ok(());
            }
            let tail = rows.last().map_or_else(|| GENESIS_HASH.to_owned(), |entry| entry.entry_hash.clone());
            let checkpoint = make(
                signer,
                tenant,
                AuditChainKind::Management,
                tenant.as_id(),
                None,
                (sequence, tail),
                ledger.anchors.last(),
            )?;
            ledger.anchors.push(checkpoint);
            Ok(())
        })
        .await?;
    Ok(())
}

fn report(
    signer: &AuditAnchorSigner,
    tenant: TenantId,
    rows: &[AuditLog],
    ledger: &ManagementLedger,
) -> DomainResult<AnchoredChainVerification> {
    validate_anchors(signer, tenant, AuditChainKind::Management, None, &ledger.anchors)?;
    let chain = verify_chain(rows);
    let mut violations = Vec::new();
    for value in &ledger.anchors {
        let anchor = &value.anchor;
        let matches = if anchor.up_to_sequence == 0 {
            anchor.tail_hash == GENESIS_HASH
        } else {
            rows.iter()
                .find(|entry| entry.sequence == anchor.up_to_sequence)
                .is_some_and(|entry| entry.entry_hash == anchor.tail_hash && entry.verify())
        };
        if !matches {
            violations.push(format!("Checkpoint {} does not match its record", anchor.id));
        }
    }
    let latest = ledger.anchors.last().cloned();
    // Mock 没有持久外部见证；签名前缀有效也不能声称已经完全持久锚定。
    Ok(AnchoredChainVerification {
        chain,
        anchors_valid: violations.is_empty(),
        anchors_checked: ledger.anchors.len(),
        unsigned_legacy_checkpoints: 0,
        latest,
        fully_anchored: false,
        violations,
    })
}

fn validate_anchors(
    signer: &AuditAnchorSigner,
    tenant: TenantId,
    kind: AuditChainKind,
    agent: Option<Id>,
    anchors: &[SignedAuditAnchor],
) -> DomainResult<()> {
    let mut previous = None;
    for value in anchors {
        signer.verify(value, tenant, kind, agent)?;
        value.follows(previous)?;
        previous = Some(value);
    }
    Ok(())
}

fn make(
    signer: &AuditAnchorSigner,
    tenant: TenantId,
    kind: AuditChainKind,
    chain: Id,
    agent: Option<Id>,
    position: (i64, String),
    previous: Option<&SignedAuditAnchor>,
) -> DomainResult<SignedAuditAnchor> {
    let mut envelope = SignedAuditAnchor {
        kind,
        chain_id: chain,
        agent_id: agent,
        previous_anchor_id: previous.map(|value| value.anchor.id),
        previous_anchor_hash: previous.map(SignedAuditAnchor::witness_hash),
        anchor: AuditChainAnchor {
            id: Id::new(),
            tenant_id: tenant,
            up_to_sequence: position.0,
            tail_hash: position.1,
            entry_count: position.0,
            created_at: Timestamp::now(),
            signature: String::new(),
        },
    };
    envelope.follows(previous)?;
    signer.sign(&mut envelope)?;
    Ok(envelope)
}
