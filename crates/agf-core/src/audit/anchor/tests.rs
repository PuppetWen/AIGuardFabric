use super::*;
use crate::audit::{AuditAction, AuditOutcome};

fn record(agent: Id) -> AuditLog {
    let mut entry = crate::audit::tests::entry(1, GENESIS_HASH, AuditAction::Execute);
    entry.actor.kind = "agent".into();
    entry.actor.id = Some(agent);
    entry.outcome = AuditOutcome::Denied;
    entry.seal();
    entry
}

#[test]
fn segment_rejects_rehashed_identity_sequence_gap_duplicate_and_oversize() {
    let agent = Id::new();
    let entry = record(agent);
    assert!(verify_agent_segment(std::slice::from_ref(&entry), entry.tenant_id, agent, 0, GENESIS_HASH).is_ok());
    let mut wrong = entry.clone();
    wrong.actor.id = Some(Id::new());
    // 既有 AuditLog 哈希未覆盖 actor.id，记录段校验仍必须拒绝身份篡改。
    assert!(wrong.verify());
    assert!(verify_agent_segment(&[wrong], entry.tenant_id, agent, 0, GENESIS_HASH).is_err());
    let mut gap = entry.clone();
    gap.sequence = 2;
    gap.seal();
    assert!(verify_agent_segment(&[gap], entry.tenant_id, agent, 0, GENESIS_HASH).is_err());
    let mut duplicate = entry.clone();
    duplicate.sequence = 2;
    duplicate.prev_hash = entry.entry_hash.clone();
    duplicate.seal();
    assert!(verify_agent_segment(&[entry.clone(), duplicate], entry.tenant_id, agent, 0, GENESIS_HASH).is_err());
    let mut oversized = entry.clone();
    oversized.note = "x".repeat(16 * 1024);
    oversized.seal();
    assert!(verify_agent_segment(&[oversized], entry.tenant_id, agent, 0, GENESIS_HASH).is_err());
    let mut changed = entry.clone();
    changed.note = "tampered".into();
    assert!(verify_agent_segment(&[changed], entry.tenant_id, agent, 0, GENESIS_HASH).is_err());
    assert!(verify_agent_segment(&vec![entry.clone(); 257], entry.tenant_id, agent, 0, GENESIS_HASH).is_err());
}

#[test]
fn checkpoint_links_include_purpose_agent_identity_and_previous_signature() {
    let tenant = TenantId::new();
    let agent = Id::new();
    let first = SignedAuditAnchor {
        kind: AuditChainKind::AgentRuntime,
        chain_id: Id::new(),
        agent_id: Some(agent),
        previous_anchor_id: None,
        previous_anchor_hash: None,
        anchor: AuditChainAnchor {
            id: Id::new(),
            tenant_id: tenant,
            up_to_sequence: 0,
            tail_hash: GENESIS_HASH.into(),
            entry_count: 0,
            created_at: crate::time::Timestamp::now(),
            signature: "a".repeat(64),
        },
    };
    let mut next = first.clone();
    next.anchor.id = Id::new();
    next.anchor.up_to_sequence = 1;
    next.anchor.entry_count = 1;
    next.anchor.tail_hash = "b".repeat(64);
    next.previous_anchor_id = Some(first.anchor.id);
    next.previous_anchor_hash = Some(first.witness_hash());
    assert!(next.follows(Some(&first)).is_ok());
    let payload = next.signing_payload();
    next.agent_id = Some(Id::new());
    assert_ne!(next.signing_payload(), payload);
    assert!(next.follows(Some(&first)).is_err());
    next.agent_id = Some(agent);
    let mut damaged = first.clone();
    damaged.anchor.signature = "c".repeat(64);
    assert!(next.follows(Some(&damaged)).is_err());
    assert!(next.validate_identity(TenantId::new(), AuditChainKind::AgentRuntime, Some(agent)).is_err());
    assert!(next.validate_identity(tenant, AuditChainKind::Management, None).is_err());
    assert!(!valid_hash(&"A".repeat(64)));
    assert!(!valid_hash(&"a".repeat(63)));
}
