//! 由 `audit.rs` 拆分：`entry` 等 15 个函数（纯搬移，逻辑不变）。

use crate::ids::{Id, TenantId};
use crate::time::Timestamp;

use super::*;

pub(crate) fn entry(sequence: i64, prev_hash: &str, action: AuditAction) -> AuditLog {
    let mut e = AuditLog {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        sequence,
        action,
        outcome: AuditOutcome::Success,
        actor: AuditActor {
            id: Some(Id::new()),
            kind: "user".into(),
            name: "admin".into(),
            source_ip: Some("10.0.0.1".into()),
            user_agent: None,
            session_id: None,
        },
        target: AuditTarget::new("policy", Some(Id::new().to_string()), Some("阻断危险命令".into())),
        before: None,
        after: Some(serde_json::json!({"enabled": true})),
        changed_fields: vec!["enabled".into()],
        request_id: None,
        error: None,
        note: String::new(),
        prev_hash: prev_hash.to_string(),
        entry_hash: String::new(),
        at: Timestamp::now(),
    };
    e.seal();
    e
}

pub(crate) fn build_chain(n: i64) -> Vec<AuditLog> {
    let mut out: Vec<AuditLog> = Vec::new();
    let mut prev = GENESIS_HASH.to_string();
    for i in 1..=n {
        let e = entry(i, &prev, AuditAction::Configure);
        prev = e.entry_hash.clone();
        out.push(e);
    }
    out
}

#[test]
pub(crate) fn genesis_hash_is_64_zeros() {
    assert_eq!(GENESIS_HASH.len(), 64);
    assert!(GENESIS_HASH.chars().all(|c| c == '0'));
}

#[test]
pub(crate) fn chain_verifies_when_intact() {
    let chain = build_chain(10);
    let report = verify_chain(&chain);
    assert!(report.passed, "违规项: {:?}", report.violations);
    assert_eq!(report.checked, 10);
    assert_eq!(report.first_sequence, Some(1));
    assert_eq!(report.last_sequence, Some(10));
}

#[test]
pub(crate) fn tampering_content_is_detected() {
    let mut chain = build_chain(5);
    chain[2].note = "被篡改".into();
    let report = verify_chain(&chain);
    assert!(!report.passed);
    assert!(report.violations.iter().any(|v| v.kind == "hash_mismatch" && v.sequence == 3));
}

#[test]
pub(crate) fn deleting_middle_entry_is_detected() {
    let chain = build_chain(5);
    let mut damaged = chain;
    damaged.remove(2);
    let report = verify_chain(&damaged);
    assert!(!report.passed);
    assert!(report.violations.iter().any(|v| v.kind == "prev_gap"));
    assert!(report.violations.iter().any(|v| v.kind == "sequence_gap"));
}

#[test]
pub(crate) fn deleting_first_entry_or_resealing_wrong_genesis_is_detected() {
    let mut truncated = build_chain(3);
    truncated.remove(0);
    let report = verify_chain(&truncated);
    assert!(!report.passed);
    assert!(report.violations.iter().any(|row| row.kind == "sequence_gap"));
    assert!(report.violations.iter().any(|row| row.kind == "prev_gap"));

    let wrong_genesis = vec![entry(1, "forged", AuditAction::Configure)];
    assert!(wrong_genesis[0].verify(), "单条内容哈希本身正确");
    assert!(!verify_chain(&wrong_genesis).passed, "首条记录仍须连接创世哈希");
}

#[test]
pub(crate) fn paged_verifier_detects_gap_between_batches() {
    let mut chain = build_chain(5);
    chain.remove(2);
    let mut verifier = ChainVerifier::new();
    for batch in chain.chunks(2) {
        for entry in batch {
            verifier.push(entry);
        }
    }
    let report = verifier.finish();
    assert_eq!(report.checked, 4);
    assert!(!report.passed);
    assert!(report.violations.iter().any(|row| row.kind == "sequence_gap"));
    assert!(report.violations.iter().any(|row| row.kind == "prev_gap"));
}

#[test]
pub(crate) fn inserting_forged_entry_is_detected() {
    let mut chain = build_chain(4);
    // 攻击者插入一条自洽的记录，但 prev_hash 指向错误的位置
    let forged = entry(99, GENESIS_HASH, AuditAction::Grant);
    chain.push(forged);
    let report = verify_chain(&chain);
    assert!(!report.passed);
}

#[test]
pub(crate) fn empty_chain_passes() {
    let report = verify_chain(&[]);
    assert!(report.passed);
    assert_eq!(report.checked, 0);
    assert_eq!(report.last_sequence, None);
}

#[test]
pub(crate) fn rehashing_with_anchor_signature_payload_is_stable() {
    let anchor = AuditChainAnchor {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        up_to_sequence: 100,
        tail_hash: "abc".into(),
        entry_count: 100,
        created_at: Timestamp::now(),
        signature: String::new(),
    };
    assert_eq!(anchor.signing_payload(), anchor.signing_payload());
}

#[test]
pub(crate) fn sensitive_actions_flagged() {
    assert!(AuditAction::Grant.is_sensitive());
    assert!(AuditAction::Export.is_sensitive());
    assert!(!AuditAction::Read.is_sensitive());
    assert_eq!(AuditAction::Contain.as_str(), "contain");
}

#[test]
pub(crate) fn query_filtering() {
    let chain = build_chain(3);
    let mut q = AuditQuery::default();
    assert!(chain.iter().all(|e| q.matches(e)));
    q.actions = vec![AuditAction::Grant];
    assert!(!q.matches(&chain[0]));
    q.actions.clear();
    q.actor = Some("ADMI".into());
    assert!(q.matches(&chain[0]), "操作者匹配应忽略大小写");
    q.actor = Some("someone-else".into());
    assert!(!q.matches(&chain[0]));
    q.actor = None;
    q.sensitive_only = true;
    assert!(q.matches(&chain[0]), "Configure 属于高敏感动作，应被 sensitive_only 命中");
}

#[test]
pub(crate) fn query_sensitive_only_includes_configure() {
    let chain = build_chain(1);
    let q = AuditQuery { sensitive_only: true, ..AuditQuery::default() };
    assert!(q.matches(&chain[0]), "Configure 属于高敏感动作");
    let read = entry(2, GENESIS_HASH, AuditAction::Read);
    assert!(!q.matches(&read), "Read 不属于高敏感动作");
}

#[test]
pub(crate) fn query_time_window() {
    let chain = build_chain(2);
    let q = AuditQuery {
        from: Some(Timestamp::now().offset_secs(-10)),
        to: Some(Timestamp::now().offset_secs(10)),
        ..AuditQuery::default()
    };
    assert!(q.matches(&chain[0]));
    let q2 = AuditQuery { from: Some(Timestamp::now().offset_secs(60)), ..AuditQuery::default() };
    assert!(!q2.matches(&chain[0]));
}

#[test]
pub(crate) fn system_actor_helper() {
    let a = AuditActor::system("agf-scheduler");
    assert_eq!(a.kind, "service");
    assert!(a.id.is_none());
}

#[test]
pub(crate) fn outcome_str() {
    assert_eq!(AuditOutcome::Denied.as_str(), "denied");
    assert_eq!(AuditOutcome::Failure.as_str(), "failure");
}
