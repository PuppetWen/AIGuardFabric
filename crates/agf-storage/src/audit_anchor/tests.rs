#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use agf_core::{
    audit::{AuditChainAnchor, GENESIS_HASH},
    time::Timestamp,
};

fn envelope() -> SignedAuditAnchor {
    let tenant = TenantId::new();
    SignedAuditAnchor {
        kind: AuditChainKind::Management,
        chain_id: tenant.as_id(),
        agent_id: None,
        previous_anchor_id: None,
        previous_anchor_hash: None,
        anchor: AuditChainAnchor {
            id: Id::new(),
            tenant_id: tenant,
            up_to_sequence: 0,
            tail_hash: GENESIS_HASH.into(),
            entry_count: 0,
            created_at: Timestamp::now(),
            signature: String::new(),
        },
    }
}
fn signer() -> AuditAnchorSigner {
    AuditAnchorSigner::from_base64("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=").unwrap()
}

#[test]
fn master_key_signatures_bind_the_whole_checkpoint_and_reject_development_fallback() {
    assert!(AuditAnchorSigner::from_base64("").is_err());
    assert!(AuditAnchorSigner::from_base64("invalid").is_err());
    let signer = signer();
    let mut value = envelope();
    signer.sign(&mut value).unwrap();
    let tenant = value.anchor.tenant_id;
    assert!(signer.verify(&value, tenant, AuditChainKind::Management, None).is_ok());
    let mut changes = vec![value.clone(); 5];
    changes[0].anchor.id = Id::new();
    changes[1].chain_id = Id::new();
    changes[2].anchor.created_at = Timestamp::parse_rfc3339("2000-01-01T00:00:00Z").unwrap();
    changes[3].anchor.signature = "0".repeat(64);
    changes[4].previous_anchor_id = Some(Id::new());
    changes[4].previous_anchor_hash = Some("a".repeat(64));
    for changed in changes {
        assert!(signer.verify(&changed, tenant, AuditChainKind::Management, None).is_err());
    }
    assert!(!format!("{signer:?}").contains("AQEB"));
}

#[test]
fn witness_is_persistent_exclusive_bounded_and_never_a_build_artifact() {
    let root = std::path::PathBuf::from("target/test-data").join(format!("audit-witness-{}", Id::new()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join(".owned-test"), "audit-witness-test").unwrap();
    let mut value = envelope();
    signer().sign(&mut value).unwrap();
    let tenant = value.anchor.tenant_id;
    let witness = AuditWitness::acquire(&root, tenant, None).unwrap();
    assert!(witness.read().unwrap().is_none());
    assert!(AuditWitness::acquire(&root, tenant, None).is_err());
    witness.advance(&value).unwrap();
    drop(witness);
    let witness = AuditWitness::acquire(&root, tenant, None).unwrap();
    assert_eq!(witness.read().unwrap().unwrap().witness_hash(), value.witness_hash());
    drop(witness);
    let path = root.join("audit-witnesses-v1").join(format!("{tenant}-management.json"));
    std::fs::write(&path, vec![b'x'; 16 * 1024 + 1]).unwrap();
    assert!(AuditWitness::acquire(&root, tenant, None).unwrap().read().is_err());
    assert_eq!(std::fs::read_to_string(root.join(".owned-test")).unwrap(), "audit-witness-test");
    std::fs::remove_dir_all(root).unwrap();
}
