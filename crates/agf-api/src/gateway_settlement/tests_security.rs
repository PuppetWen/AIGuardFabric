//! Bad encrypted evidence and bounded-write failures must be rejected before publication.
use super::{codec, records::*, reducer, sql, tests_fixture::fixture};
use agf_core::{
    audit::{AuditAction, AuditActor, AuditOutcome, AuditTarget},
    credential::KeyBackend,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    time::Timestamp,
};
use agf_storage::crypto::FieldCipher;
use serde_json::json;
use std::collections::BTreeMap;

#[test]
fn pending_aad_binds_exact_tenant_attempt_and_kind() -> DomainResult<()> {
    let f = fixture(864_100)?;
    let cipher = FieldCipher::new(&[1; 32], "owned", KeyBackend::LocalFile)?;
    let encoded = codec::encode_with(&cipher, f.fact.origin.tenant, f.fact.attempt, PENDING, &f.pending)?;
    let decoded: Pending = codec::decode_with(&cipher, f.fact.origin.tenant, f.fact.attempt, PENDING, &encoded)?;
    assert_eq!(codec::hash(&decoded)?, codec::hash(&f.pending)?);
    assert!(
        codec::decode_with::<Pending>(
            &cipher,
            TenantId::from_uuid(Id::new().as_uuid()),
            f.fact.attempt,
            PENDING,
            &encoded
        )
        .is_err()
    );
    assert!(codec::decode_with::<Pending>(&cipher, f.fact.origin.tenant, Id::new(), PENDING, &encoded).is_err());
    assert!(codec::decode_with::<Pending>(&cipher, f.fact.origin.tenant, f.fact.attempt, FACT, &encoded).is_err());
    let foreign = FieldCipher::new(&[2; 32], "other", KeyBackend::LocalFile)?;
    assert!(codec::decode_with::<Pending>(&foreign, f.fact.origin.tenant, f.fact.attempt, PENDING, &encoded).is_err());
    Ok(())
}
#[test]
fn exact_original_execution_window_cannot_be_renewed_or_rounded_down() -> DomainResult<()> {
    let mut f = fixture(864_100)?;
    let submitted = f.fact.submitted_at;
    assert!(reducer::validate(&f.fact, &f.pending).is_ok());
    f.fact.execute_before =
        Timestamp::from_unix_millis(submitted.unix_millis() + 110_001).map_err(DomainError::Validation)?;
    assert!(reducer::validate(&f.fact, &f.pending).is_err());
    f.fact.execute_before = submitted;
    assert!(reducer::validate(&f.fact, &f.pending).is_err());
    f.fact.execute_before = submitted.offset_secs(-1);
    assert!(reducer::validate(&f.fact, &f.pending).is_err());
    Ok(())
}
#[test]
fn budget_counts_complete_keys_records_and_maximum_sealed_audit_before_publication() {
    let tenant = TenantId::default_tenant();
    let mut audit = crate::state::AppState::audit_entry(
        tenant,
        AuditAction::Execute,
        AuditOutcome::Failure,
        AuditActor::system("gateway-settlement-test"),
        AuditTarget::new("gateway-attempt", None, None),
        "",
    );
    let rows = BTreeMap::from([((FACT, Id::new()), json!("x".repeat(1024 * 1024)))]);
    assert!(sql::budget(tenant, &rows, &audit).is_err());
    let mut rows = BTreeMap::new();
    for _ in 0..9 {
        rows.insert((FACT, Id::new()), json!("x".repeat(900_000)));
    }
    assert!(sql::budget(tenant, &rows, &audit).is_ok());
    rows.insert((FACT, Id::new()), json!("x".repeat(900_000)));
    assert!(sql::budget(tenant, &rows, &audit).is_err());
    audit.tenant_id = TenantId::from_uuid(Id::new().as_uuid());
    assert!(sql::budget(tenant, &BTreeMap::new(), &audit).is_err());
    assert!(sql::budget(tenant, &BTreeMap::from([((FACT, Id::nil()), json!({}))]), &audit).is_err());
}
#[test]
fn full_pending_body_bound_applies_before_encryption() -> DomainResult<()> {
    let cipher = FieldCipher::new(&[1; 32], "owned", KeyBackend::LocalFile)?;
    assert!(
        codec::encode_with(&cipher, TenantId::default_tenant(), Id::new(), PENDING, &json!("x".repeat(64 * 1024)))
            .is_err()
    );
    Ok(())
}
#[test]
fn cache_evidence_cannot_claim_paid_usage_or_mix_an_unknown_provider_outcome() -> DomainResult<()> {
    let mut f = fixture(864_100)?;
    f.pending.outcome.evidence = Evidence::LocalReply;
    assert!(reducer::validate(&f.fact, &f.pending).is_err());
    f.pending.outcome.evidence = Evidence::SentUsageUnknown;
    assert!(reducer::validate(&f.fact, &f.pending).is_err());
    Ok(())
}
