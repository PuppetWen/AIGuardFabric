//! Negative invariants of the actual typed reducer and real AEAD; no fabricated provider success.
use super::{
    Binding, CAPACITY, INDEX, MAX_KEYS, identity,
    model::{Capacity, Entry},
};
use crate::{
    Principal,
    gateway_settlement::{codec, records::*, tests_fixture::fixture},
};
use agf_core::{
    credential::KeyBackend,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    rbac::SubjectKind,
};
use agf_storage::crypto::FieldCipher;
use axum::http::{HeaderMap, HeaderValue};
use serde_json::json;

fn principal(origin: &Origin) -> Principal {
    Principal {
        subject_id: Some(origin.subject),
        agent_id: origin.bound_agent,
        subject_kind: origin.kind,
        tenant: origin.tenant,
        identity_tenant: origin.identity_tenant,
        roles: vec![],
        superadmin: false,
        must_change_password: false,
        must_setup_mfa: false,
        session_id: origin.session.clone(),
        scopes: vec![],
        source_ip: None,
        user_agent: None,
        department: None,
    }
}
fn binding() -> DomainResult<Binding> {
    let namespace = "a".repeat(64);
    Ok(Binding { id: identity::id(&namespace)?, namespace, input: "b".repeat(64) })
}

#[test]
fn namespace_cannot_split_when_a_key_is_rebound_or_a_user_logs_in_again() -> DomainResult<()> {
    let f = fixture(864_100)?;
    let original = principal(&f.fact.origin);
    let bytes = identity::namespace_bytes(&original, "owned-key")?;
    let mut rebound = original.clone();
    rebound.agent_id = Some(Id::new());
    rebound.session_id = Some("new-legitimate-login".into());
    rebound.roles = vec!["different-current-role".into()];
    assert_eq!(identity::namespace_bytes(&rebound, "owned-key")?, bytes);
    assert!(f.fact.origin.matches(&rebound).is_err(), "occupied namespace keeps its original bound Agent");
    Ok(())
}

#[test]
fn tenant_identity_kind_subject_and_caller_key_remain_separate_namespaces() -> DomainResult<()> {
    let f = fixture(864_100)?;
    let original = principal(&f.fact.origin);
    let baseline = identity::namespace_bytes(&original, "owned-key")?;
    for field in 0..4 {
        let mut foreign = original.clone();
        match field {
            0 => foreign.tenant = TenantId::new(),
            1 => foreign.identity_tenant = TenantId::new(),
            2 => foreign.subject_kind = SubjectKind::User,
            _ => foreign.subject_id = Some(Id::new()),
        }
        assert_ne!(identity::namespace_bytes(&foreign, "owned-key")?, baseline);
    }
    assert_ne!(identity::namespace_bytes(&original, "other-key")?, baseline);
    Ok(())
}

#[test]
fn header_is_single_printable_ascii_without_url_or_log_material() -> DomainResult<()> {
    for key in ["", "contains space", &"x".repeat(201)] {
        let mut headers = HeaderMap::new();
        headers.insert("idempotency-key", HeaderValue::from_str(key).map_err(|_| identity::invalid())?);
        assert!(identity::header(&headers).is_err());
    }
    let mut headers = HeaderMap::new();
    headers.append("idempotency-key", HeaderValue::from_static("first"));
    headers.append("idempotency-key", HeaderValue::from_static("second"));
    assert!(identity::header(&headers).is_err());
    Ok(())
}

#[test]
fn service_mac_matches_independent_rfc4231_short_and_long_key_vectors() {
    assert_eq!(
        hex::encode(identity::mac(&[0x0b; 20], b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        hex::encode(identity::mac(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First")),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

#[test]
fn real_encryption_binds_index_tenant_id_and_kind_and_does_not_contain_input_or_key() -> DomainResult<()> {
    let f = fixture(864_100)?;
    let binding = binding()?;
    let entry = Entry::new(&binding, &f.fact)?;
    let cipher = FieldCipher::new(&[1; 32], "owned-test-only", KeyBackend::LocalFile)?;
    let encoded = codec::encode_with(&cipher, f.fact.origin.tenant, binding.id, INDEX, &entry)?;
    let restored: Entry = codec::decode_with(&cipher, f.fact.origin.tenant, binding.id, INDEX, &encoded)?;
    restored.validate(binding.id, &binding.namespace)?;
    restored.fact(&f.fact)?;
    assert!(codec::decode_with::<Entry>(&cipher, TenantId::new(), binding.id, INDEX, &encoded).is_err());
    assert!(codec::decode_with::<Entry>(&cipher, f.fact.origin.tenant, Id::new(), INDEX, &encoded).is_err());
    assert!(codec::decode_with::<Entry>(&cipher, f.fact.origin.tenant, binding.id, CAPACITY, &encoded).is_err());
    assert!(!serde_json::to_string(&encoded)?.contains(&binding.input));
    Ok(())
}

#[test]
fn authenticated_index_must_reject_another_fact_owner_uuid_usage_or_original_clock() -> DomainResult<()> {
    let f = fixture(864_100)?;
    let entry = Entry::new(&binding()?, &f.fact)?;
    for change in 0..5 {
        let mut wrong = f.fact.clone();
        match change {
            0 => wrong.attempt = Id::new(),
            1 => wrong.usage_id = Id::new(),
            2 => wrong.origin.bound_agent = Some(Id::new()),
            3 => wrong.submitted_at = wrong.submitted_at.offset_secs(1),
            _ => wrong.execute_before = wrong.execute_before.offset_secs(1),
        }
        assert!(entry.fact(&wrong).is_err());
    }
    // A new terminal phase/charge projection does not invent a new admission identity.
    let mut settled = f.fact.clone();
    settled.phase = Phase::Settled { outcome_hash: "c".repeat(64), audit_id: Id::new() };
    entry.fact(&settled)?;
    Ok(())
}

#[test]
fn different_input_never_matches_an_already_authenticated_key() -> DomainResult<()> {
    let f = fixture(864_100)?;
    let mut binding = binding()?;
    let entry = Entry::new(&binding, &f.fact)?;
    assert!(entry.matches(&binding));
    binding.input = "c".repeat(64);
    assert!(!entry.matches(&binding));
    Ok(())
}

#[test]
fn permanent_capacity_never_evicts_or_accepts_a_missing_or_false_counter() -> DomainResult<()> {
    let tenant = TenantId::default_tenant();
    let row = Capacity::next(None, tenant, 0)?;
    assert_eq!(serde_json::to_value(&row)?["used"], 1);
    assert!(Capacity::next(None, tenant, 1).is_err());
    assert!(Capacity::next(Some(row), tenant, 0).is_err());
    let full: Capacity = serde_json::from_value(json!({"tenant":tenant,"used":MAX_KEYS}))?;
    assert!(matches!(Capacity::next(Some(full), tenant, MAX_KEYS), Err(DomainError::RateLimited(_))));
    let wrong: Capacity = serde_json::from_value(json!({"tenant":TenantId::new(),"used":0}))?;
    assert!(Capacity::next(Some(wrong), tenant, 0).is_err());
    Ok(())
}

#[test]
fn keyed_preparation_preserves_original_window_and_rejects_an_already_elapsed_deadline() -> DomainResult<()> {
    let submitted = agf_core::time::Timestamp::now();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    assert_eq!(
        crate::gateway_settlement::workflow::original_window(Some((submitted, deadline)))?,
        (submitted, deadline)
    );
    let expired = tokio::time::Instant::now() - std::time::Duration::from_millis(1);
    assert!(matches!(
        crate::gateway_settlement::workflow::original_window(Some((submitted, expired))),
        Err(DomainError::Timeout(_))
    ));
    Ok(())
}
