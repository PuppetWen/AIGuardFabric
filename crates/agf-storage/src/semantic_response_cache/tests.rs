#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use agf_core::{
    credential::KeyBackend,
    enums::DataClass,
    error::DomainResult,
    ids::{Id, TenantId},
};
use serde_json::json;

fn cipher() -> crate::FieldCipher {
    crate::FieldCipher::new(&[9; 32], "semantic-test", KeyBackend::LocalFile).unwrap()
}
fn issuer() -> DomainIssuer {
    DomainIssuer::from_server_key([7; 32]).unwrap()
}
fn evidence() -> ServerSemanticEvidence {
    ServerSemanticEvidence {
        tenant: TenantId::new(),
        subject_id: Id::new(),
        subject_kind: "user".into(),
        identity_tenant: TenantId::new(),
        session: Some("owned-session".into()),
        agent_id: None,
        department: Some("owned-department".into()),
        data_class: DataClass::Public,
        internal_placement_verified: false,
        chat_endpoint: Id::new(),
        chat_model: "owned-chat".into(),
        chat_model_revision: "revision-1".into(),
        embedding_endpoint: Id::new(),
        embedding_model: "owned-embedding".into(),
        embedding_model_revision: "revision-1".into(),
        dimensions: 3,
        transport_mode: "mock".into(),
        cache_configuration_version: 1,
        fences: vec![
            ConfigurationFence::from_server_record(
                "model-endpoint",
                Id::new(),
                1,
                &json!({"version":1,"enabled":true}),
            )
            .unwrap(),
        ],
        fixed_request: json!({"messages":[{"role":"system","content":"fixed instruction"},{"role":"user","content":null}],"temperature":0}),
        authority_deadline_ms: chrono::Utc::now().timestamp_millis() + 60_000,
    }
}
fn response(text: &str) -> PlainResponse {
    PlainResponse::from_canonical(
        json!({"id":"owned-reply","model":"owned-chat","message":{"role":"assistant","content":text},
        "finish_reason":"stop","usage":{"prompt_tokens":12,"completion_tokens":4}}),
        "owned-chat",
    )
    .unwrap()
}
fn admission(vector: Vec<f32>, text: &str) -> Admission {
    Admission::new(vector, response(text), 900).unwrap()
}
fn query() -> SearchVector {
    SearchVector::new(vec![1.0, 0.0, 0.0], 0.99, 0.001).unwrap()
}
struct Authority;
#[async_trait::async_trait]
impl SemanticReadAuthority for Authority {
    async fn revalidate(&self, _domain: &TrustedSemanticDomain) -> DomainResult<()> {
        Ok(())
    }
}

#[test]
fn domain_binds_actual_fences_fixed_parameters_identity_and_model_revision() {
    let service = issuer();
    let base = evidence();
    let first = service.issue(base.clone()).unwrap();
    let mut changes = Vec::new();
    let mut changed = base.clone();
    changed.subject_id = Id::new();
    changes.push(changed);
    let mut changed = base.clone();
    changed.session = Some("other-session".into());
    changes.push(changed);
    let mut changed = base.clone();
    changed.tenant = TenantId::new();
    changes.push(changed);
    let mut changed = base.clone();
    changed.chat_model_revision = "revision-2".into();
    changes.push(changed);
    let mut changed = base.clone();
    changed.embedding_model_revision = "revision-2".into();
    changes.push(changed);
    let mut changed = base.clone();
    changed.transport_mode = "live".into();
    changes.push(changed);
    let mut changed = base.clone();
    changed.fixed_request["max_tokens"] = json!(999);
    changes.push(changed);
    let mut changed = base.clone();
    changed.fences[0] = ConfigurationFence::from_server_record(
        "model-endpoint",
        base.fences[0].id,
        1,
        &json!({"version":1,"enabled":false}),
    )
    .unwrap();
    changes.push(changed);
    for changed in changes {
        assert_ne!(service.issue(changed).unwrap().digest(), first.digest());
    }
    let mut refreshed = base;
    refreshed.authority_deadline_ms += 1000;
    assert_eq!(
        service.issue(refreshed).unwrap().digest(),
        first.digest(),
        "Original authority deadlines do not destroy reusable domain identity"
    );
}

#[test]
fn confidential_unverified_internal_and_duplicate_source_evidence_cannot_issue() {
    for class in [DataClass::Confidential, DataClass::Restricted, DataClass::Internal] {
        let mut value = evidence();
        value.data_class = class;
        assert!(issuer().issue(value).is_err());
    }
    let mut value = evidence();
    value.fences.push(value.fences[0].clone());
    assert!(issuer().issue(value).is_err());
    let mut value = evidence();
    value.authority_deadline_ms = 0;
    assert!(issuer().issue(value).is_err());
}

#[test]
fn staged_service_result_preserves_identity_and_rejects_invalid_data() {
    let id = Id::new();
    let first = Admission::from_staged_server_result(id, vec![1.0, 0.0, 0.0], response("staged"), 900).unwrap();
    let second = Admission::from_staged_server_result(id, vec![1.0, 0.0, 0.0], response("staged"), 900).unwrap();
    assert_eq!(first.id(), second.id());
    assert_ne!(Admission::new(vec![1.0], response("new"), 900).unwrap().id(), id);
    for (invalid_id, vector, ttl) in [
        (Id::nil(), vec![1.0], 900),
        (id, vec![0.0], 900),
        (id, vec![f32::NAN], 900),
        (id, vec![1.0; 4097], 900),
        (id, vec![1.0], 0),
        (id, vec![1.0], 901),
    ] {
        assert!(Admission::from_staged_server_result(invalid_id, vector, response("staged"), ttl).is_err());
    }
    let mut corrupt = response("staged");
    corrupt.0["raw"] = json!({"provider":"not admissible"});
    assert!(Admission::from_staged_server_result(id, vec![1.0], corrupt, 900).is_err());
}

#[test]
fn issuer_capability_and_aead_bind_original_tenant_row_domain_expiry_and_payload() {
    let domain = issuer().issue(evidence()).unwrap();
    let entry = codec::seal(&cipher(), &domain, admission(vec![1.0, 0.0, 0.0], "private response")).unwrap();
    assert!(!serde_json::to_string(&entry).unwrap().contains("private response"));
    let wrong_issuer = DomainIssuer::from_server_key([1; 32]).unwrap();
    assert!(wrong_issuer.validate(&domain).is_err());
    for modify in [0, 1, 2, 3] {
        let mut bad = entry.clone();
        match modify {
            0 => bad.tenant = TenantId::new(),
            1 => bad.id = Id::new(),
            2 => bad.expires_ms += 1,
            _ => bad.secret.aad = Some("foreign authenticated domain".into()),
        }
        assert!(codec::choose(&cipher(), &domain, &query(), vec![bad]).is_err());
    }
}

#[test]
fn cosine_is_finite_for_extreme_and_subnormal_vectors_rejects_bad_and_equal_scores() {
    let query = SearchVector::new(vec![f32::MAX, f32::MAX], 1.0, 0.0).unwrap();
    assert!((query.score(&[f32::MAX, f32::MAX]).unwrap() - 1.0).abs() < 1e-12);
    let subnormal = f32::from_bits(1);
    assert!(
        (SearchVector::new(vec![subnormal, 0.0], 0.9, 0.0).unwrap().score(&[subnormal, 0.0]).unwrap() - 1.0).abs()
            < 1e-12
    );
    for vector in [vec![], vec![0.0], vec![f32::INFINITY], vec![f32::NAN], vec![1.0; 4097]] {
        assert!(SearchVector::new(vector, 0.9, 0.0).is_err());
    }
    assert!(SearchVector::new(vec![1.0], f64::NAN, 0.0).is_err());
}

#[tokio::test]
async fn memory_reuses_similar_vector_without_plain_prompt_storage_and_fails_ambiguous() {
    let domain = issuer().issue(evidence()).unwrap();
    let repository = MemoryRepository::new(issuer(), cipher());
    repository.admit(&domain, admission(vec![1.0, 0.01, 0.0], "answer-one"), |_| Ok(())).unwrap();
    assert!(matches!(repository.lookup(&domain, &query(), &Authority).await.unwrap(), Lookup::Hit { .. }));
    repository.admit(&domain, admission(vec![1.0, 0.01, 0.0], "conflicting-answer"), |_| Ok(())).unwrap();
    assert!(matches!(repository.lookup(&domain, &query(), &Authority).await.unwrap(), Lookup::Ambiguous));
    let mut changed = evidence();
    changed.tenant = domain.tenant;
    assert!(matches!(
        repository.lookup(&issuer().issue(changed).unwrap(), &query(), &Authority).await.unwrap(),
        Lookup::Miss
    ));
}

#[tokio::test]
async fn over_128_is_explicit_miss_and_512_capacity_evicts_only_cache() {
    let domain = issuer().issue(evidence()).unwrap();
    let repository = MemoryRepository::new(issuer(), cipher());
    for _ in 0..513 {
        repository.admit(&domain, admission(vec![1.0, 0.0, 0.0], "owned-answer"), |_| Ok(())).unwrap();
    }
    assert_eq!(repository.rows.lock().unwrap().len(), 512);
    assert!(matches!(repository.lookup(&domain, &query(), &Authority).await.unwrap(), Lookup::CandidateLimit));
    let before = repository.rows.lock().unwrap().len();
    assert!(repository.admit(&domain, admission(vec![1.0, 0.0, 0.0], "rejected"), |_| Err(codec::corrupt())).is_err());
    assert_eq!(repository.rows.lock().unwrap().len(), before);
}

#[test]
fn encoded_envelope_and_plain_response_bounds_reject_oversize_raw_tools_and_partial() {
    let domain = issuer().issue(evidence()).unwrap();
    let big = response(&"x".repeat(210_000));
    assert!(
        codec::seal(&cipher(), &domain, Admission::new(vec![1.0, 0.0, 0.0], big, 900).unwrap()).is_err(),
        "Actual base64 envelope exceeds256KiB even though clear response fits"
    );
    let base = response("safe").0;
    for field in ["raw", "unknown"] {
        let mut value = base.clone();
        value[field] = json!({"private":"body"});
        assert!(PlainResponse::from_canonical(value, "owned-chat").is_err());
    }
    let mut value = base.clone();
    value["finish_reason"] = json!("length");
    assert!(PlainResponse::from_canonical(value, "owned-chat").is_err());
    let mut value = base;
    value["message"]["tool_calls"] = json!([{"id":"unsafe"}]);
    assert!(PlainResponse::from_canonical(value, "owned-chat").is_err());
    assert!(Admission::new(vec![1.0], response("safe"), 901).is_err());
}

#[test]
fn tenant_encoded_byte_budget_evicts_before_row_limit_and_foreign_rows_are_retained() {
    let domain = issuer().issue(evidence()).unwrap();
    let foreign = issuer().issue(evidence()).unwrap();
    let repository = MemoryRepository::new(issuer(), cipher());
    let foreign_id = repository.admit(&foreign, admission(vec![1.0, 0.0, 0.0], "foreign-owned"), |_| Ok(())).unwrap();
    let text = "x".repeat(110_000);
    for _ in 0..140 {
        repository.admit(&domain, admission(vec![1.0, 0.0, 0.0], &text), |_| Ok(())).unwrap();
    }
    let rows = repository.rows.lock().unwrap();
    let current = rows.values().filter(|entry| entry.tenant == domain.tenant).collect::<Vec<_>>();
    assert!(current.len() < 140 && current.len() < MAX_ROWS);
    assert!(current.iter().map(|entry| codec::encoded_size(entry).unwrap()).sum::<usize>() <= MAX_TENANT_BYTES);
    assert!(rows.contains_key(&(foreign.tenant, foreign_id)));
}

#[tokio::test]
async fn pure_memory_lookup_never_prunes_expired_rows_and_get_requires_current_authority() {
    let domain = issuer().issue(evidence()).unwrap();
    let repository = MemoryRepository::new(issuer(), cipher());
    let id = repository
        .admit(&domain, Admission::new(vec![1.0, 0.0, 0.0], response("owned"), 1).unwrap(), |_| Ok(()))
        .unwrap();
    {
        repository.rows.lock().unwrap().get_mut(&(domain.tenant, id)).unwrap().expires_ms = 0;
    }
    assert!(matches!(repository.lookup(&domain, &query(), &Authority).await.unwrap(), Lookup::Miss));
    assert_eq!(repository.rows.lock().unwrap().len(), 1);
    struct Revoked;
    #[async_trait::async_trait]
    impl SemanticReadAuthority for Revoked {
        async fn revalidate(&self, _: &TrustedSemanticDomain) -> DomainResult<()> {
            Err(codec::corrupt())
        }
    }
    assert!(repository.lookup(&domain, &query(), &Revoked).await.is_err());
}
