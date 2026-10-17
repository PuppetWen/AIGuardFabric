use super::{
    budget,
    configuration::{self, Mode, ProfileInput, Settings},
    endpoint, mock, plan, util,
};
use agf_core::{
    enums::DataClass,
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
};
use serde_json::json;

pub(super) fn settings(mode: Mode) -> Settings {
    Settings {
        chat_endpoint_id: Id::new(),
        chat_model: "owned-chat".into(),
        chat_model_revision: "owned-chat-revision-1".into(),
        embedding_endpoint_id: Id::new(),
        embedding_model: "owned-embedding".into(),
        embedding_model_revision: "revision-1".into(),
        dimensions: 64,
        send_dimensions: false,
        max_input_tokens: 8192,
        embedding_micro_per_1k: if mode == Mode::Live { 1000 } else { 0 },
        threshold_ppm: 950_000,
        ttl_seconds: 300,
        classification_floor: DataClass::Internal,
        mode,
    }
}

#[test]
fn absent_profile_never_automatically_enables_or_attests_placement() {
    let view = configuration::absent_view();
    assert!(!view.enabled && !view.placement_verified && !view.provider_weights_revision_verified);
    assert_eq!(view.version, 0);
    assert!(view.settings.is_none());
}

#[test]
fn create_update_and_disable_use_explicit_cas_without_implicit_enable() -> DomainResult<()> {
    let tenant = TenantId::default_tenant();
    let create = ProfileInput { expected_version: 0, enabled: false, settings: None };
    let first = create.apply(tenant, None)?;
    assert_eq!(first.version, 1);
    assert!(!first.enabled);
    assert!(matches!(create.apply(tenant, Some(&first)), Err(DomainError::Conflict(_))));
    let update = ProfileInput { expected_version: 1, enabled: true, settings: Some(settings(Mode::MockVector)) };
    let second = update.apply(tenant, Some(&first))?;
    assert_eq!(second.version, 2);
    assert!(second.enabled);
    let disabled = ProfileInput { expected_version: 2, enabled: false, settings: second.settings.clone() }
        .apply(tenant, Some(&second))?;
    assert_eq!(disabled.version, 3);
    assert!(!disabled.enabled);
    Ok(())
}

#[test]
fn profile_rejects_foreign_identity_revision_overflow_and_unmanaged_inputs() -> DomainResult<()> {
    let tenant = TenantId::default_tenant();
    let input = ProfileInput { expected_version: 0, enabled: false, settings: None };
    let mut row = input.apply(tenant, None)?;
    row.id = Id::new();
    assert!(row.validate(tenant).is_err());
    row.id = util::record_id(tenant);
    row.version = u64::MAX;
    assert!(
        ProfileInput { expected_version: u64::MAX, enabled: false, settings: None }.apply(tenant, Some(&row)).is_err()
    );
    for key in ["url", "authority", "domain", "api_key", "internal_placement_verified"] {
        let mut raw = json!({"expected_version":0,"enabled":false,"settings":null});
        raw[key] = json!("not-server-owned");
        assert!(serde_json::from_value::<ProfileInput>(raw).is_err());
    }
    Ok(())
}

#[test]
fn dimensions_price_threshold_and_ttl_are_bounded_before_preparation() {
    let good = settings(Mode::Live);
    assert!(good.validate().is_ok());
    let mut invalid = good.clone();
    invalid.dimensions = 0;
    assert!(invalid.validate().is_err());
    invalid = good.clone();
    invalid.dimensions = 4097;
    assert!(invalid.validate().is_err());
    invalid = good.clone();
    invalid.embedding_micro_per_1k = 0;
    assert!(invalid.validate().is_err());
    invalid = good.clone();
    invalid.embedding_micro_per_1k = u64::MAX;
    assert!(invalid.validate().is_err());
    invalid = good.clone();
    invalid.ttl_seconds = 901;
    assert!(invalid.validate().is_err());
    invalid = good.clone();
    invalid.threshold_ppm = 899_999;
    assert!(invalid.validate().is_err());
    invalid = good;
    invalid.threshold_ppm = 1_000_001;
    assert!(invalid.validate().is_err());
    assert_eq!(configuration::configured_cost(1, 1), Some(1));
    assert_eq!(configuration::configured_cost(8192, 1000), Some(8192));
}

#[test]
fn actual_agent_and_server_floor_cannot_be_lowered_by_public_client_hint() {
    let mut live = settings(Mode::Live);
    assert_eq!(plan::classify(&live, Some(DataClass::Public), DataClass::Public, None), None);
    live.classification_floor = DataClass::Public;
    assert_eq!(plan::classify(&live, None, DataClass::Public, None), None);
    assert_eq!(plan::classify(&live, Some(DataClass::Internal), DataClass::Public, None), None);
    assert_eq!(plan::classify(&live, Some(DataClass::Public), DataClass::Public, None), Some(DataClass::Public));
    assert_eq!(plan::classify(&live, Some(DataClass::Public), DataClass::Internal, None), None);
    assert_eq!(plan::classify(&live, Some(DataClass::Public), DataClass::Public, Some(DataClass::Confidential)), None);
}

#[test]
fn local_mock_explicitly_supports_internal_but_never_confidential_or_live_fallback() {
    let mut mock = settings(Mode::MockVector);
    assert!(mock.validate().is_ok());
    assert_eq!(plan::classify(&mock, None, DataClass::Public, None), Some(DataClass::Internal));
    assert_eq!(plan::classify(&mock, Some(DataClass::Confidential), DataClass::Public, None), None);
    mock.embedding_micro_per_1k = 1;
    assert!(mock.validate().is_err());
}

#[test]
fn exact_existing_root_or_v1_origin_mapping_rejects_path_credentials_and_http() -> DomainResult<()> {
    assert_eq!(endpoint::origin("https://example.test/v1")?, "https://example.test");
    assert_eq!(endpoint::origin("https://example.test/")?, "https://example.test");
    for raw in [
        "http://127.0.0.1:1234",
        "https://x.test/private/v1",
        "https://x.test/./v1",
        "https://x.test/v1/../v1",
        "https://user:secret@x.test/v1",
        "https://x.test/v1?q=secret",
        "https://x.test/%76%31",
        " https://x.test/v1",
        "https://x.test/v1#fragment",
    ] {
        assert!(endpoint::origin(raw).is_err());
    }
    Ok(())
}

#[test]
fn actual_mock_vector_is_order_invariant_normalized_and_not_a_vendor_model() -> DomainResult<()> {
    let first = mock::vector("secure private cache", 64)?;
    let second = mock::vector("CACHE secure private", 64)?;
    let different = mock::vector("completely unrelated request", 64)?;
    assert_eq!(first, second);
    assert_ne!(first, different);
    let norm = first.iter().map(|value| f64::from(*value).powi(2)).sum::<f64>();
    assert!((norm - 1.0).abs() < 1e-6);
    for invalid in ["", "   "] {
        assert!(mock::vector(invalid, 64).is_err());
    }
    assert!(mock::vector("text", 0).is_err());
    assert!(mock::vector(&"x".repeat(8193), 64).is_err());
    Ok(())
}

#[test]
fn canonical_source_fingerprint_preserves_all_nonprompt_values_and_float_shape() -> DomainResult<()> {
    let first = json!({"b":{"z":1,"a":2},"a":["system",0.0]});
    let reordered = json!({"a":["system",0.0],"b":{"a":2,"z":1}});
    assert_eq!(util::digest(&first)?, util::digest(&reordered)?);
    assert_ne!(util::digest(&first)?, util::digest(&json!({"a":["changed-system",0.0],"b":{"a":2,"z":1}}))?);
    Ok(())
}

#[test]
fn foreseeable_vector_and_evidence_storage_limits_refuse_before_paid_transport() -> DomainResult<()> {
    assert_eq!(budget::maximum(1024, 512, 64)?, 5632);
    assert!(budget::maximum(1024, 512, 4096).is_err());
    assert!(budget::maximum(usize::MAX, 1, 64).is_err());
    assert!(budget::maximum(24 * 1024, 0, 1).is_err());
    Ok(())
}
