//! Stable admission data and original TTL do not grant renewed model or cache authority.
use super::{codec, semantic_plan::*, source, tests_fixture::fixture};
use agf_core::{
    asset::Asset,
    enums::{AssetKind, DataClass},
    error::DomainResult,
    ids::Id,
};
use agf_storage::semantic_response_cache::{ConfigurationFence, ServerSemanticEvidence};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn evidence(fact: &super::records::Fact) -> DomainResult<ServerSemanticEvidence> {
    let endpoint = fact.charge.as_ref().ok_or_else(super::store::missing)?.endpoint;
    Ok(ServerSemanticEvidence {
        tenant: fact.origin.tenant,
        identity_tenant: fact.origin.identity_tenant,
        subject_id: fact.origin.subject,
        subject_kind: "api_key".into(),
        session: None,
        agent_id: None,
        department: None,
        data_class: DataClass::Public,
        internal_placement_verified: false,
        chat_endpoint: endpoint,
        chat_model: "owned-model".into(),
        chat_model_revision: "revision-1".into(),
        embedding_endpoint: Id::new(),
        embedding_model: "owned-embedding".into(),
        embedding_model_revision: "embedding-1".into(),
        dimensions: 2,
        transport_mode: "live".into(),
        cache_configuration_version: 1,
        fences: vec![ConfigurationFence::from_server_record(
            "model-endpoint",
            endpoint,
            1,
            &json!({"revision":1,"encrypted":"owned"}),
        )?],
        fixed_request: json!({"temperature":0}),
        authority_deadline_ms: 0,
    })
}
fn result() -> DomainResult<(super::records::Fact, CacheResult)> {
    let f = fixture(1_800_000_000)?;
    let plan = CachePlan::capture(evidence(&f.fact)?, vec![1.0, 0.5], 60, "a".repeat(64))?;
    let created_ms = f.fact.submitted_at.unix_millis() + 1000;
    let row = CacheResult {
        id: cache_id(&f.fact),
        plan,
        created_ms,
        expires_ms: created_ms + 60000,
        response: json!({"id":"owned-reply","model":"owned-model","message":{"role":"assistant","content":"ok"},
            "finish_reason":"stop","usage":{"prompt_tokens":4,"completion_tokens":3}}),
    };
    row.validate(&f.fact)?;
    Ok((f.fact, row))
}
#[test]
fn staged_admission_preserves_id_and_never_renews_original_ttl() -> DomainResult<()> {
    let (fact, row) = result()?;
    let restored: CacheResult = serde_json::from_value(serde_json::to_value(&row)?)?;
    restored.validate(&fact)?;
    assert_eq!(row.id, restored.admission(30)?.id());
    assert_eq!(restored.remaining_ttl(row.created_ms + 30500), Some(29));
    assert_eq!(restored.remaining_ttl(row.expires_ms - 999), None);
    assert_eq!(restored.remaining_ttl(row.expires_ms), None);
    let other = fixture(1_800_000_000)?;
    assert!(restored.validate(&other.fact).is_err());
    Ok(())
}
#[test]
fn semantic_admission_rejects_raw_partial_unknown_vector_or_changed_identity() -> DomainResult<()> {
    let (fact, row) = result()?;
    let mut changed = row.clone();
    changed.response["raw"] = json!({"private":"must-never-stage"});
    assert!(changed.validate(&fact).is_err());
    changed = row.clone();
    changed.response["finish_reason"] = json!("length");
    assert!(changed.validate(&fact).is_err());
    changed = row.clone();
    changed.plan.vector[0] = f32::NAN;
    assert!(changed.validate(&fact).is_err());
    changed = row.clone();
    changed.id = Id::new();
    assert!(changed.validate(&fact).is_err());
    changed = row;
    changed.expires_ms += 1;
    assert!(changed.validate(&fact).is_err());
    Ok(())
}
#[test]
fn same_version_full_content_change_is_a_different_fence() -> DomainResult<()> {
    let (_, row) = result()?;
    let original = &row.plan.profile.fences[0];
    let actual = ConfigurationFence::from_server_record(
        &original.kind,
        original.id,
        original.version,
        &json!({"revision":1,"encrypted":"changed"}),
    )?;
    assert!(!fence_matches(original, &actual)?);
    assert_ne!(original.witness, codec::hash(&actual)?);
    Ok(())
}
#[test]
fn canonical_union_order_uses_actual_rule_key_and_deduplicates_cache_keys() -> DomainResult<()> {
    let (fact, row) = result()?;
    let tenant = fact.origin.tenant;
    let rules = source::record_ids("detection-rules", tenant, &[])?;
    assert_eq!(rules, vec![agf_core::ids::deterministic_id("detection-rules", &tenant.to_string())]);
    assert_ne!(rules[0], crate::model_routes::tenant_record_id(tenant));
    let endpoint = row.plan.profile.fences[0].id;
    let keys = BTreeMap::from([("model-endpoint".into(), vec![endpoint]), ("detection-rules".into(), rules.clone())]);
    assert_eq!(
        source::lock_order(&keys, Some(&row.plan)),
        vec![("detection-rules".into(), rules[0]), ("model-endpoint".into(), endpoint)]
    );
    assert!(source::record_ids("model-endpoint", tenant, &[json!({"endpoint":{"id":Id::nil()}})]).is_err());
    let empty: Vec<Value> = vec![];
    assert!(source::record_ids("model-endpoint", tenant, &empty)?.is_empty());
    Ok(())
}
#[test]
fn agent_safety_fences_classification_and_department_but_not_telemetry() -> DomainResult<()> {
    let tenant = agf_core::ids::TenantId::default_tenant();
    let mut asset = Asset::new(tenant, AssetKind::Agent, "owned-agent", "owned-agent");
    let original = super::agent::AgentSafety::from_asset(tenant, asset.id, &asset)?;
    asset.exposure_score = 99;
    asset.last_seen_at = None;
    asset.name = "renamed".into();
    assert!(super::agent::AgentSafety::from_asset(tenant, asset.id, &asset)? == original);
    assert_eq!(original.raise_class(DataClass::Public), DataClass::Internal);
    asset.department = Some("different".into());
    assert!(super::agent::AgentSafety::from_asset(tenant, asset.id, &asset)? != original);
    asset.department = None;
    asset.data_class = DataClass::Confidential;
    assert!(super::agent::AgentSafety::from_asset(tenant, asset.id, &asset)? != original);
    asset.deleted_at = Some(agf_core::time::Timestamp::now());
    assert!(super::agent::AgentSafety::from_asset(tenant, asset.id, &asset).is_err());
    Ok(())
}
