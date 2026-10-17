//! Real memory ConfigStore witnesses distinguish fixed capacity from corrupt authority.
use super::*;
use serde_json::json;

async fn capture(store: &ConfigStore, tenant: TenantId, records: usize, bytes: usize) -> DomainResult<Capture> {
    Source::capture_records(store, tenant, false, "owned-rule-fingerprint".into(), Bounds { records, bytes }).await
}

#[tokio::test]
async fn complete_absence_is_atomic_but_cardinality_across_kinds_is_only_a_typed_bypass() -> DomainResult<()> {
    let store = ConfigStore::new(None);
    let tenant = TenantId::default_tenant();
    assert!(matches!(capture(&store, tenant, 0, 0).await?, Capture::Ready(_)));
    for _ in 0..2 {
        let id = Id::new();
        store.put(tenant, "case-containment", id, &json!({"tenant_id":tenant,"id":id})).await?;
    }
    let endpoint = Id::new();
    store.put(tenant, "model-endpoint", endpoint, &json!({"endpoint":{"tenant_id":tenant,"id":endpoint}})).await?;
    assert!(matches!(capture(&store, tenant, 2, 8192).await?, Capture::Bypass(Bypass::Cardinality)));
    assert!(matches!(capture(&store, tenant, 3, 8192).await?, Capture::Ready(_)));
    assert_eq!(store.list::<Value>(tenant, "case-containment").await?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn full_encoded_bytes_across_kinds_never_capture_a_prefix_or_mutate_source() -> DomainResult<()> {
    let store = ConfigStore::new(None);
    let tenant = TenantId::default_tenant();
    let case = Id::new();
    let endpoint = Id::new();
    let first = json!({"id":case,"tenant_id":tenant,"text":"中文\n"});
    let second = json!({"endpoint":{"id":endpoint,"tenant_id":tenant}});
    let budget = serde_json::to_vec(&first)?.len() + serde_json::to_vec(&second)?.len();
    store.put(tenant, "case-containment", case, &first).await?;
    store.put(tenant, "model-endpoint", endpoint, &second).await?;
    assert!(matches!(capture(&store, tenant, 2, budget - 1).await?, Capture::Bypass(Bypass::EncodedBytes)));
    assert!(matches!(capture(&store, tenant, 2, budget).await?, Capture::Ready(_)));
    assert_eq!(store.list::<Value>(tenant, "case-containment").await?, vec![first]);
    assert_eq!(store.list::<Value>(tenant, "model-endpoint").await?, vec![second]);
    Ok(())
}

#[tokio::test]
async fn foreign_or_nil_authority_is_an_error_never_legacy_capacity_bypass() -> DomainResult<()> {
    let store = ConfigStore::new(None);
    let tenant = TenantId::default_tenant();
    let id = Id::new();
    store.put(tenant, "model-endpoint", id, &json!({"endpoint":{"id":id,"tenant_id":TenantId::new()}})).await?;
    assert!(capture(&store, tenant, 512, 8 * 1024 * 1024).await.is_err());
    store.put(tenant, "model-endpoint", id, &json!({"endpoint":{"id":Id::nil(),"tenant_id":tenant}})).await?;
    assert!(capture(&store, tenant, 512, 8 * 1024 * 1024).await.is_err());
    assert!(capture(&store, TenantId::from_uuid(uuid::Uuid::nil()), 512, 8 * 1024 * 1024).await.is_err());
    Ok(())
}

#[test]
fn singleton_lock_identity_rejects_a_noncanonical_stored_row() {
    let expected = agf_core::ids::Id::new();
    assert!(super::locked_ids_match("detection-rules", &[], &[expected]));
    assert!(super::locked_ids_match("detection-rules", &[expected], &[expected]));
    assert!(!super::locked_ids_match("detection-rules", &[agf_core::ids::Id::new()], &[expected]));
    assert!(!super::locked_ids_match("model-endpoint", &[], &[expected]));
}
