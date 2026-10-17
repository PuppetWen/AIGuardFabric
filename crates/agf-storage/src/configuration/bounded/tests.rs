use super::*;
use serde_json::json;

#[tokio::test]
async fn zero_limit_proves_absence_and_nonempty_collection_never_returns_prefix() -> DomainResult<()> {
    let store = ConfigStore::new(None);
    let tenant = TenantId::default_tenant();
    assert!(
        matches!(store.list_bounded::<Value>(tenant,"owned-witness",0,0).await?, BoundedConfigurationList::Complete(rows) if rows.is_empty())
    );
    store.put(tenant, "owned-witness", Id::new(), &json!({"id":"first"})).await?;
    store.put(tenant, "owned-witness", Id::new(), &json!({"id":"second"})).await?;
    assert!(matches!(
        store.list_bounded::<Value>(tenant, "owned-witness", 1, 8192).await?,
        BoundedConfigurationList::TooMany
    ));
    assert!(
        matches!(store.list_bounded::<Value>(tenant,"owned-witness",2,8192).await?, BoundedConfigurationList::Complete(rows) if rows.len()==2)
    );
    Ok(())
}

#[tokio::test]
async fn escaped_utf8_encoded_size_is_exact_and_limits_never_disclose_a_partial_row() -> DomainResult<()> {
    let store = ConfigStore::new(None);
    let tenant = TenantId::default_tenant();
    let payload = json!({"safe":"中文\u{0001}\n"});
    let size = serde_json::to_vec(&payload)?.len();
    store.put(tenant, "owned-witness", Id::new(), &payload).await?;
    assert!(matches!(
        store.list_bounded::<Value>(tenant, "owned-witness", 1, size - 1).await?,
        BoundedConfigurationList::TooLarge
    ));
    assert!(
        matches!(store.list_bounded::<Value>(tenant,"owned-witness",1,size).await?, BoundedConfigurationList::Complete(rows) if rows==vec![payload])
    );
    Ok(())
}

#[tokio::test]
async fn complete_witness_is_tenant_isolated_and_does_not_mutate_configuration() -> DomainResult<()> {
    let store = ConfigStore::new(None);
    let first = TenantId::default_tenant();
    let second = TenantId::new();
    store.put(first, "owned-witness", Id::new(), &json!({"owner":first})).await?;
    store.put(second, "owned-witness", Id::new(), &json!({"owner":second})).await?;
    let before = store.list::<Value>(first, "owned-witness").await?;
    assert!(
        matches!(store.list_bounded::<Value>(first,"owned-witness",1,8192).await?, BoundedConfigurationList::Complete(rows) if rows==before)
    );
    assert_eq!(store.list::<Value>(first, "owned-witness").await?, before);
    assert!(store.list_bounded::<Value>(first, "owned-witness", 513, 8192).await.is_err());
    assert!(store.list_bounded::<Value>(first, "owned-witness", 1, 8 * 1024 * 1024 + 1).await.is_err());
    Ok(())
}

#[test]
fn allocation_free_counter_stops_before_oversized_json_payload_completes() -> DomainResult<()> {
    let large = json!({"body":"x".repeat(128*1024)});
    assert_eq!(encoded_size(&large, 1024)?, None);
    let exact = serde_json::to_vec(&large)?.len();
    assert_eq!(encoded_size(&large, exact)?, Some(exact));
    Ok(())
}
