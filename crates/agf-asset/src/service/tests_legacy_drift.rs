//! Legacy comparisons must retain the first observation without manufacturing history entries.
#![allow(clippy::unwrap_used)]
use super::*;

#[tokio::test]
async fn same_day_discovery_cannot_erase_the_baseline_or_duplicate_history() {
    let tenant = TenantId::default_tenant();
    let backend = InMemoryAssetBackend::new();
    let service = AssetService::new();
    let today = Date::today().to_iso();
    let mut batch = batch_with(tenant, vec![("mcp", AssetKind::McpServer, "stdio:original")]);
    service.ingest(&backend, tenant, &batch).await.unwrap();
    let baseline = backend.snapshot_hashes(tenant, &today).await.unwrap();
    batch.assets[0].endpoint = Some("stdio:replacement".into());
    service.ingest(&backend, tenant, &batch).await.unwrap();
    assert_eq!(backend.snapshot_hashes(tenant, &today).await.unwrap(), baseline);
    let history_count = backend.change_count().unwrap();
    let (_, first) = service.snapshot_and_drift(&backend, tenant, Some(&today)).await.unwrap();
    let (_, second) = service.snapshot_and_drift(&backend, tenant, Some(&today)).await.unwrap();
    assert_eq!(first.summary.modified, 1);
    assert_eq!(first.changes[0].id, second.changes[0].id);
    assert_eq!(backend.change_count().unwrap(), history_count);
    assert_eq!(backend.snapshot_hashes(tenant, &today).await.unwrap(), baseline);
}

#[tokio::test]
async fn invalid_dates_fail_before_creating_snapshots() {
    let tenant = TenantId::default_tenant();
    let backend = InMemoryAssetBackend::new();
    let service = AssetService::new();
    let asset = Asset::new(tenant, AssetKind::Skill, "Unobserved", "manual");
    backend.upsert(tenant, &asset).await.unwrap();
    for date in ["not-a-date", "2026-02-30", "9999-01-01", "2026-1-01"] {
        assert!(service.snapshot_and_drift(&backend, tenant, Some(date)).await.is_err());
    }
    assert!(backend.snapshot_hashes(tenant, &Date::today().to_iso()).await.unwrap().is_empty());
    assert_eq!(backend.change_count().unwrap(), 0);
}
