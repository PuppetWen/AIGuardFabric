//! 由 `service.rs` 拆分：`batch_with` 等 14 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn batch_with(tenant: TenantId, items: Vec<(&str, AssetKind, &str)>) -> DiscoveryBatch {
    let mut b = DiscoveryBatch::new(tenant, DiscoverySource::AgentReport);
    for (name, kind, endpoint) in items {
        let mut d = DiscoveredAsset::new(kind, name, format!("fp-{name}"), DiscoverySource::AgentReport);
        d.endpoint = Some(endpoint.to_string());
        b.assets.push(d);
    }
    b
}

#[tokio::test]
pub(crate) async fn ingest_creates_assets_idempotently() {
    let tenant = TenantId::default_tenant();
    let svc = AssetService::new();
    let backend = InMemoryAssetBackend::new();
    let batch = batch_with(tenant, vec![("fs-mcp", AssetKind::McpServer, "stdio:npx")]);

    let s1 = svc.ingest(&backend, tenant, &batch).await;
    assert!(s1.is_ok());
    let Ok(s1) = s1 else { return };
    assert_eq!(s1.created, 1);
    assert_eq!(backend.asset_count().ok(), Some(1));

    // 再次入库同一指纹：不重复创建
    let s2 = svc.ingest(&backend, tenant, &batch).await.unwrap_or_else(|_| unreachable!());
    assert_eq!(s2.created, 0);
    assert_eq!(backend.asset_count().ok(), Some(1));
    assert_eq!(s2.unchanged + s2.updated, 1);
}

#[tokio::test]
pub(crate) async fn ingest_records_risky_change_for_new_mcp() {
    let tenant = TenantId::default_tenant();
    let svc = AssetService::new();
    let backend = InMemoryAssetBackend::new();
    let batch = batch_with(tenant, vec![("new-mcp", AssetKind::McpServer, "stdio:npx")]);
    let stats = svc.ingest(&backend, tenant, &batch).await.unwrap_or_default();
    assert_eq!(stats.risky_changes, 1);
    assert!(stats.needs_attention());
    let changes = backend.changes().unwrap_or_default();
    assert!(changes.iter().any(|c| c.risky && c.domain == Some(agf_core::enums::RiskDomain::ToolAbuse)));
}

#[tokio::test]
pub(crate) async fn ingest_detects_endpoint_change() {
    let tenant = TenantId::default_tenant();
    let svc = AssetService::new();
    let backend = InMemoryAssetBackend::new();
    let first = batch_with(tenant, vec![("mcp", AssetKind::McpServer, "stdio:npx-ok")]);
    assert!(svc.ingest(&backend, tenant, &first).await.is_ok());

    let second = batch_with(tenant, vec![("mcp", AssetKind::McpServer, "stdio:npx-evil")]);
    let stats = svc.ingest(&backend, tenant, &second).await.unwrap_or_default();
    assert_eq!(stats.updated, 1, "端点变化应计为更新");
    assert_eq!(stats.unchanged, 0);
    // 回归：字段差分必须**落台账**（曾经算完就丢，导致"内容变了的既有资产"在
    // 资产变更页里查不到，风险回溯断链）
    assert!(stats.changes >= 1, "内容变化应产出变更记录: {stats:?}");
    let assets = backend.list_all(tenant).await.unwrap_or_default();
    let target_id = assets.first().map(|a| a.id).unwrap_or_default();
    let changes = backend.changes().unwrap_or_default();
    assert!(changes.iter().any(|c| c.asset_id == target_id), "变更台账应包含该资产: {changes:?}");
}

#[tokio::test]
pub(crate) async fn ingest_preserves_manual_ownership_and_lifecycle() {
    let tenant = TenantId::default_tenant();
    let svc = AssetService::new();
    let backend = InMemoryAssetBackend::new();
    let batch = batch_with(tenant, vec![("mcp", AssetKind::McpServer, "stdio:npx")]);
    assert!(svc.ingest(&backend, tenant, &batch).await.is_ok());

    // 人工评审：流转到生产并设置归属
    let assets = backend.list_all(tenant).await.unwrap_or_default();
    let id = assets[0].id;
    let mut t = LifecycleTransition::new(id, LifecycleState::Production, "secops", "评审通过");
    t.owner = Some("alice".to_string());
    t.data_class = Some(agf_core::enums::DataClass::Internal);
    assert!(svc.transition(&backend, tenant, &t).await.is_ok());

    // 再次发现不应覆盖人工设置
    assert!(svc.ingest(&backend, tenant, &batch).await.is_ok());
    let after = backend.find(tenant, id).await.unwrap_or(None);
    let Some(after) = after else { return };
    assert_eq!(after.lifecycle, LifecycleState::Production);
    assert_eq!(after.owner.as_deref(), Some("alice"));
}

#[tokio::test]
pub(crate) async fn transition_rejects_invalid_path() {
    let tenant = TenantId::default_tenant();
    let svc = AssetService::new();
    let backend = InMemoryAssetBackend::new();
    let batch = batch_with(tenant, vec![("mcp", AssetKind::McpServer, "stdio:npx")]);
    assert!(svc.ingest(&backend, tenant, &batch).await.is_ok());
    let assets = backend.list_all(tenant).await.unwrap_or_default();
    let id = assets[0].id;
    // trial → production 合法；production → trial 非法
    let mut ok = LifecycleTransition::new(id, LifecycleState::Production, "op", "上线");
    ok.owner = Some("alice".into());
    ok.data_class = Some(agf_core::enums::DataClass::Internal);
    assert!(svc.transition(&backend, tenant, &ok).await.is_ok());
    let back = LifecycleTransition::new(id, LifecycleState::Trial, "op", "回退");
    let res = svc.transition(&backend, tenant, &back).await;
    assert!(matches!(res.err(), Some(DomainError::Conflict(_))));
}

#[tokio::test]
pub(crate) async fn transition_to_production_requires_owner_and_class() {
    let tenant = TenantId::default_tenant();
    let svc = AssetService::new();
    let backend = InMemoryAssetBackend::new();
    let batch = batch_with(tenant, vec![("mcp", AssetKind::McpServer, "stdio:npx")]);
    assert!(svc.ingest(&backend, tenant, &batch).await.is_ok());
    let assets = backend.list_all(tenant).await.unwrap_or_default();
    let t = LifecycleTransition::new(assets[0].id, LifecycleState::Production, "op", "上线");
    let res = svc.transition(&backend, tenant, &t).await;
    assert!(matches!(res.err(), Some(DomainError::Validation(_))), "缺少归属人/分级必须拒绝");
}

#[tokio::test]
pub(crate) async fn transition_missing_asset_returns_not_found() {
    let tenant = TenantId::default_tenant();
    let svc = AssetService::new();
    let backend = InMemoryAssetBackend::new();
    let t = LifecycleTransition::new(Id::new(), LifecycleState::UnderReview, "op", "x");
    let res = svc.transition(&backend, tenant, &t).await;
    assert!(matches!(res.err(), Some(DomainError::NotFound { .. })));
}

#[tokio::test]
pub(crate) async fn inventory_computes_distribution() {
    let tenant = TenantId::default_tenant();
    let svc = AssetService::new();
    let backend = InMemoryAssetBackend::new();
    let mut batch = batch_with(
        tenant,
        vec![
            ("a", AssetKind::Agent, "stdio:x"),
            ("m1", AssetKind::McpServer, "stdio:m1"),
            ("m2", AssetKind::McpServer, "stdio:m2"),
        ],
    );
    batch.assets[0].exposure_score = 80;
    assert!(svc.ingest(&backend, tenant, &batch).await.is_ok());
    let stats = svc.inventory(&backend, tenant).await.unwrap_or_default();
    assert_eq!(stats.total, 3);
    assert_eq!(stats.by_kind.get("mcp-server"), Some(&2));
    assert_eq!(stats.by_kind.get("agent"), Some(&1));
    assert!(stats.shadow >= 1, "试用状态资产应计入影子资产");
    assert!(stats.avg_exposure > 0.0);
}

#[tokio::test]
pub(crate) async fn snapshot_and_drift_detects_new_asset() {
    let tenant = TenantId::default_tenant();
    let svc = AssetService::new();
    let backend = InMemoryAssetBackend::new();
    // 先建立"昨天"的基线（空集合 → 只有空快照）
    let (n0, _) = svc
        .snapshot_and_drift(&backend, tenant, Some("2026-01-01"))
        .await
        .unwrap_or((0, DriftReport::new(tenant, "", "", vec![])));
    assert_eq!(n0, 0);

    let batch = batch_with(tenant, vec![("mcp", AssetKind::McpServer, "stdio:npx")]);
    assert!(svc.ingest(&backend, tenant, &batch).await.is_ok());
    let (n1, report) =
        svc.snapshot_and_drift(&backend, tenant, Some("2026-01-01")).await.unwrap_or_else(|_| unreachable!());
    assert_eq!(n1, 1);
    assert!(report.summary.added >= 1, "与空基线对比应检出新增");
    assert!(report.summary.needs_attention());
}

#[tokio::test]
pub(crate) async fn drift_clean_when_nothing_changed() {
    let tenant = TenantId::default_tenant();
    let svc = AssetService::new();
    let backend = InMemoryAssetBackend::new();
    let batch = batch_with(tenant, vec![("mcp", AssetKind::McpServer, "stdio:npx")]);
    assert!(svc.ingest(&backend, tenant, &batch).await.is_ok());
    let today = Date::today().to_iso();
    assert!(svc.snapshot_and_drift(&backend, tenant, Some(&today)).await.is_ok());
    let (_, report) = svc.snapshot_and_drift(&backend, tenant, Some(&today)).await.unwrap_or_else(|_| unreachable!());
    assert_eq!(report.summary.total, 0, "同一天两次快照不应产生漂移");
}

#[test]
pub(crate) fn stale_trial_and_silent_agent_detection() {
    let tenant = TenantId::default_tenant();
    let now = Timestamp::now();
    let mut stale = Asset::new(tenant, AssetKind::McpServer, "old-trial", "fp1");
    stale.created_at = now.offset_secs(-90 * 86_400);
    stale.lifecycle = LifecycleState::Trial;
    let mut fresh = Asset::new(tenant, AssetKind::McpServer, "new", "fp2");
    fresh.lifecycle = LifecycleState::Trial;
    let pool = vec![stale, fresh.clone()];
    let stale_hits = AssetService::stale_trial_assets(&pool, 30, now);
    assert_eq!(stale_hits.len(), 1);

    let mut silent = Asset::new(tenant, AssetKind::Agent, "agent", "fp3");
    silent.last_seen_at = Some(now.offset_secs(-10_000));
    let mut alive = Asset::new(tenant, AssetKind::Agent, "agent2", "fp4");
    alive.last_seen_at = Some(now);
    let agents = vec![silent, alive];
    let silent_hits = AssetService::silent_agents(&agents, 3_600, now);
    assert_eq!(silent_hits.len(), 1);
}

#[test]
pub(crate) fn lifecycle_transition_validation_for_production() {
    let t = LifecycleTransition::new(Id::new(), LifecycleState::Production, "op", "x");
    assert!(t.validate_for_production().is_err());
    let mut t2 = t.clone();
    t2.owner = Some("alice".into());
    t2.data_class = Some(agf_core::enums::DataClass::Internal);
    assert!(t2.validate_for_production().is_ok());
    let t3 = LifecycleTransition::new(Id::new(), LifecycleState::Trial, "op", "x");
    assert!(t3.validate_for_production().is_ok(), "非生产流转无需这些字段");
}

#[test]
pub(crate) fn inventory_stats_severity_levels() {
    let tenant = TenantId::default_tenant();
    let mut many = Vec::new();
    for i in 0..8 {
        let mut a = Asset::new(tenant, AssetKind::McpServer, format!("m{i}"), format!("fp{i}"));
        a.exposure_score = 90;
        many.push(a);
    }
    assert_eq!(InventoryStats::from_assets(&many).severity(), Severity::High);
    assert_eq!(InventoryStats::from_assets(&[]).severity(), Severity::Low);
    many[0].attributes.insert("has_plaintext_secret".into(), serde_json::json!(false));
    many[1].attributes.insert("has_plaintext_secret".into(), serde_json::json!(true));
    many[2].attributes.insert("hasPlaintextSecret".into(), serde_json::json!(true));
    assert_eq!(InventoryStats::from_assets(&many).with_plaintext_secret, 2);
}
