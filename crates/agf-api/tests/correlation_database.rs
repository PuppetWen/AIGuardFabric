//! SQL 历史在新实例重建，乱序时序、跨源图和基线均实际进入发现与告警。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::tenant_directory;
use agf_core::{event::Event, ids::Id};
use agf_ingest::pipeline::SqlSink;
use agf_storage::{AuditRepo, Database, EventRepo, Store, objectstore::MemoryObjectStore};
use common::*;

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn all_four_shapes_persist_with_history_recovery_and_duplicate_protection() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap();
    let db = Database::from_pool(pool);
    db.migrate().await.unwrap();
    let db = Arc::new(Store::new(db, None, Arc::new(MemoryObjectStore::new())));
    for kind in 0..4 {
        let tenant = TenantId::new();
        sqlx::query("INSERT INTO tenants(id,slug,name) VALUES ($1,$2,'Correlation validation')")
            .bind(tenant.as_uuid())
            .bind(format!("correlation-{tenant}"))
            .execute(db.db().pool())
            .await
            .unwrap();
        let mut h = setup().await;
        h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
        h.state.ingest_sink = Arc::new(SqlSink::new(db.clone()));
        h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
        let mut definition = agf_api::correlation::samples::examples(tenant).remove(kind);
        definition.enabled = true;
        let key = definition.rule.key().to_owned();
        agf_api::correlation::registry::save(&h.state, tenant, "SQL test".into(), definition.clone(), 0, false)
            .await
            .unwrap();
        let mut events = definition.positive;
        // 时序规则先收较晚的网络事件，再补到较早的认证事件。
        if kind == 0 {
            events.reverse();
        }
        for event in &events[..events.len() - 1] {
            persist(&db, event).await;
            agf_api::event_analysis::process(&h.state, event).await.unwrap();
        }
        let event = events.last().unwrap().clone();
        // 新状态实例只有 SQL，未沿用进程中的发现/规则/画像缓存。
        let mut fresh = h.state.clone();
        fresh.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
        fresh.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
        persist(&db, &event).await;
        let (a, b) = tokio::join!(
            agf_api::event_analysis::process(&fresh, &event),
            agf_api::event_analysis::process(&fresh, &event)
        );
        let a = a.unwrap();
        let b = b.unwrap();
        assert_ne!(a.duplicate, b.duplicate);
        assert_eq!(a.alert_ids, b.alert_ids);
        let findings = fresh.store.finding_list_all_durable(tenant).await.unwrap();
        let matched: Vec<_> = findings
            .iter()
            .filter(|f| f.source_origin == "correlation-analysis" && f.rule_keys == vec![key.clone()])
            .collect();
        assert_eq!(matched.len(), 1, "shape {kind}: {findings:?}");
        let finding = matched[0];
        assert!(finding.evidence.len() >= 2);
        let alert = fresh.store.alert_get_durable(tenant, a.alert_ids[0]).await.unwrap().unwrap();
        assert!(alert.finding_ids.contains(&finding.id));
        assert!(alert.event_ids.contains(&event.id));
        assert!(fresh.store.finding_get_durable(TenantId::new(), finding.id).await.unwrap().is_none());
        let counts = fresh.store.alert_list_durable(tenant, None, None).await.unwrap().len();
        assert!(agf_api::event_analysis::process(&fresh, &event).await.unwrap().duplicate);
        assert_eq!(fresh.store.alert_list_durable(tenant, None, None).await.unwrap().len(), counts);
    }
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn publishing_correlation_rule_rolls_back_with_failed_audit() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap();
    let database = Database::from_pool(pool.clone());
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(store)));
    let tenant = tenant_directory::new(format!("correlation-audit-{}", Id::new()), "Correlation audit".into());
    tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.app = build_router(h.state.clone());
    let token = format!("Bearer {}", h.admin);
    let tenant_id = tenant.id.to_string();
    let headers = [("authorization", token.as_str()), ("x-agf-tenant", tenant_id.as_str())];
    let mut definition = agf_api::correlation::samples::examples(tenant.id).remove(0);
    definition.enabled = true;
    let key = definition.rule.key().to_owned();
    let payload = json!({"definition":definition,"expected_version":0});
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    let chain_before = AuditRepo::chain_stats(&mut tx).await.unwrap();
    tx.commit().await.unwrap();

    let constraint = format!("agf_test_correlation_audit_{}", Id::new().as_uuid().simple());
    sqlx::query(&format!(
        "ALTER TABLE audit_logs ADD CONSTRAINT {constraint} CHECK (tenant_id <> '{}'::uuid) NOT VALID",
        tenant.id
    ))
    .execute(&pool)
    .await
    .unwrap();
    let failed = h.request_with("POST", "/api/v1/correlation/rules", &headers, Some(payload.clone())).await;
    assert!(!failed.status.is_success(), "{}", failed.text);
    assert!(agf_api::correlation::registry::get(&h.state, tenant.id).await.unwrap().entries.is_empty());
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    assert_eq!(AuditRepo::chain_stats(&mut tx).await.unwrap(), chain_before);
    tx.commit().await.unwrap();
    sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}")).execute(&pool).await.unwrap();

    let saved = h.request_with("POST", "/api/v1/correlation/rules", &headers, Some(payload.clone())).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.json()["current"]["version"], 1);
    let audit = h.request_with("GET", "/api/v1/audit?actor=correlation-rule&action=configure", &headers, None).await;
    assert_eq!(audit.json()["total"], 1);
    assert_eq!(audit.json()["items"][0]["target"]["id"], key);
    let stale = h.request_with("POST", "/api/v1/correlation/rules", &headers, Some(payload)).await;
    assert_eq!(stale.status, StatusCode::CONFLICT);
    let audit = h.request_with("GET", "/api/v1/audit?actor=correlation-rule&action=configure", &headers, None).await;
    assert_eq!(audit.json()["total"], 1);

    definition.enabled = false;
    let removed = h
        .request_with(
            "POST",
            "/api/v1/correlation/rules",
            &headers,
            Some(json!({"definition":definition,"expected_version":1,"deleted":true})),
        )
        .await;
    assert_eq!(removed.status, StatusCode::OK, "{}", removed.text);
    assert_eq!(removed.json()["current"]["deleted"], true);
    let audit = h.request_with("GET", "/api/v1/audit?actor=correlation-rule&action=delete", &headers, None).await;
    assert_eq!(audit.json()["total"], 1);
    assert_eq!(audit.json()["items"][0]["target"]["id"], key);
    pool.close().await;
}

async fn persist(db: &Store, event: &Event) {
    let event = event.clone();
    db.with_tenant(event.tenant_id, move |tx| Box::pin(async move { EventRepo::insert(tx, &event).await }))
        .await
        .unwrap();
}
