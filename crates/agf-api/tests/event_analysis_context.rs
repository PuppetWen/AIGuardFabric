//! Authoritative input transaction regressions; each case owns fresh tenant rows.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{
    enums::IngestProtocol,
    error::DomainError,
    event::{Event, EventCategory},
    ids::{Id, deterministic_id},
    rule::Detection,
    time::Timestamp,
};
use agf_ingest::pipeline::SqlSink;
use agf_storage::{Database, EventRepo, Store, configuration::ConfigStore, objectstore::MemoryObjectStore};
use common::*;
use std::time::Duration;

async fn fixture(shared_configuration: bool) -> (Harness, Arc<Store>) {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    // A nested directory/configuration pool checkout would deadlock this fixture.
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&url).await.unwrap();
    let db = Database::from_pool(pool);
    db.migrate().await.unwrap();
    let db = Arc::new(Store::new(db, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.tenant = TenantId::new();
    h.other_tenant = TenantId::new();
    for tenant in [h.tenant, h.other_tenant] {
        sqlx::query("INSERT INTO tenants(id,slug,name) VALUES($1,$2,'Analysis input transaction fixture')")
            .bind(tenant.as_uuid())
            .bind(format!("analysis-context-{tenant}"))
            .execute(db.db().pool())
            .await
            .unwrap();
    }
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.state.ingest_sink = Arc::new(SqlSink::new(db.clone()));
    h.state.configurations = Arc::new(ConfigStore::new(shared_configuration.then(|| db.clone())));
    let mut rule = agf_api::state::fallback_rules().remove(0);
    rule.key = "context-base-rule".into();
    rule.name = "Context complete detector".into();
    rule.detection = Detection::Keyword { any: vec!["base-context-warning".into()] };
    rule.samples.positive = vec!["base-context-warning".into()];
    rule.samples.negative = vec!["benign-context".into()];
    h.state.rules = Arc::new(agf_scan::loader::RulePackLoader::strict().load_inline(vec![rule]).unwrap());
    (h, db)
}

async fn save(db: &Store, tenant: TenantId, message: &str) -> Event {
    let mut event = Event::new(tenant, Id::new(), IngestProtocol::Otlp);
    event.category = EventCategory::AiSession;
    event.message = message.into();
    event.raw_hash = agf_core::secret::content_hash(message);
    let stored = event.clone();
    db.with_tenant(tenant, move |tx| Box::pin(async move { EventRepo::insert(tx, &stored).await })).await.unwrap();
    event
}

async fn deliver(h: &Harness, event: &Event) -> Result<agf_api::event_analysis::AnalysisResult, DomainError> {
    tokio::time::timeout(
        Duration::from_secs(5),
        agf_api::event_analysis::process_delivery(
            &h.state,
            "agf.events",
            &format!("agf.events.{}.{}", event.tenant_id, event.severity.as_str()),
            &serde_json::to_vec(event).unwrap(),
        ),
    )
    .await
    .expect("analysis retained the only pool connection across a nested lookup")
}

async fn put_detection(h: &Harness, registry: &impl serde::Serialize) {
    h.state
        .configurations
        .put(h.tenant, "detection-rules", deterministic_id("detection-rules", &h.tenant.to_string()), registry)
        .await
        .unwrap();
}

async fn receipt(db: &Store, event: &Event) -> (i64, Option<String>) {
    let tenant = event.tenant_id;
    let id = event.id;
    db.with_tenant(tenant, move |tx| {
        Box::pin(async move {
            sqlx::query_as("SELECT count(*),min(rule_fingerprint) FROM event_analysis_receipts WHERE event_id=$1")
                .bind(id.as_uuid())
                .fetch_one(&mut **tx)
                .await
                .map_err(|e| agf_storage::map_sqlx_err("context_fixture", &e))
        })
    })
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn shared_context_single_connection_preserves_canonical_and_completed_short_circuit() {
    let (h, db) = fixture(true).await;
    let event = save(&db, h.tenant, "benign-context").await;
    let mut forged = event.clone();
    forged.message = "base-context-warning".into();
    let result = deliver(&h, &forged).await.unwrap();
    assert!(result.finding_ids.is_empty(), "broker message replaced canonical evidence");
    assert!(!result.duplicate);
    let first = receipt(&db, &event).await;
    assert_eq!(first.0, 1);
    // A completed receipt must win before configuration parsing or the event-time lookup.
    put_detection(&h, &json!({"entries":"invalid-registry-fixture"})).await;
    forged.time = forged.time.offset_secs(1);
    assert!(deliver(&h, &forged).await.unwrap().duplicate);
    assert_eq!(receipt(&db, &event).await, first);
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn shared_context_deferred_short_circuit_avoids_invalid_registry_and_preserves_attempts() {
    let (h, db) = fixture(true).await;
    let event = save(&db, h.tenant, "base-context-warning").await;
    let tenant = h.tenant;
    let id = event.id;
    db.with_tenant(tenant, move |tx| {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO event_analysis_retries(tenant_id,event_id,error_code,last_error,paused)
            VALUES($1,$2,'fixture','fixture retry',true)",
            )
            .bind(tenant.as_uuid())
            .bind(id.as_uuid())
            .execute(&mut **tx)
            .await
            .map_err(|e| agf_storage::map_sqlx_err("context_fixture_retry", &e))?;
            Ok(())
        })
    })
    .await
    .unwrap();
    put_detection(&h, &json!({"entries":"invalid-registry-fixture"})).await;
    assert!(matches!(deliver(&h, &event).await, Err(DomainError::RateLimited(_))));
    let result = agf_api::event_analysis::process_or_defer_delivery(
        &h.state,
        "agf.events",
        &format!("agf.events.{}.{}", tenant, event.severity.as_str()),
        &serde_json::to_vec(&event).unwrap(),
    )
    .await
    .unwrap();
    assert!(result.is_none());
    let attempts: i32 = db
        .with_tenant(tenant, move |tx| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT attempts FROM event_analysis_retries WHERE event_id=$1")
                    .bind(id.as_uuid())
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(|e| agf_storage::map_sqlx_err("context_attempts", &e))
            })
        })
        .await
        .unwrap();
    assert_eq!(attempts, 1);
    assert_eq!(receipt(&db, &event).await.0, 0);
    sqlx::query("UPDATE tenants SET enabled=false WHERE id=$1")
        .bind(tenant.as_uuid())
        .execute(db.db().pool())
        .await
        .unwrap();
    assert!(
        matches!(deliver(&h, &event).await, Err(DomainError::Forbidden(_))),
        "disabled tenant is rejected before the shared deferred lookup"
    );
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn shared_context_matches_memory_configuration_authority_and_next_revision() {
    let (sql, sql_db) = fixture(true).await;
    let (memory, memory_db) = fixture(false).await;
    let mut definition = sql.state.rules.rules[0].clone();
    definition.detection = Detection::Keyword { any: vec!["configured-context-first".into()] };
    definition.samples.positive = vec!["configured-context-first".into()];
    let mut registry = agf_api::rule_store::Registry::default();
    registry.entries.insert(
        definition.key.clone(),
        vec![agf_api::rule_store::Revision {
            definition: definition.clone(),
            changed_at: Timestamp::now(),
            actor: "context fixture".into(),
        }],
    );
    for h in [&sql, &memory] {
        put_detection(h, &registry).await;
    }
    let first_sql = save(&sql_db, sql.tenant, "configured-context-first").await;
    let first_memory = save(&memory_db, memory.tenant, "configured-context-first").await;
    let a = deliver(&sql, &first_sql).await.unwrap();
    let b = deliver(&memory, &first_memory).await.unwrap();
    assert_eq!((a.finding_ids.len(), a.alert_ids.len()), (1, 1));
    assert_eq!((b.finding_ids.len(), b.alert_ids.len()), (1, 1));
    let first_fingerprint = receipt(&sql_db, &first_sql).await.1;
    assert_eq!(first_fingerprint, receipt(&memory_db, &first_memory).await.1);
    definition.detection = Detection::Keyword { any: vec!["configured-context-next".into()] };
    definition.samples.positive = vec!["configured-context-next".into()];
    registry.entries.get_mut(&definition.key).unwrap().push(agf_api::rule_store::Revision {
        definition,
        changed_at: Timestamp::now(),
        actor: "next published fixture revision".into(),
    });
    for h in [&sql, &memory] {
        put_detection(h, &registry).await;
    }
    let next_sql = save(&sql_db, sql.tenant, "configured-context-next").await;
    let next_memory = save(&memory_db, memory.tenant, "configured-context-next").await;
    assert_eq!(deliver(&sql, &next_sql).await.unwrap().finding_ids.len(), 1);
    assert_eq!(deliver(&memory, &next_memory).await.unwrap().finding_ids.len(), 1);
    let next_fingerprint = receipt(&sql_db, &next_sql).await.1;
    assert_ne!(next_fingerprint, first_fingerprint, "prepared input became a permanent registry cache");
    assert_eq!(next_fingerprint, receipt(&memory_db, &next_memory).await.1);
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn shared_context_cross_tenant_reference_is_not_canonical_evidence() {
    let (h, db) = fixture(true).await;
    let foreign = save(&db, h.other_tenant, "base-context-warning").await;
    let mut forged = foreign.clone();
    forged.tenant_id = h.tenant;
    assert!(matches!(deliver(&h, &forged).await, Err(DomainError::NotFound { entity: "committed-event", .. })));
    assert!(
        agf_api::event_analysis::process_or_defer_delivery(
            &h.state,
            "agf.events",
            &format!("agf.events.{}.{}", h.tenant, forged.severity.as_str()),
            &serde_json::to_vec(&forged).unwrap()
        )
        .await
        .is_err()
    );
    assert_eq!(receipt(&db, &foreign).await.0, 0);
    assert_eq!(receipt(&db, &forged).await.0, 0);
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn shared_context_invalid_canonical_is_retained_for_recovery() {
    let (h, db) = fixture(true).await;
    let event = save(&db, h.tenant, "base-context-warning").await;
    let tenant = event.tenant_id;
    let id = event.id;
    db.with_tenant(tenant, move |tx| {
        Box::pin(async move {
            sqlx::query("UPDATE events SET ai='\"invalid-canonical-fixture\"'::jsonb WHERE id=$1")
                .bind(id.as_uuid())
                .execute(&mut **tx)
                .await
                .map_err(|e| agf_storage::map_sqlx_err("context_corrupt_fixture", &e))?;
            Ok(())
        })
    })
    .await
    .unwrap();
    assert!(matches!(deliver(&h, &event).await, Err(DomainError::Parse(_))));
    assert!(
        agf_api::event_analysis::process_or_defer_delivery(
            &h.state,
            "agf.events",
            &format!("agf.events.{}.{}", tenant, event.severity.as_str()),
            &serde_json::to_vec(&event).unwrap()
        )
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(receipt(&db, &event).await.0, 0);
    let rows: i64 = db
        .with_tenant(tenant, move |tx| {
            Box::pin(async move {
                sqlx::query_scalar(
                    "SELECT count(*) FROM event_analysis_retries WHERE event_id=$1 AND resolved_at IS NULL",
                )
                .bind(id.as_uuid())
                .fetch_one(&mut **tx)
                .await
                .map_err(|e| agf_storage::map_sqlx_err("context_retry", &e))
            })
        })
        .await
        .unwrap();
    assert_eq!(rows, 1);
    let later = save(&db, tenant, "benign-context").await;
    assert!(deliver(&h, &later).await.unwrap().finding_ids.is_empty());
    assert_eq!(receipt(&db, &later).await.0, 1);
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn shared_context_missing_registry_equals_builtin_and_foreign_store_is_not_substituted() {
    let (mut h, db) = fixture(true).await;
    let builtin = save(&db, h.tenant, "base-context-warning").await;
    assert_eq!(deliver(&h, &builtin).await.unwrap().finding_ids.len(), 1);
    let other_store = Arc::new(Store::new(db.db().clone(), None, Arc::new(MemoryObjectStore::new())));
    h.state.configurations = Arc::new(ConfigStore::new(Some(other_store)));
    assert!(!h.state.configurations.uses_database(&db));
    let mut definition = h.state.rules.rules[0].clone();
    definition.detection = Detection::Keyword { any: vec!["separate-authority-context".into()] };
    definition.samples.positive = vec!["separate-authority-context".into()];
    let mut registry = agf_api::rule_store::Registry::default();
    registry.entries.insert(
        definition.key.clone(),
        vec![agf_api::rule_store::Revision {
            definition,
            changed_at: Timestamp::now(),
            actor: "separate Store fixture".into(),
        }],
    );
    put_detection(&h, &registry).await;
    let event = save(&db, h.tenant, "separate-authority-context").await;
    assert_eq!(deliver(&h, &event).await.unwrap().finding_ids.len(), 1);
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn shared_context_correlation_publication_is_visible_on_the_next_event() {
    let (h, db) = fixture(true).await;
    let mut definition = agf_api::correlation::samples::examples(h.tenant).remove(0);
    let previous = definition.positive[0].clone();
    let current = definition.positive[1].clone();
    agf_api::correlation::registry::save(
        &h.state,
        h.tenant,
        "disabled fixture revision".into(),
        definition.clone(),
        0,
        false,
    )
    .await
    .unwrap();
    let stored = previous.clone();
    db.with_tenant(h.tenant, move |tx| Box::pin(async move { EventRepo::insert(tx, &stored).await })).await.unwrap();
    assert!(deliver(&h, &previous).await.unwrap().finding_ids.is_empty());
    definition.enabled = true;
    agf_api::correlation::registry::save(&h.state, h.tenant, "enabled fixture revision".into(), definition, 1, false)
        .await
        .unwrap();
    let stored = current.clone();
    db.with_tenant(h.tenant, move |tx| Box::pin(async move { EventRepo::insert(tx, &stored).await })).await.unwrap();
    let result = deliver(&h, &current).await.unwrap();
    assert_eq!(result.finding_ids.len(), 1, "prior disabled revision was reused after publication");
    let id = result.finding_ids[0];
    let finding = db
        .with_tenant(h.tenant, move |tx| Box::pin(async move { agf_storage::FindingRepo::get(tx, id).await }))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(finding.source_origin, "correlation-analysis");
    let references: Vec<_> = finding.evidence.iter().filter_map(|e| e.artifact_ref.as_deref()).collect();
    assert!(references.iter().any(|value| value.ends_with(&previous.id.to_string())));
    assert!(references.iter().any(|value| value.ends_with(&current.id.to_string())));
}
