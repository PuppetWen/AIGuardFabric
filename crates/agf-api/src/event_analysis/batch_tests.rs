//! Real isolated SQL tests; private stages make races deterministic without product test hooks.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use agf_core::{
    enums::IngestProtocol,
    event::EventCategory,
    ids::{TenantId, deterministic_id},
    rule::Detection,
};
use agf_ingest::pipeline::SqlSink;
use agf_storage::{Database, EventRepo, configuration::ConfigStore, objectstore::MemoryObjectStore};
use serde_json::json;
use std::{collections::BTreeMap, time::Duration};

async fn fixture() -> (AppState, Arc<Store>, TenantId, TenantId) {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&url).await.unwrap();
    let database = Database::from_pool(pool);
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let env: BTreeMap<String, String> = [
        ("AGF_ENV", "test"),
        ("AGF_MOCK_MODE", "1"),
        ("AGF_JWT_SECRET", "unit-test-secret-key-at-least-32-bytes-long"),
        ("AGF_JWT_ISSUER", "aiguardfabric"),
        ("AGF_PROJECT_ROOT", "."),
        ("AGF_MASTER_KEY_BASE64", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    let mut config = agf_core::config::from_env_map(&env).unwrap();
    config.data_dir = format!("./target/test-data/analysis-batch-{}", Id::new());
    let mut state = AppState::offline(config).unwrap();
    state.store = Arc::new(crate::store::ApiStore::with_database(store.clone()));
    state.ingest_sink = Arc::new(SqlSink::new(store.clone()));
    state.configurations = Arc::new(ConfigStore::new(Some(store.clone())));
    let mut rule = crate::state::fallback_rules().remove(0);
    rule.key = "batch-full-detector".into();
    rule.detection = Detection::Keyword { any: vec!["batch-security-warning".into()] };
    rule.samples.positive = vec!["batch-security-warning".into()];
    rule.samples.negative = vec!["batch-benign".into()];
    state.rules = Arc::new(agf_scan::loader::RulePackLoader::strict().load_inline(vec![rule]).unwrap());
    let (tenant, other) = (TenantId::new(), TenantId::new());
    for id in [tenant, other] {
        sqlx::query("INSERT INTO tenants(id,slug,name) VALUES($1,$2,'Analysis batch fixture')")
            .bind(id.as_uuid())
            .bind(format!("batch-{id}"))
            .execute(store.db().pool())
            .await
            .unwrap();
    }
    (state, store, tenant, other)
}

async fn save(store: &Store, tenant: TenantId, message: &str) -> Event {
    let mut event = Event::new(tenant, Id::new(), IngestProtocol::Otlp);
    event.category = EventCategory::AiSession;
    event.message = message.into();
    event.raw_hash = agf_core::secret::content_hash(message);
    let stored = event.clone();
    store.with_tenant(tenant, move |tx| Box::pin(async move { EventRepo::insert(tx, &stored).await })).await.unwrap();
    event
}

async fn receipts(store: &Store, tenant: TenantId) -> Vec<serde_json::Value> {
    store
        .with_tenant(tenant, |tx| {
            Box::pin(async move {
                sqlx::query_scalar(
                    "SELECT to_jsonb(r)||jsonb_build_object('txid',xmin::text)
            FROM event_analysis_receipts r ORDER BY event_id",
                )
                .fetch_all(&mut **tx)
                .await
                .map_err(|e| agf_storage::map_sqlx_err("batch_fixture_receipts", &e))
            })
        })
        .await
        .unwrap()
}

async fn detection(state: &AppState, tenant: TenantId, value: &impl serde::Serialize) {
    state
        .configurations
        .put(tenant, "detection-rules", deterministic_id("detection-rules", &tenant.to_string()), value)
        .await
        .unwrap();
}

async fn retry_row(store: &Store, event: &Event, paused: bool, attempts: i32, delay: i64) {
    let event = event.clone();
    store.with_tenant(event.tenant_id, move |tx| Box::pin(async move {
        sqlx::query("INSERT INTO event_analysis_retries(tenant_id,event_id,error_code,last_error,paused,attempts,available_at)
            VALUES($1,$2,'fixture','fixture', $3,$4,now()+($5 * interval '1 second'))")
            .bind(event.tenant_id.as_uuid()).bind(event.id.as_uuid()).bind(paused).bind(attempts).bind(delay)
            .execute(&mut **tx).await.map_err(|e| agf_storage::map_sqlx_err("batch_fixture_retry", &e))?;
        Ok(())
    })).await.unwrap();
}

async fn prepared(state: &AppState, store: &Arc<Store>, events: &[Event]) -> serde_json::Value {
    context::load_batch(state, store, events, true).await.unwrap().unwrap().snapshot.unwrap().identity().unwrap()
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn empty_batch_canonical_rls_pool_one_fingerprint_and_atomic_receipts() {
    let (state, store, tenant, other) = fixture().await;
    let mut events = Vec::new();
    for _ in 0..32 {
        events.push(save(&store, tenant, "batch-benign").await);
    }
    retry_row(&store, &events[0], false, 2, -1).await;
    let foreign = save(&store, other, "batch-security-warning").await;
    let mut forged = foreign.clone();
    forged.tenant_id = tenant;
    assert!(try_empty_batch(&state, &[forged], true).await.unwrap().is_none());
    assert!(receipts(&store, other).await.is_empty());
    // A routed message cannot replace committed evidence.
    for event in &mut events {
        event.message = "batch-security-warning".into();
    }
    let results = tokio::time::timeout(Duration::from_secs(10), process_batch(&state, &events)).await.unwrap().unwrap();
    assert_eq!(results.len(), 32);
    assert!(results.iter().all(|r| !r.duplicate && r.finding_ids.is_empty() && r.alert_ids.is_empty()));
    let rows = receipts(&store, tenant).await;
    assert_eq!(rows.len(), 32);
    assert!(rows.iter().all(|r| r["txid"] == rows[0]["txid"]), "not one atomic bulk commit");
    assert!(
        rows.iter().all(|r| r["rule_fingerprint"] == state.rules.report.pack_fingerprint
            && !r["notification_enqueued_at"].is_null())
    );
    let resolved: bool =
        sqlx::query_scalar("SELECT resolved_at IS NOT NULL FROM event_analysis_retries WHERE tenant_id=$1")
            .bind(tenant.as_uuid())
            .fetch_one(store.db().pool())
            .await
            .unwrap();
    assert!(resolved);
    assert!(receipts(&store, other).await.is_empty());
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn empty_batch_completed_precedes_time_registry_and_inbatch_duplicate_falls_back() {
    let (state, store, tenant, _) = fixture().await;
    let event = save(&store, tenant, "batch-benign").await;
    let result = process_batch(&state, &[event.clone(), event.clone()]).await.unwrap();
    assert_eq!(result.iter().map(|r| r.duplicate).collect::<Vec<_>>(), [false, true]);
    let first = receipts(&store, tenant).await;
    detection(&state, tenant, &json!({"entries":"invalid-fixture"})).await;
    let mut wrong_time = event;
    wrong_time.time = wrong_time.time.offset_secs(1);
    assert!(process_batch(&state, std::slice::from_ref(&wrong_time)).await.unwrap()[0].duplicate);
    retry_row(&store, &wrong_time, true, 1, -1).await;
    assert!(
        matches!(process_batch(&state, &[wrong_time]).await, Err(DomainError::RateLimited(_))),
        "broker deferred gate must precede even a completed receipt"
    );
    assert_eq!(receipts(&store, tenant).await, first);
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn empty_batch_deferred_precedes_bad_registry_and_preserves_handoff_attempts() {
    let (state, store, tenant, _) = fixture().await;
    let mut events = Vec::new();
    for (paused, attempts, delay) in [(true, 1, -1), (false, 2, 600), (false, 8, -1)] {
        let event = save(&store, tenant, "batch-benign").await;
        retry_row(&store, &event, paused, attempts, delay).await;
        events.push(event);
    }
    detection(&state, tenant, &json!({"entries":"invalid-fixture"})).await;
    for event in &events {
        assert!(try_empty_batch(&state, &[event.clone()], true).await.unwrap().is_none());
        assert!(matches!(process_batch(&state, &[event.clone()]).await, Err(DomainError::RateLimited(_))));
        assert!(
            process_or_defer_delivery(
                &state,
                "agf.events",
                &format!("agf.events.{}.{}", tenant, event.severity.as_str()),
                &serde_json::to_vec(event).unwrap()
            )
            .await
            .unwrap()
            .is_none()
        );
    }
    let attempts: Vec<(uuid::Uuid, i32)> =
        sqlx::query_as("SELECT event_id,attempts FROM event_analysis_retries WHERE tenant_id=$1")
            .bind(tenant.as_uuid())
            .fetch_all(store.db().pool())
            .await
            .unwrap();
    let attempts: BTreeMap<_, _> = attempts.into_iter().collect();
    let expected: BTreeMap<_, _> =
        events.iter().zip([1, 2, 8]).map(|(event, attempts)| (event.id.as_uuid(), attempts)).collect();
    assert_eq!(attempts, expected);
    assert!(receipts(&store, tenant).await.is_empty());
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn empty_batch_registry_publication_before_commit_has_zero_writes_and_next_revision() {
    let (state, store, tenant, _) = fixture().await;
    let event = save(&store, tenant, "batch-benign").await;
    let identity = prepared(&state, &store, &[event.clone()]).await;
    let mut definition = crate::correlation::samples::examples(tenant).remove(0);
    crate::correlation::registry::save(&state, tenant, "batch fixture".into(), definition.clone(), 0, false)
        .await
        .unwrap();
    assert!(
        commit::save_empty_batch(&store, &[event.clone()], &state.rules.report.pack_fingerprint, identity, true)
            .await
            .unwrap()
            .is_none()
    );
    assert!(receipts(&store, tenant).await.is_empty());
    let identity = prepared(&state, &store, &[event.clone()]).await;
    let mut rule = state.rules.rules[0].clone();
    rule.detection = Detection::Keyword { any: vec!["batch-benign".into()] };
    rule.samples.positive = vec!["batch-benign".into()];
    rule.samples.negative = vec!["different-safe-value".into()];
    let mut registry = crate::rule_store::Registry::default();
    registry.entries.insert(
        rule.key.clone(),
        vec![crate::rule_store::Revision {
            definition: rule,
            changed_at: agf_core::time::Timestamp::now(),
            actor: "published during preparation".into(),
        }],
    );
    detection(&state, tenant, &registry).await;
    assert!(
        commit::save_empty_batch(&store, &[event.clone()], &state.rules.report.pack_fingerprint, identity, true)
            .await
            .unwrap()
            .is_none()
    );
    assert!(receipts(&store, tenant).await.is_empty());
    assert_eq!(process_batch(&state, &[event]).await.unwrap()[0].finding_ids.len(), 1);
    let later = save(&store, tenant, "different-safe-value").await;
    definition.enabled = true;
    crate::correlation::registry::save(&state, tenant, "next correlation revision".into(), definition, 1, false)
        .await
        .unwrap();
    assert!(try_empty_batch(&state, &[later.clone()], true).await.unwrap().is_none());
    sqlx::query("UPDATE tenants SET enabled=false WHERE id=$1")
        .bind(tenant.as_uuid())
        .execute(store.db().pool())
        .await
        .unwrap();
    assert!(matches!(process_batch(&state, &[later]).await, Err(DomainError::Forbidden(_))));
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn empty_batch_conflict_wait_reads_winner_in_later_statement_and_leaves_its_retry() {
    let (state, store, tenant, _) = fixture().await;
    let event = save(&store, tenant, "batch-benign").await;
    retry_row(&store, &event, false, 3, -1).await;
    let identity = prepared(&state, &store, &[event.clone()]).await;
    let finding = Id::new();
    let alert = Id::new();
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    let mut winner =
        sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&url).await.unwrap().begin().await.unwrap();
    sqlx::query(
        "INSERT INTO event_analysis_receipts(tenant_id,event_id,event_time,rule_fingerprint,finding_ids,alert_ids)
        VALUES($1,$2,$3,'winner-fingerprint',$4,$5)",
    )
    .bind(tenant.as_uuid())
    .bind(event.id.as_uuid())
    .bind(event.time.as_datetime())
    .bind(json!([finding]))
    .bind(json!([alert]))
    .execute(&mut *winner)
    .await
    .unwrap();
    let cloned_store = store.clone();
    let fingerprint = state.rules.report.pack_fingerprint.clone();
    let task =
        tokio::spawn(
            async move { commit::save_empty_batch(&cloned_store, &[event], &fingerprint, identity, true).await },
        );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            sqlx::query("SELECT pg_stat_clear_snapshot()").execute(&mut *winner).await.unwrap();
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity
                WHERE datname=current_database() AND wait_event_type='Lock'
                AND query LIKE 'INSERT INTO event_analysis_receipts%')",
            )
            .fetch_one(&mut *winner)
            .await
            .unwrap();
            if blocked {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("batch never reached the real ON CONFLICT wait");
    winner.commit().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap().unwrap().unwrap();
    assert!(result[0].duplicate);
    assert_eq!(result[0].finding_ids, [finding]);
    assert_eq!(result[0].alert_ids, [alert]);
    let resolved: bool =
        sqlx::query_scalar("SELECT resolved_at IS NOT NULL FROM event_analysis_retries WHERE tenant_id=$1")
            .bind(tenant.as_uuid())
            .fetch_one(store.db().pool())
            .await
            .unwrap();
    assert!(!resolved, "duplicate receipts must retain original retry behavior");
    assert_eq!(receipts(&store, tenant).await[0]["rule_fingerprint"], "winner-fingerprint");
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn empty_batch_sql_failure_rolls_back_all_receipts_before_single_event_handoff() {
    let (state, store, tenant, _) = fixture().await;
    let first = save(&store, tenant, "batch-benign").await;
    let second = save(&store, tenant, "batch-benign").await;
    let identity = prepared(&state, &store, &[first.clone(), second.clone()]).await;
    let name = format!("batch_fail_{}", Id::new().to_string().replace('-', ""));
    let function = format!("CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NEW.tenant_id='{}'::uuid AND NEW.event_id='{}'::uuid THEN RAISE EXCEPTION 'owned batch fixture failure'; END IF;
        RETURN NEW; END $$", tenant, second.id);
    sqlx::query(&function).execute(store.db().pool()).await.unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER {name} BEFORE INSERT ON event_analysis_receipts FOR EACH ROW EXECUTE FUNCTION {name}()"
    ))
    .execute(store.db().pool())
    .await
    .unwrap();
    assert!(
        commit::save_empty_batch(
            &store,
            &[first.clone(), second.clone()],
            &state.rules.report.pack_fingerprint,
            identity,
            true
        )
        .await
        .is_err()
    );
    assert!(receipts(&store, tenant).await.is_empty());
    let handed_off = process_or_defer_delivery(
        &state,
        "agf.events",
        &format!("agf.events.{}.{}", tenant, second.severity.as_str()),
        &serde_json::to_vec(&second).unwrap(),
    )
    .await
    .unwrap();
    assert!(handed_off.is_none());
    assert!(receipts(&store, tenant).await.is_empty());
    sqlx::query(&format!("DROP TRIGGER {name} ON event_analysis_receipts")).execute(store.db().pool()).await.unwrap();
    sqlx::query(&format!("DROP FUNCTION {name}()")).execute(store.db().pool()).await.unwrap();
    assert!(!process(&state, &first).await.unwrap().duplicate);
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn empty_batch_finding_and_correlation_fallback_keep_prior_rule_evidence_order() {
    use agf_correlate::temporal::{CorrelationRule, RuleStep, TemporalRule};
    let (state, store, tenant, _) = fixture().await;
    let mut definition = crate::correlation::samples::examples(tenant).remove(0);
    let mut previous = definition.positive[0].clone();
    previous.category = EventCategory::AiSession;
    let current = definition.positive[1].clone();
    previous.message = "batch-security-warning".into();
    previous.raw_hash = agf_core::secret::content_hash(&previous.message);
    let mut step = RuleStep::required("Prior full detector finding", 1);
    step.rule_keys = vec!["batch-full-detector".into()];
    definition.rule = CorrelationRule::Temporal(
        TemporalRule::new(
            "batch-ordered-evidence",
            "Batch order",
            300,
            vec![step, RuleStep::required("Network", 1).with_categories(&["network"])],
            agf_core::enums::Severity::High,
        )
        .ordered(),
    );
    definition.enabled = true;
    // Registry samples validate the rule; runtime prior rule keys must come from the completed receipt.
    let mut sample_previous = previous.clone();
    sample_previous.ai.rule_keys = vec!["batch-full-detector".into()];
    definition.positive = vec![sample_previous, current.clone()];
    definition.negative = vec![current.clone()];
    let benign = save(&store, tenant, "batch-benign").await;
    let warmup_warning = save(&store, tenant, "batch-security-warning").await;
    let first = process_batch(&state, &[benign, warmup_warning]).await.unwrap();
    assert!(first[0].finding_ids.is_empty());
    assert_eq!(first[1].finding_ids.len(), 1, "full detection cannot take the empty shortcut");
    crate::correlation::registry::save(&state, tenant, "ordered batch fixture".into(), definition, 0, false)
        .await
        .unwrap();
    for stored in [previous.clone(), current.clone()] {
        store
            .with_tenant(tenant, move |tx| Box::pin(async move { EventRepo::insert(tx, &stored).await }))
            .await
            .unwrap();
    }
    // This verifies processing order, not global broker/source-time order. Both canonical rows
    // already exist, and original correlation history may see a later event before its receipt.
    let name = format!("batch_order_{}", Id::new().to_string().replace('-', ""));
    let function = format!("CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NEW.tenant_id='{}'::uuid AND NEW.event_id='{}'::uuid AND NOT EXISTS(
            SELECT 1 FROM event_analysis_receipts r CROSS JOIN LATERAL jsonb_array_elements_text(r.finding_ids) k(value)
            JOIN findings f ON f.id=k.value::uuid WHERE r.event_id='{}'::uuid AND f.rule_keys @> '[\"batch-full-detector\"]'::jsonb)
        THEN RAISE EXCEPTION 'previous complete receipt and detector evidence not visible'; END IF;
        RETURN NEW; END $$", tenant, current.id, previous.id);
    sqlx::query(&function).execute(store.db().pool()).await.unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER {name} BEFORE INSERT ON event_analysis_receipts FOR EACH ROW EXECUTE FUNCTION {name}()"
    ))
    .execute(store.db().pool())
    .await
    .unwrap();
    let results = process_batch(&state, &[previous.clone(), current.clone()]).await.unwrap();
    sqlx::query(&format!("DROP TRIGGER {name} ON event_analysis_receipts")).execute(store.db().pool()).await.unwrap();
    sqlx::query(&format!("DROP FUNCTION {name}()")).execute(store.db().pool()).await.unwrap();
    assert!(!results[0].duplicate && !results[1].duplicate);
    let mut correlations = Vec::new();
    let mut base_count = 0;
    for result in &results {
        for id in &result.finding_ids {
            let id = *id;
            let finding = store
                .with_tenant(tenant, move |tx| Box::pin(async move { agf_storage::FindingRepo::get(tx, id).await }))
                .await
                .unwrap()
                .unwrap();
            if finding.source_origin == "correlation-analysis" {
                correlations.push(finding);
            } else {
                base_count += 1;
            }
        }
    }
    assert_eq!(base_count, 1);
    assert_eq!(correlations.len(), 1, "later processing duplicated the existing correlation chain");
    let finding = &correlations[0];
    let evidence: Vec<_> = finding.evidence.iter().filter_map(|e| e.artifact_ref.as_deref()).collect();
    assert!(evidence.iter().any(|r| r.ends_with(&previous.id.to_string())));
    assert!(evidence.iter().any(|r| r.ends_with(&current.id.to_string())));
    assert_eq!(receipts(&store, tenant).await.len(), 4);
}
