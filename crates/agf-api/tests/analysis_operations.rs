//! Real SQL: poison-event quarantine, versioned operator recovery and retained history.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{enums::IngestProtocol, event::Event, ids::Id, rule::Detection};
use agf_ingest::pipeline::SqlSink;
use agf_storage::{Database, EventRepo, Store, objectstore::MemoryObjectStore};
use common::*;
const PATH: &str = "/api/v1/sources/analysis/failures";

#[tokio::test]
async fn recovery_requires_authentication_scope_and_sql() {
    let h = setup().await;
    assert_eq!(h.request("GET", PATH, None, None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(h.request_with("GET", PATH, &[("x-agf-key", &h.api_key)], None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(h.request("GET", PATH, Some(&h.admin), None).await.status, StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn quarantined_event_recovers_once_with_durable_operator_history() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap();
    let db = Database::from_pool(pool);
    db.migrate().await.unwrap();
    let db = Arc::new(Store::new(db, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.state.ingest_sink = Arc::new(SqlSink::new(db.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
    let tenant = agf_api::tenant_directory::new(
        format!("analysis-operations-{}", TenantId::new()),
        "Analysis recovery validation".into(),
    );
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    let mut rule = agf_api::state::fallback_rules().remove(0);
    rule.name = "Invalid SQL title\0private-marker-never-expose".into();
    rule.key = "analysis-operations".into();
    rule.detection = Detection::Keyword { any: vec!["recovery-poison-fixture".into()] };
    rule.samples.positive = vec!["recovery-poison-fixture".into()];
    rule.samples.negative = vec!["benign".into()];
    h.state.rules = Arc::new(agf_scan::loader::RulePackLoader::strict().load_inline(vec![rule.clone()]).unwrap());
    h.app = build_router(h.state.clone());
    let bearer = format!("Bearer {}", h.admin);
    let tenant_id = tenant.id.to_string();
    let headers = [("authorization", bearer.as_str()), ("x-agf-tenant", tenant_id.as_str())];
    let mut poison = Event::new(tenant.id, Id::new(), IngestProtocol::Webhook);
    poison.category = agf_core::event::EventCategory::AiSession;
    poison.message = "recovery-poison-fixture".into();
    let mut good = poison.clone();
    good.id = Id::new();
    good.message = "benign".into();
    let events = vec![poison.clone(), good];
    db.with_tenant(tenant.id, move |tx| Box::pin(async move { EventRepo::insert_batch(tx, &events).await }))
        .await
        .unwrap();
    for attempt in 1..=8 {
        due(&db, tenant.id).await;
        let result = agf_api::event_analysis::recover_pending(&h.state, tenant.id).await.unwrap();
        assert_eq!(result.0, usize::from(attempt == 1), "good events continue past failures");
    }
    due(&db, tenant.id).await;
    assert_eq!(agf_api::event_analysis::recover_pending(&h.state, tenant.id).await.unwrap().0, 0);
    let failures = h.request_with("GET", PATH, &headers, None).await;
    assert_eq!(failures.status, StatusCode::OK, "{}", failures.text);
    assert!(!failures.text.contains("private-marker-never-expose"));
    assert_eq!(failures.json()["total"], 1);
    let row = failures.json()["items"][0].clone();
    assert_eq!(row["state"], "quarantined");
    assert_eq!(row["attempts"], 8);
    let subject = format!("agf.events.{}.{}", tenant.id, poison.severity.as_str());
    let delivery = agf_api::event_analysis::process_delivery(
        &h.state,
        "agf.events",
        &subject,
        &serde_json::to_vec(&poison).unwrap(),
    )
    .await;
    assert!(matches!(delivery, Err(agf_core::error::DomainError::RateLimited(_))), "broker cannot bypass quarantine");
    let status = h.request_with("GET", "/api/v1/sources/delivery", &headers, None).await;
    assert_eq!(status.json()["analysis"]["quarantined"], 1);
    let url = format!("{PATH}/{}/retry", poison.id);
    let read_key = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("sources:read")],
        ..ApiKeyIssueRequest::named(tenant.id, "recovery-read-only", Timestamp::now())
    });
    h.state.store.api_key_create_durable(&read_key.record).await.unwrap();
    let read_only = h.request_with("GET", PATH, &[("x-agf-key", &read_key.plaintext)], None).await;
    assert_eq!(read_only.status, StatusCode::OK, "{}", read_only.text);
    assert_eq!(read_only.json()["can_manage"], false);
    assert_eq!(
        h.request_with("POST", &url, &[("x-agf-key", &read_key.plaintext)], Some(json!({"expected_version":8})))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let foreign = h.request("GET", &format!("{PATH}/{}/history", poison.id), Some(&h.admin), None).await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND);
    let pause_url = format!("{PATH}/{}/pause", poison.id);
    let (a, b) = tokio::join!(
        h.request_with("POST", &pause_url, &headers, Some(json!({"expected_version":8}))),
        h.request_with("POST", &pause_url, &headers, Some(json!({"expected_version":8})))
    );
    assert!(matches!(
        (a.status, b.status),
        (StatusCode::OK, StatusCode::CONFLICT) | (StatusCode::CONFLICT, StatusCode::OK)
    ));
    assert_eq!(agf_api::event_analysis::recover_pending(&h.state, tenant.id).await.unwrap().0, 0);
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
    rule.name = "Recovered rule".into();
    h.state.rules = Arc::new(agf_scan::loader::RulePackLoader::strict().load_inline(vec![rule]).unwrap());
    h.app = build_router(h.state.clone());
    let resumed = h.request_with("POST", &url, &headers, Some(json!({"expected_version":9}))).await;
    assert_eq!(resumed.status, StatusCode::OK, "{}", resumed.text);
    let (a, b) = tokio::join!(
        agf_api::event_analysis::recover_pending(&h.state, tenant.id),
        agf_api::event_analysis::recover_pending(&h.state, tenant.id)
    );
    a.unwrap();
    b.unwrap();
    let resolved = h.request_with("GET", &format!("{PATH}?state=resolved"), &headers, None).await;
    assert_eq!(resolved.json()["total"], 1);
    assert_eq!(resolved.json()["items"][0]["total_attempts"], 8);
    let history = h.request_with("GET", &format!("{PATH}/{}/history?page_size=1", poison.id), &headers, None).await;
    assert_eq!(history.json()["total"], 2);
    assert_eq!(history.json()["items"].as_array().unwrap().len(), 1);
    let counts:(i64,i64,i64)=db.with_tenant(tenant.id,|tx|Box::pin(async move{
        sqlx::query_as("SELECT (SELECT count(*) FROM findings),(SELECT count(*) FROM alerts),(SELECT count(*) FROM event_analysis_receipts)")
            .fetch_one(&mut **tx).await.map_err(|e|agf_storage::map_sqlx_err("recovery_counts",&e))
    })).await.unwrap();
    assert_eq!(counts, (1, 1, 2), "competing retries do not duplicate committed effects");
    assert_eq!(
        h.request_with("POST", &url, &headers, Some(json!({"expected_version":11}))).await.status,
        StatusCode::CONFLICT
    );

    // Keep an explicitly labelled, paused synthetic event for browser recovery acceptance.
    let mut browser = Event::new(tenant.id, Id::new(), IngestProtocol::Webhook);
    browser.message = "Synthetic browser recovery fixture: benign".into();
    let event_id = browser.id;
    db.with_tenant(tenant.id, move |tx|Box::pin(async move{
        EventRepo::insert_batch(tx,&[browser]).await?;
        sqlx::query("INSERT INTO event_analysis_retries(tenant_id,event_id,paused,error_code,last_error) VALUES ($1,$2,true,'analysis_failed','Synthetic browser recovery fixture')")
            .bind(tenant.id.as_uuid()).bind(event_id.as_uuid()).execute(&mut **tx).await
            .map_err(|e|agf_storage::map_sqlx_err("browser_recovery_fixture",&e))?;
        Ok(())
    })).await.unwrap();
}

async fn due(db: &Store, tenant: TenantId) {
    db.with_tenant(tenant, |tx| {
        Box::pin(async move {
            sqlx::query("UPDATE event_analysis_retries SET available_at=now()-interval '1 second'")
                .execute(&mut **tx)
                .await
                .map_err(|e| agf_storage::map_sqlx_err("retry_due", &e))?;
            Ok(())
        })
    })
    .await
    .unwrap();
}
