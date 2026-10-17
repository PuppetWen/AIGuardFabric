//! Real SQL verifies stable case URLs, atomic timelines and competing case ownership.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{
    enums::{CaseState, Severity},
    ids::Id,
};
use agf_storage::{AuditRepo, CaseRepo, Database, Store, objectstore::MemoryObjectStore};
use common::*;

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn case_identity_timeline_and_alert_links_survive_concurrency_and_restart() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(10).connect(&url).await.unwrap();
    let db = Database::from_pool(pool);
    db.migrate().await.unwrap();
    let db = Arc::new(Store::new(db, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
    let tenant =
        agf_api::tenant_directory::new(format!("case-durability-{}", Id::new()), "Case durability validation".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.app = build_router(h.state.clone());
    let bearer = format!("Bearer {}", h.admin);
    let tenant_id = tenant.id.to_string();
    let headers = [("authorization", bearer.as_str()), ("x-agf-tenant", tenant_id.as_str())];
    let create = h.request_with("POST", "/api/v1/cases", &headers, Some(json!({"title":"Stable case URL"}))).await;
    assert_eq!(create.status, StatusCode::CREATED, "{}", create.text);
    let id = Id::parse(create.json()["case"]["id"].as_str().unwrap()).unwrap();
    let case_url = format!("/api/v1/cases/{id}");
    let saved = db
        .with_tenant(tenant.id, move |tx| Box::pin(async move { CaseRepo::get(tx, id, false).await }))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(saved.id, id, "API ID already exists in SQL before the response");
    assert_eq!(create.json()["case"]["code"], saved.code);
    let failed =
        h.state.store.case_set_state_durable(tenant.id, id, CaseState::Investigating, None, "bad\0actor").await;
    assert!(failed.is_err());
    assert_eq!(h.state.store.case_get_durable(tenant.id, id).await.unwrap().unwrap().state, CaseState::New);
    assert_eq!(
        h.state.store.case_events_durable(tenant.id, id).await.unwrap().len(),
        1,
        "timeline failure rolls back state"
    );
    let failed = h
        .state
        .store
        .case_create_durable(
            tenant.id,
            "Rollback creation",
            "",
            Severity::Medium,
            &[],
            &[],
            &[],
            None,
            "bad\0actor",
            None,
        )
        .await;
    assert!(failed.is_err());
    assert_eq!(
        h.state.store.case_list_durable(tenant.id).await.unwrap().len(),
        1,
        "timeline failure rolls back the entire new case"
    );

    let creations = futures::future::join_all((0..4).map(|index| {
        h.request_with("POST", "/api/v1/cases", &headers, Some(json!({"title":format!("Concurrent case {index}")})))
    }))
    .await;
    let mut codes = std::collections::BTreeSet::new();
    for response in creations {
        assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
        assert!(codes.insert(response.json()["case"]["code"].as_str().unwrap().to_owned()));
    }
    let state_url = format!("{case_url}/state");
    let (a, b) = tokio::join!(
        h.request_with("POST", &state_url, &headers, Some(json!({"state":"investigating"}))),
        h.request_with("POST", &state_url, &headers, Some(json!({"state":"investigating"})))
    );
    assert_eq!(a.status, StatusCode::OK, "{}", a.text);
    assert_eq!(b.status, StatusCode::OK, "{}", b.text);
    assert_eq!(
        h.state.store.case_events_durable(tenant.id, id).await.unwrap().len(),
        2,
        "same-state redelivery does not duplicate timeline entries"
    );
    assert_eq!(
        h.request_with("POST", &state_url, &headers, Some(json!({"state":"new"}))).await.status,
        StatusCode::CONFLICT
    );
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.app = build_router(h.state.clone());
    let detail = h.request_with("GET", &case_url, &headers, None).await;
    assert_eq!(detail.status, StatusCode::OK, "{}", detail.text);
    assert_eq!(detail.json()["case"]["id"], id.to_string());
    assert_eq!(detail.json()["case"]["state"], "investigating");
    let timeline = h.request_with("GET", &format!("{case_url}/timeline"), &headers, None).await;
    assert_eq!(timeline.json()["events"].as_array().unwrap().len(), 2);
    assert!(timeline.json()["events"][1]["actor"].as_str().unwrap().starts_with("user:"));
    assert_eq!(h.request("GET", &case_url, Some(&h.admin), None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        h.request("GET", &format!("{case_url}/timeline"), Some(&h.admin), None).await.status,
        StatusCode::NOT_FOUND
    );
    let due = Timestamp::now().offset_secs(600);
    h.state.store.case_set_sla_durable(tenant.id, id, Some(due), true).await.unwrap();
    let store = agf_api::store::ApiStore::with_database(db.clone());
    let same = store.case_get_durable(tenant.id, id).await.unwrap().unwrap();
    assert_eq!(same.sla_due_at.as_ref().map(Timestamp::unix_secs), Some(due.unix_secs()));
    assert!(same.sla_breached);

    // Replayed legacy creation preserves the ID and does not overwrite a later state.
    let replay = saved.clone();
    let replayed = db
        .with_tenant(tenant.id, move |tx| Box::pin(async move { CaseRepo::insert_identity(tx, &replay).await }))
        .await
        .unwrap();
    assert_eq!(replayed.id, id);
    assert_eq!(replayed.state, CaseState::Investigating);
    let mut imported = saved.clone();
    imported.id = Id::new();
    let import_id = imported.id;
    let imported = db
        .with_tenant(tenant.id, move |tx| Box::pin(async move { CaseRepo::insert_identity(tx, &imported).await }))
        .await
        .unwrap();
    assert_eq!(imported.id, import_id);
    assert_ne!(imported.code, saved.code, "colliding display number must not replace the stable ID");

    let (alert, _) = db
        .with_tenant(tenant.id, |tx| {
            Box::pin(async move {
                agf_storage::AlertRepo::upsert_dedup(
                    tx,
                    "case-link-fixture",
                    "Case link",
                    "",
                    Severity::Medium,
                    None,
                    &[],
                    &[],
                    None,
                )
                .await
            })
        })
        .await
        .unwrap();
    let before = store.case_list_durable(tenant.id).await.unwrap().len();
    let body = Some(json!({"title":"Exclusive alert case","alert_ids":[alert]}));
    let (a, b) = tokio::join!(
        h.request_with("POST", "/api/v1/cases", &headers, body.clone()),
        h.request_with("POST", "/api/v1/cases", &headers, body)
    );
    assert!(
        matches!(
            (a.status, b.status),
            (StatusCode::CREATED, StatusCode::CONFLICT) | (StatusCode::CONFLICT, StatusCode::CREATED)
        ),
        "{} / {}",
        a.text,
        b.text
    );
    assert_eq!(
        store.case_list_durable(tenant.id).await.unwrap().len(),
        before + 1,
        "losing alert ownership rolls back its new case"
    );
    let linked = store.alert_get_durable(tenant.id, alert).await.unwrap().unwrap().case_id.unwrap();
    assert_eq!(store.case_get_durable(tenant.id, linked).await.unwrap().unwrap().alert_ids, vec![alert]);

    let (audit_alert, _) = db
        .with_tenant(tenant.id, |tx| {
            Box::pin(async move {
                agf_storage::AlertRepo::upsert_dedup(
                    tx,
                    "case-audit-rollback-fixture",
                    "Audit rollback alert",
                    "",
                    Severity::Medium,
                    None,
                    &[],
                    &[],
                    None,
                )
                .await
            })
        })
        .await
        .unwrap();
    let cases_before = store.case_list_durable(tenant.id).await.unwrap().len();
    let mut tx = db.db().begin_tenant(tenant.id).await.unwrap();
    let audit_before = AuditRepo::chain_stats(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    let constraint = format!("agf_test_case_audit_{}", Id::new().as_uuid().simple());
    sqlx::query(&format!(
        "ALTER TABLE audit_logs ADD CONSTRAINT {constraint} CHECK (tenant_id <> '{}'::uuid) NOT VALID",
        tenant.id
    ))
    .execute(db.db().pool())
    .await
    .unwrap();
    let rejected = h
        .request_with(
            "POST",
            "/api/v1/cases",
            &headers,
            Some(json!({"title":"No ghost case","alert_ids":[audit_alert]})),
        )
        .await;
    assert!(!rejected.status.is_success(), "{}", rejected.text);
    assert_eq!(store.case_list_durable(tenant.id).await.unwrap().len(), cases_before);
    assert_eq!(store.alert_get_durable(tenant.id, audit_alert).await.unwrap().unwrap().case_id, None);
    let mut tx = db.db().begin_tenant(tenant.id).await.unwrap();
    assert_eq!(AuditRepo::chain_stats(&mut tx).await.unwrap(), audit_before);
    tx.commit().await.unwrap();
    sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}")).execute(db.db().pool()).await.unwrap();
    let recovered = h
        .request_with(
            "POST",
            "/api/v1/cases",
            &headers,
            Some(json!({"title":"Audited case","alert_ids":[audit_alert]})),
        )
        .await;
    assert_eq!(recovered.status, StatusCode::CREATED, "{}", recovered.text);
    let id = recovered.json()["case"]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        store.alert_get_durable(tenant.id, audit_alert).await.unwrap().unwrap().case_id,
        Some(Id::parse(&id).unwrap())
    );
    let audit = h.request_with("GET", &format!("/api/v1/audit?actor=case-create&q={id}"), &headers, None).await;
    assert_eq!(audit.status, StatusCode::OK, "{}", audit.text);
    assert_eq!(audit.json()["items"][0]["target"]["id"], id);
    let mut tx = db.db().begin_tenant(tenant.id).await.unwrap();
    assert_eq!(AuditRepo::chain_stats(&mut tx).await.unwrap().0, audit_before.0 + 1);
    tx.commit().await.unwrap();

    let case_id = Id::parse(&id).unwrap();
    let timeline_before = store.case_events_durable(tenant.id, case_id).await.unwrap().len();
    let mut tx = db.db().begin_tenant(tenant.id).await.unwrap();
    let audit_before = AuditRepo::chain_stats(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    let constraint = format!("agf_test_case_state_audit_{}", Id::new().as_uuid().simple());
    sqlx::query(&format!(
        "ALTER TABLE audit_logs ADD CONSTRAINT {constraint} CHECK (tenant_id <> '{}'::uuid) NOT VALID",
        tenant.id
    ))
    .execute(db.db().pool())
    .await
    .unwrap();
    let state_url = format!("/api/v1/cases/{id}/state");
    let rejected = h.request_with("POST", &state_url, &headers, Some(json!({"state":"investigating"}))).await;
    assert!(!rejected.status.is_success(), "{}", rejected.text);
    assert_eq!(store.case_get_durable(tenant.id, case_id).await.unwrap().unwrap().state, CaseState::New);
    assert_eq!(store.case_events_durable(tenant.id, case_id).await.unwrap().len(), timeline_before);
    let mut tx = db.db().begin_tenant(tenant.id).await.unwrap();
    assert_eq!(AuditRepo::chain_stats(&mut tx).await.unwrap(), audit_before);
    tx.commit().await.unwrap();
    sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}")).execute(db.db().pool()).await.unwrap();
    let recovered = h.request_with("POST", &state_url, &headers, Some(json!({"state":"investigating"}))).await;
    assert_eq!(recovered.status, StatusCode::OK, "{}", recovered.text);
    assert_eq!(store.case_get_durable(tenant.id, case_id).await.unwrap().unwrap().state, CaseState::Investigating);
    let audit = h.request_with("GET", &format!("/api/v1/audit?actor=case-state&q={id}"), &headers, None).await;
    assert_eq!(audit.status, StatusCode::OK, "{}", audit.text);
    assert_eq!(audit.json()["items"][0]["target"]["id"], id);
    let repeated = h.request_with("POST", &state_url, &headers, Some(json!({"state":"investigating"}))).await;
    assert_eq!(repeated.status, StatusCode::OK, "{}", repeated.text);
    assert_eq!(store.case_events_durable(tenant.id, case_id).await.unwrap().len(), timeline_before + 1);
    let mut tx = db.db().begin_tenant(tenant.id).await.unwrap();
    assert_eq!(AuditRepo::chain_stats(&mut tx).await.unwrap().0, audit_before.0 + 1);
    tx.commit().await.unwrap();
}
