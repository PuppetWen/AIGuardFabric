//! Manual and scheduled report artifacts must commit with their success audits.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::{
    report_service::{self, REPORTS, RunOrigin, SCHEDULES, ScheduleRecord},
    tenant_directory,
};
use agf_core::{audit::AuditActor, ids::Id, time::Timestamp};
use agf_storage::{AuditRepo, Database, Store, objectstore::MemoryObjectStore};
use common::*;

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn manual_report_rolls_back_when_audit_fails() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap();
    let database = Database::from_pool(pool.clone());
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(store)));
    let tenant =
        tenant_directory::new(format!("report-generate-audit-{}", Id::new()), "Report generation audit".into());
    tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.app = build_router(h.state.clone());
    let token = format!("Bearer {}", h.admin);
    let tenant_id = tenant.id.to_string();
    let headers = [("authorization", token.as_str()), ("x-agf-tenant", tenant_id.as_str())];
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    let chain_before = AuditRepo::chain_stats(&mut tx).await.unwrap();
    tx.commit().await.unwrap();

    let constraint = format!("agf_test_report_generate_audit_{}", Id::new().as_uuid().simple());
    sqlx::query(&format!(
        "ALTER TABLE audit_logs ADD CONSTRAINT {constraint} CHECK (tenant_id <> '{}'::uuid) NOT VALID",
        tenant.id
    ))
    .execute(&pool)
    .await
    .unwrap();
    let failed = h
        .request_with("POST", "/api/v1/reports", &headers, Some(json!({"title":"must rollback","format":"markdown"})))
        .await;
    assert!(!failed.status.is_success(), "{}", failed.text);
    let artifacts: Vec<Value> = h.state.configurations.list(tenant.id, REPORTS).await.unwrap();
    assert!(artifacts.is_empty(), "audit failure left a report artifact");
    let listed = h.request_with("GET", "/api/v1/reports", &headers, None).await;
    assert_eq!(listed.json()["total"], 0);
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    assert_eq!(AuditRepo::chain_stats(&mut tx).await.unwrap(), chain_before);
    tx.commit().await.unwrap();

    sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}")).execute(&pool).await.unwrap();
    let created = h
        .request_with("POST", "/api/v1/reports", &headers, Some(json!({"title":"audited report","format":"markdown"})))
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let id = created.json()["report"]["id"].as_str().unwrap().to_owned();
    let detail = h.request_with("GET", &format!("/api/v1/reports/{id}"), &headers, None).await;
    assert_eq!(detail.status, StatusCode::OK, "{}", detail.text);
    let downloaded = h.request_with("GET", &format!("/api/v1/reports/{id}/download"), &headers, None).await;
    assert_eq!(downloaded.status, StatusCode::OK);
    assert!(downloaded.text.contains("audited report"));
    let audit = h.request_with("GET", "/api/v1/audit?actor=report-generate&action=export", &headers, None).await;
    assert_eq!(audit.json()["items"][0]["target"]["id"], id);
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn scheduled_reports_roll_back_and_retry_without_duplicate_audits() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap();
    let database = Database::from_pool(pool.clone());
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(store)));
    let tenant = tenant_directory::new(format!("schedule-report-audit-{}", Id::new()), "Schedule audit".into());
    tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.app = build_router(h.state.clone());
    let token = format!("Bearer {}", h.admin);
    let tenant_id = tenant.id.to_string();
    let headers = [("authorization", token.as_str()), ("x-agf-tenant", tenant_id.as_str())];
    let create = |name: &str| json!({"name":name,"cron":"* * * * *","format":"markdown"});
    let manual = h.request_with("POST", "/api/v1/reports/schedules", &headers, Some(create("manual"))).await;
    let scheduled = h.request_with("POST", "/api/v1/reports/schedules", &headers, Some(create("scheduled"))).await;
    assert_eq!(manual.status, StatusCode::CREATED, "{}", manual.text);
    assert_eq!(scheduled.status, StatusCode::CREATED, "{}", scheduled.text);
    let manual_id = Id::parse(manual.json()["schedule"]["id"].as_str().unwrap()).unwrap();
    let scheduled_id = Id::parse(scheduled.json()["schedule"]["id"].as_str().unwrap()).unwrap();
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    let chain_before = AuditRepo::chain_stats(&mut tx).await.unwrap();
    tx.commit().await.unwrap();

    let constraint = format!("agf_test_report_schedule_generate_{}", Id::new().as_uuid().simple());
    sqlx::query(&format!(
        "ALTER TABLE audit_logs ADD CONSTRAINT {constraint} CHECK (tenant_id <> '{}'::uuid) NOT VALID",
        tenant.id
    ))
    .execute(&pool)
    .await
    .unwrap();
    let failed = h.request_with("POST", &format!("/api/v1/reports/schedules/{manual_id}/run"), &headers, None).await;
    assert!(!failed.status.is_success(), "{}", failed.text);
    let scheduled_now = Timestamp::now().offset_secs(120);
    assert!(
        report_service::run_one(&h.state, tenant.id, scheduled_id, scheduled_now, RunOrigin::Scheduled).await.is_err()
    );
    let artifacts: Vec<Value> = h.state.configurations.list(tenant.id, REPORTS).await.unwrap();
    assert!(artifacts.is_empty(), "audit failure left a scheduled report artifact");
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    assert_eq!(AuditRepo::chain_stats(&mut tx).await.unwrap(), chain_before);
    tx.commit().await.unwrap();
    sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}")).execute(&pool).await.unwrap();

    let failed_manual: ScheduleRecord =
        h.state.configurations.get(tenant.id, SCHEDULES, manual_id).await.unwrap().unwrap();
    let original_minute = failed_manual.claimed_at.unwrap();
    h.state
        .configurations
        .mutate::<ScheduleRecord, _>(tenant.id, SCHEDULES, manual_id, |row| {
            row.lease_until = None;
            Ok(())
        })
        .await
        .unwrap();
    let succeeded = h.request_with("POST", &format!("/api/v1/reports/schedules/{manual_id}/run"), &headers, None).await;
    assert_eq!(succeeded.status, StatusCode::OK, "{}", succeeded.text);
    let report_id = succeeded.json()["report"]["id"].as_str().unwrap().to_owned();
    let scheduled_report =
        report_service::run_one(&h.state, tenant.id, scheduled_id, scheduled_now.offset_secs(61), RunOrigin::Scheduled)
            .await
            .unwrap()
            .unwrap();
    let reports: Vec<Value> = h.state.configurations.list(tenant.id, REPORTS).await.unwrap();
    assert_eq!(reports.len(), 2);
    let manual_audit =
        h.request_with("GET", "/api/v1/audit?actor=report-schedule-run&action=export", &headers, None).await;
    assert_eq!(manual_audit.json()["total"], 1);
    assert_eq!(manual_audit.json()["items"][0]["target"]["id"], report_id);
    let system_audit =
        h.request_with("GET", "/api/v1/audit?actor=agf-report-scheduler&action=export", &headers, None).await;
    assert_eq!(system_audit.json()["total"], 1);
    assert_eq!(system_audit.json()["items"][0]["target"]["id"], scheduled_report.id.to_string());
    let repeated = report_service::run_one(
        &h.state,
        tenant.id,
        manual_id,
        original_minute,
        RunOrigin::Manual(AuditActor::system("report-schedule-run")),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(repeated.id.to_string(), report_id);
    let audit_again =
        h.request_with("GET", "/api/v1/audit?actor=report-schedule-run&action=export", &headers, None).await;
    assert_eq!(audit_again.json()["total"], 1, "same-minute retry must not add success audit");
    pool.close().await;
}
