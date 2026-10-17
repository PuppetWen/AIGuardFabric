//! Parser definitions, history and success audit commit atomically without changing live parsing on failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
#[path = "configuration_audit_support/mod.rs"]
mod database;
use agf_api::parser_store::{self, KIND, Record};
use agf_core::{audit::AuditAction, ids::Id};
use common::*;
use database::*;

fn input(key: &str, field: &str) -> Value {
    let sample = json!({(field):"sample"}).to_string();
    json!({"definition":{"key":key,"name":key,"engine":"json-path","pattern":"$",
        "required_fields":[field],"mapping":{"map":{(field):"event.action"}}},
        "sample":sample,"enabled":true,"priority":1})
}

async fn create(h: &Harness, key: &str) -> (Id, String) {
    let response = h.post("/api/v1/parsers", input(key, "original_signal")).await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
    let id = Id::parse(response.json()["id"].as_str().unwrap()).unwrap();
    (id, format!("/api/v1/parsers/{id}"))
}

async fn push(h: &Harness, path: &str, field: &str, nonce: &str) {
    let response = h.post(path, json!({(field):nonce})).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.json()["matched"], 1, "{}", response.text);
    assert_eq!(response.json()["accepted"], 1, "{}", response.text);
}

#[tokio::test]
async fn offline_parser_revisions_append_once_and_conflicts_append_nothing() {
    let h = setup().await;
    let (id, path) = create(&h, "offline-parser-audit").await;
    let mut update = input("offline-parser-audit", "next_signal");
    update["expected_version"] = json!(1);
    assert_eq!(h.request("PUT", &path, Some(&h.admin), Some(update.clone())).await.status, StatusCode::OK);
    assert_eq!(h.request("PUT", &path, Some(&h.admin), Some(update)).await.status, StatusCode::CONFLICT);
    assert_eq!(
        h.post(&format!("{path}/restore"), json!({"version":1,"expected_version":2})).await.status,
        StatusCode::OK
    );
    let delete = json!({"expected_version":3});
    assert_eq!(h.request("DELETE", &path, Some(&h.admin), Some(delete)).await.status, StatusCode::OK);
    let rows = audits(&h, "parser").await;
    assert_eq!(rows.len(), 4);
    let target = id.to_string();
    assert!(rows.iter().all(|row| row.target.id.as_deref() == Some(target.as_str())));
    assert_eq!(
        rows.iter().map(|row| row.action).collect::<Vec<_>>(),
        vec![AuditAction::Create, AuditAction::Update, AuditAction::Configure, AuditAction::Delete]
    );
    assert!(h.state.store.audit_verify_durable(h.tenant).await.unwrap().passed);
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn parser_create_update_restore_and_delete_roll_back_with_failed_audit() {
    let case = SqlCase::open("parser-audit-rollback").await;
    let h = &case.h;
    let (id, path) = create(h, "sql-parser-audit").await;
    let mut update = input("sql-parser-audit", "next_signal");
    update["expected_version"] = json!(1);
    assert_eq!(h.request("PUT", &path, Some(&h.admin), Some(update)).await.status, StatusCode::OK);
    let source = h
        .post(
            "/api/v1/ingest/sources",
            json!({"name":"Parser audit source",
        "protocol":"http-webhook","parserId":id}),
        )
        .await;
    assert_eq!(source.status, StatusCode::CREATED, "{}", source.text);
    let events = format!("/api/v1/ingest/sources/{}/events", source.json()["id"].as_str().unwrap());
    push(h, &events, "next_signal", "before-fault").await;
    let before = case.rows(KIND).await;
    let audit_before = case.audit_stats().await;
    let constraint = case.block_audit().await;
    let mut rejected_update = input("sql-parser-audit", "lost_signal");
    rejected_update["expected_version"] = json!(2);
    rejected_update["enabled"] = json!(false);
    let mutations = [
        ("POST", "/api/v1/parsers".into(), input("failed-new-parser", "new_signal")),
        ("PUT", path.clone(), rejected_update),
        ("POST", format!("{path}/restore"), json!({"version":1,"expected_version":2})),
        ("DELETE", path.clone(), json!({"expected_version":2})),
    ];
    for (index, (method, uri, body)) in mutations.into_iter().enumerate() {
        assert_audit_failure(&h.request(method, &uri, Some(&h.admin), Some(body)).await);
        assert_eq!(case.rows(KIND).await, before, "{method} {uri} changed definition/history/delete state");
        assert_eq!(case.audit_stats().await, audit_before);
        push(h, &events, "next_signal", &format!("after-fault-{index}")).await;
    }
    let other = case.second_instance().await;
    let observed: Record = other.state.configurations.get(h.tenant, KIND, id).await.unwrap().unwrap();
    assert_eq!(observed.current.as_ref().unwrap().parser.definition.version, 2);
    assert_eq!(observed.history.len(), 2);
    assert!(!observed.deleted);
    case.unblock_audit(&constraint).await;
    let restored = h.post(&format!("{path}/restore"), json!({"version":1,"expected_version":2})).await;
    assert_eq!(restored.status, StatusCode::OK, "{}", restored.text);
    assert_eq!(restored.json()["version"], 3);
    push(h, &events, "original_signal", "restored-real-parser").await;
    create(h, "failed-new-parser").await;
    assert_eq!(
        h.request("DELETE", &path, Some(&h.admin), Some(json!({"expected_version":3}))).await.status,
        StatusCode::OK
    );
    assert_eq!(other.get(&path).await.status, StatusCode::NOT_FOUND);
    assert_eq!(h.post(&events, json!({"original_signal":"deleted"})).await.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(audits(h, "parser").await.len(), 5);
    assert!(h.state.store.audit_verify_durable(h.tenant).await.unwrap().passed);
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn parser_old_versions_cannot_overwrite_other_instances_or_foreign_templates() {
    let case = SqlCase::open("parser-audit-conflict").await;
    let h = &case.h;
    let (id, path) = create(h, "sql-parser-shared-key").await;
    let other = case.second_instance().await;
    let mut left = input("sql-parser-shared-key", "left_signal");
    left["expected_version"] = json!(1);
    let mut right = input("sql-parser-shared-key", "right_signal");
    right["expected_version"] = json!(1);
    let (a, b) = tokio::join!(
        h.request("PUT", &path, Some(&h.admin), Some(left)),
        other.request("PUT", &path, Some(&other.admin), Some(right))
    );
    let statuses = [a.status, b.status];
    assert_eq!(statuses.iter().filter(|status| **status == StatusCode::OK).count(), 1, "{a:?} {b:?}");
    assert_eq!(statuses.iter().filter(|status| **status == StatusCode::CONFLICT).count(), 1);
    let before = case.rows(KIND).await;
    let stats = case.audit_stats().await;
    for (method, uri, body) in [
        ("POST", format!("{path}/restore"), json!({"version":1,"expected_version":1})),
        ("DELETE", path.clone(), json!({"expected_version":1})),
    ] {
        assert_eq!(other.request(method, &uri, Some(&other.admin), Some(body)).await.status, StatusCode::CONFLICT);
    }
    assert_eq!(case.rows(KIND).await, before);
    assert_eq!(case.audit_stats().await, stats);
    let foreign = case.foreign_instance().await;
    assert_eq!(foreign.get(&path).await.status, StatusCode::NOT_FOUND);
    let (foreign_id, _) = create(&foreign, "sql-parser-shared-key").await;
    assert_eq!(foreign_id, id, "the same parser key has one deterministic ID per tenant's isolated record");
    assert_eq!(parser_store::custom(&foreign.state, foreign.tenant, id).await.unwrap().history.len(), 1);
    assert_eq!(parser_store::custom(&other.state, h.tenant, id).await.unwrap().history.len(), 2);
    assert_eq!(audits(h, "parser").await.len(), 2);
    assert_eq!(audits(&foreign, "parser").await.len(), 1);
    case.pool.close().await;
}
