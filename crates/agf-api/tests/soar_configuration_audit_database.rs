//! Automatic-response configuration audits preserve revisions and the cross-instance capacity limit.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
#[path = "configuration_audit_support/mod.rs"]
mod database;
use agf_api::{soar_automation as automation, soar_workflow};
use agf_core::{audit::AuditAction, ids::Id};
use common::*;
use database::*;

const ROOT: &str = "/api/v1/soar/automations";

fn definition(key: &str, enabled: bool, version: u64) -> Value {
    json!({"enabled":enabled,"expected_version":version,"reason":"Reviewed configuration transaction",
        "playbook":{"key":key,"name":key,"enabled":true,"trigger":{"min_severity":"high"},
            "require_approval":true,"steps":[{"name":"Reviewed domain","action":"block-domain",
                "params":{"domain":"configuration-test.example"}}]}})
}

async fn save(h: &Harness, key: &str, enabled: bool) -> (String, Value) {
    let response = h.post(ROOT, definition(key, enabled, 0)).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let row = response.json()["automation"].clone();
    let path = format!("{ROOT}/{}", row["id"].as_str().unwrap());
    (path, row)
}

#[tokio::test]
async fn offline_automation_revisions_have_one_audit_and_stale_updates_have_none() {
    let h = setup().await;
    let (path, row) = save(&h, "offline-configuration-audit", false).await;
    let body = definition("offline-configuration-audit", true, 1);
    let updated = h.request("PUT", &path, Some(&h.admin), Some(body.clone())).await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.text);
    assert_eq!(updated.json()["automation"]["version"], 2);
    assert_eq!(h.request("PUT", &path, Some(&h.admin), Some(body)).await.status, StatusCode::CONFLICT);
    let rows = audits(&h, "soar-automation").await;
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|entry| entry.target.id.as_deref() == row["id"].as_str()));
    assert!(rows.iter().all(|entry| entry.action == AuditAction::Update));
    assert!(h.state.store.audit_verify_durable(h.tenant).await.unwrap().passed);
}

async fn assert_no_work(case: &SqlCase) {
    automation::tick(&case.h.state).await.unwrap();
    assert!(case.rows(automation::DELIVERY).await.is_empty());
    assert!(case.rows(soar_workflow::KIND).await.is_empty());
    assert!(case.h.state.store.case_list_durable(case.h.tenant).await.unwrap().is_empty());
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn failed_automation_audit_preserves_history_and_does_not_activate_response() {
    let case = SqlCase::open("soar-configuration-rollback").await;
    let h = &case.h;
    let key = "sql-configuration-audit";
    let (path, row) = save(h, key, false).await;
    create_alert_for_soc(h, "Would activate response", "high", &format!("audit-{}", Id::new())).await;
    let before = case.rows(automation::KIND).await;
    let audit_before = case.audit_stats().await;
    let constraint = case.block_audit().await;
    let mut edited = definition(key, false, 1);
    edited["playbook"]["name"] = json!("Failed playbook mutation");
    edited["separate_approver"] = json!(true);
    for (method, uri, body) in [
        ("POST", ROOT, definition("failed-new-automation", true, 0)),
        ("PUT", path.as_str(), definition(key, true, 1)),
        ("PUT", path.as_str(), edited),
    ] {
        assert_audit_failure(&h.request(method, uri, Some(&h.admin), Some(body)).await);
        assert_eq!(case.rows(automation::KIND).await, before, "{method} {uri} changed configuration/history");
        assert_eq!(case.audit_stats().await, audit_before);
    }
    assert_no_work(&case).await;
    let other = case.second_instance().await;
    assert_eq!(other.get(&path).await.json()["automation"], row);
    case.unblock_audit(&constraint).await;
    let enabled = h.request("PUT", &path, Some(&h.admin), Some(definition(key, true, 1))).await;
    assert_eq!(enabled.status, StatusCode::OK, "{}", enabled.text);
    assert_eq!(enabled.json()["automation"]["version"], 2);
    let eligible = create_alert_for_soc(h, "After actual enablement", "high", &format!("enabled-{}", Id::new())).await;
    let active = case.rows(automation::KIND).await;
    let enabled_stats = case.audit_stats().await;
    let constraint = case.block_audit().await;
    assert_audit_failure(&other.request("PUT", &path, Some(&other.admin), Some(definition(key, false, 2))).await);
    assert_eq!(case.rows(automation::KIND).await, active, "failed disable must retain the active revision");
    assert_eq!(case.audit_stats().await, enabled_stats);
    case.unblock_audit(&constraint).await;
    automation::tick(&h.state).await.unwrap();
    let decisions = case.rows(automation::DELIVERY).await;
    assert_eq!(decisions.len(), 1, "successful enable only handles new alerts");
    assert_eq!(decisions[0]["alert_id"].as_str(), Some(eligible.as_str()));
    assert_eq!(h.state.store.case_list_durable(h.tenant).await.unwrap().len(), 1);
    assert_eq!(audits(h, "soar-automation").await.len(), 2);
    assert!(h.state.store.audit_verify_durable(h.tenant).await.unwrap().passed);
    case.pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn bounded_automation_claims_are_atomic_and_existing_updates_do_not_consume_slots() {
    let case = SqlCase::open("soar-configuration-capacity").await;
    let h = &case.h;
    let mut first_path = String::new();
    for index in 0..49 {
        let (path, _) = save(h, &format!("bounded-{index}"), false).await;
        if index == 0 {
            first_path = path;
        }
    }
    let before = case.rows(automation::KIND).await;
    let stats = case.audit_stats().await;
    let constraint = case.block_audit().await;
    assert_audit_failure(&h.post(ROOT, definition("failed-slot-50", false, 0)).await);
    assert_eq!(case.rows(automation::KIND).await, before, "failed create must not occupy slot 50");
    assert_eq!(case.audit_stats().await, stats);
    case.unblock_audit(&constraint).await;
    let other = case.second_instance().await;
    let (a, b) = tokio::join!(
        h.post(ROOT, definition("candidate-50-a", false, 0)),
        other.post(ROOT, definition("candidate-50-b", false, 0))
    );
    let statuses = [a.status, b.status];
    assert_eq!(statuses.iter().filter(|status| **status == StatusCode::OK).count(), 1, "{a:?} {b:?}");
    assert_eq!(statuses.iter().filter(|status| **status == StatusCode::BAD_REQUEST).count(), 1);
    assert_eq!(case.rows(automation::KIND).await.len(), 50);
    assert_eq!(audits(h, "soar-automation").await.len(), 50, "rejected capacity claim cannot append a success audit");
    let updated = other.request("PUT", &first_path, Some(&other.admin), Some(definition("bounded-0", false, 1))).await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.text);
    assert_eq!(updated.json()["automation"]["version"], 2);
    assert_eq!(updated.json()["automation"]["history"].as_array().unwrap().len(), 2);
    assert_eq!(case.rows(automation::KIND).await.len(), 50, "editing existing configuration needs no new slot");
    let old = h.request("PUT", &first_path, Some(&h.admin), Some(definition("bounded-0", true, 1))).await;
    assert_eq!(old.status, StatusCode::CONFLICT);
    assert_eq!(h.post(ROOT, definition("slot-51", false, 0)).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(audits(h, "soar-automation").await.len(), 51);
    let restarted = case.second_instance().await;
    assert_eq!(restarted.get(&first_path).await.json()["automation"]["version"], 2);
    assert_eq!(restarted.get(&format!("{ROOT}?page_size=100")).await.json()["total"], 50);
    let foreign = case.foreign_instance().await;
    save(&foreign, "foreign-slot-1", false).await;
    assert_eq!(audits(&foreign, "soar-automation").await.len(), 1);
    assert!(h.state.store.audit_verify_durable(h.tenant).await.unwrap().passed);
    case.pool.close().await;
}
