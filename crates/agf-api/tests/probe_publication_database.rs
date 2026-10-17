//! Probe publication must roll back with its audit and reject obsolete observations.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod configuration_audit_support;
mod integration_completion_support;
use agf_api::{cloud_store, integration_store};
use common::*;
use configuration_audit_support::{SqlCase, audits};
use integration_completion_support::*;

fn probe_kind(cloud: bool) -> &'static str {
    if cloud { "cloud-probe" } else { "integration-probe" }
}
fn config_kind(cloud: bool) -> &'static str {
    if cloud { cloud_store::KIND } else { integration_store::KIND }
}
async fn probe(h: &Harness, cloud: bool) -> Resp {
    h.post(&format!("{}/probe", base(cloud)), json!({"configuration_version":1,"confirm_live":false})).await
}
async fn report(h: &Harness, cloud: bool) -> Option<Value> {
    h.state.configurations.get(h.tenant, probe_kind(cloud), integration_store::id(h.tenant, name(cloud))).await.unwrap()
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn vendor_and_cloud_probe_audit_failure_preserves_the_previous_report() {
    for cloud in [false, true] {
        let case = SqlCase::open("probe-audit-rollback").await;
        configure(&case.h, cloud, true, "http://127.0.0.1:1").await;
        let initial = probe(&case.h, cloud).await;
        assert_eq!(initial.status, StatusCode::OK, "{}", initial.text);
        let previous = report(&case.h, cloud).await.unwrap();
        let count = audits(&case.h, probe_kind(cloud)).await.len();
        assert_eq!(count, 1);
        let constraint =
            fault(&case.pool, case.h.tenant, "audit_logs", &format!("target->>'kind'='{}'", probe_kind(cloud))).await;
        let failed = probe(&case.h, cloud).await;
        assert!(failed.status.is_server_error(), "{}", failed.text);
        assert_eq!(report(&case.h, cloud).await, Some(previous));
        assert_eq!(audits(&case.h, probe_kind(cloud)).await.len(), count);
        if cloud {
            assert_eq!(
                audits(&case.h, RUNS).await.len(),
                2,
                "each completed readonly API run has its own operation audit"
            );
        }
        unfault(&case.pool, "audit_logs", &constraint).await;
        assert_eq!(probe(&case.h, cloud).await.status, StatusCode::OK);
        assert_eq!(audits(&case.h, probe_kind(cloud)).await.len(), count + 1);
        assert!(case.h.state.store.audit_verify_durable(case.h.tenant).await.unwrap().passed);
        case.pool.close().await;
    }
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn queued_probe_cas_rejects_configuration_version_disabled_state_and_effective_mode_changes() {
    for cloud in [false, true] {
        for change in ["version", "disabled", "mode"] {
            let mut case = SqlCase::open("probe-configuration-cas").await;
            live(&mut case.h);
            configure(&case.h, cloud, true, "http://127.0.0.1:1").await;
            let id = integration_store::id(case.h.tenant, name(cloud));
            let kind = config_kind(cloud);
            let mut gate = SqlGate::acquire(&case.pool, case.h.tenant, format!("{}:{kind}:{id}", case.h.tenant)).await;
            let h = case.h.clone();
            let task = tokio::spawn(async move { probe(&h, cloud).await });
            gate.waiting(&case.pool).await;
            let mut row: integration_store::Stored =
                case.h.state.configurations.get(case.h.tenant, kind, id).await.unwrap().unwrap();
            match change {
                "version" => row.version += 1,
                "disabled" => row.enabled = false,
                "mode" => row.mock = false,
                _ => unreachable!(),
            }
            // Authoritative configuration change in the same transaction that owns the writer's lock.
            gate.rewrite(kind, id, serde_json::to_value(row).unwrap()).await;
            gate.release().await;
            let rejected = task.await.unwrap();
            assert_eq!(rejected.status, StatusCode::CONFLICT, "{cloud}/{change}: {}", rejected.text);
            assert!(report(&case.h, cloud).await.is_none());
            assert!(audits(&case.h, probe_kind(cloud)).await.is_empty());
            if cloud {
                assert_eq!(audits(&case.h, RUNS).await.len(), 1);
            }
            case.pool.close().await;
        }
    }
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn an_older_probe_cannot_overwrite_a_report_with_a_newer_start_time() {
    for cloud in [false, true] {
        let case = SqlCase::open("probe-newer-observation").await;
        configure(&case.h, cloud, true, "http://127.0.0.1:1").await;
        assert_eq!(probe(&case.h, cloud).await.status, StatusCode::OK);
        let id = integration_store::id(case.h.tenant, name(cloud));
        let kind = probe_kind(cloud);
        let count = audits(&case.h, kind).await.len();
        let mut gate = SqlGate::acquire(&case.pool, case.h.tenant, format!("{}:{kind}:{id}", case.h.tenant)).await;
        let h = case.h.clone();
        let task = tokio::spawn(async move { probe(&h, cloud).await });
        gate.waiting(&case.pool).await;
        let mut newer = report(&case.h, cloud).await.unwrap();
        newer["started_at"] = json!(Timestamp::now().offset_secs(30));
        newer["note"] = json!("Owned newer observation");
        gate.rewrite(kind, id, newer.clone()).await;
        gate.release().await;
        let rejected = task.await.unwrap();
        assert_eq!(rejected.status, StatusCode::CONFLICT, "{}", rejected.text);
        assert_eq!(report(&case.h, cloud).await, Some(newer));
        assert_eq!(audits(&case.h, kind).await.len(), count);
        case.pool.close().await;
    }
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn fresh_process_read_projections_reject_mock_reports_for_unchanged_live_configurations() {
    let case = SqlCase::open("probe-mode-read-cas").await;
    for cloud in [false, true] {
        configure(&case.h, cloud, false, "http://127.0.0.1:1").await;
        assert_eq!(probe(&case.h, cloud).await.status, StatusCode::OK);
        assert_eq!(report(&case.h, cloud).await.unwrap()["mocked"], true);
    }
    let before = case.audit_stats().await;
    let mut fresh = case.second_instance().await;
    live(&mut fresh);
    for cloud in [false, true] {
        let view = fresh.get(&configuration_path(cloud)).await;
        assert_eq!(view.status, StatusCode::OK, "{}", view.text);
        assert_eq!(view.json()["version"], 1);
        assert!(view.json()["probe"].is_null());
    }
    let services = agf_api::cloud_status::services(&fresh.state, fresh.tenant).await.unwrap();
    let cms = services.iter().find(|item| item["name"] == "alicloud-cms").unwrap();
    assert!(cms["probe"].is_null());
    assert_eq!(cms["serving"], false);
    assert_eq!(case.audit_stats().await, before, "reading must not audit or publish old observations");
    assert!(report(&fresh, true).await.is_some(), "historical evidence remains stored");
    assert!(report(&fresh, false).await.is_some());
    case.pool.close().await;
}
