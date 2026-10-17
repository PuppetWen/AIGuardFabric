//! HTTP completion recovery never reclaims an operation or calls a provider.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod integration_completion_support;
use agf_core::{audit::AuditOutcome, ids::Id};
use common::*;
use integration_completion_support::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test]
async fn pending_get_and_history_are_readonly_and_explicit_recovery_needs_no_configuration() {
    for cloud in [false, true] {
        let h = setup().await;
        let (run, _) = seed_pending(&h, cloud, "succeeded").await;
        let endpoint = format!("{}/operations/{}", base(cloud), run.id);
        let before = (rows(&h, RUNS).await, rows(&h, PENDING).await, h.state.store.audit_stats(h.tenant).unwrap());
        for _ in 0..2 {
            let response = h.get(&endpoint).await;
            assert_eq!(response.status, StatusCode::OK, "{}", response.text);
            let pending = response.json();
            assert_eq!(pending["status"], "uncertain");
            assert_eq!(pending["completion_state"], "pending_audit");
            assert_eq!(pending["provider_status"], "succeeded");
            assert!(pending["finished_at"].is_null());
            assert_eq!(pending["receipt"]["detail"], "private-receipt-marker");
            let history = h.get(&format!("{}/operations", base(cloud))).await.json();
            assert_eq!(history["items"][0]["completion_state"], "pending_audit");
            assert!(history["items"][0].get("receipt").is_none());
        }
        assert_eq!(
            (rows(&h, RUNS).await, rows(&h, PENDING).await, h.state.store.audit_stats(h.tenant).unwrap()),
            before
        );
        let response = h.request("POST", &format!("{endpoint}/recover"), Some(&h.admin), None).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text);
        assert_eq!(response.json()["completion_state"], "complete");
        assert_eq!(response.json()["status"], "succeeded");
        assert_eq!(response.json()["actor"], run.actor);
        assert_eq!(response.json()["configuration_version"], 1);
        assert!(rows(&h, PENDING).await.is_empty());
        assert_eq!(rows(&h, RUNS).await.len(), 1, "original claim must survive completion");
        let audits = operation_audits(&h, run.id).await;
        assert_eq!(audits.len(), 1);
        assert_safe_audit(&audits[0], &run);
        for _ in 0..2 {
            assert_eq!(h.get(&endpoint).await.json(), response.json());
            assert_eq!(
                h.request("POST", &format!("{endpoint}/recover"), Some(&h.admin), None).await.json(),
                response.json()
            );
        }
        assert_eq!(operation_audits(&h, run.id).await.len(), 1);
    }
}

#[tokio::test]
async fn same_post_resumes_pending_without_polling_future_and_recovers_only_once() {
    for cloud in [false, true] {
        let h = setup().await;
        configure(&h, cloud, true, "http://127.0.0.1:1").await;
        let (run, body) = seed_pending(&h, cloud, "succeeded").await;
        let calls = AtomicUsize::new(0);
        let result =
            agf_api::integration_receipts::execute(&h.state, h.tenant, run.clone(), &BTreeMap::new(), true, async {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(json!({"accepted":true}))
            })
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0, "pending recovery must not poll provider future");
        assert_eq!(result["completion_state"], "complete");
        let replay = h.post(&format!("{}/operations", base(cloud)), body.clone()).await;
        assert_eq!(replay.status, StatusCode::OK, "{}", replay.text);
        assert_eq!(replay.json(), result);
        let mut collision = body;
        if cloud {
            collision["parameters"]["EventInfo"][0]["Content"] = json!("changed");
        } else {
            collision["payload"]["title"] = json!("changed");
        }
        assert_eq!(h.post(&format!("{}/operations", base(cloud)), collision).await.status, StatusCode::CONFLICT);
        assert_eq!(operation_audits(&h, run.id).await.len(), 1);
    }
}

#[tokio::test]
async fn recovery_is_tenant_adapter_and_write_permission_scoped() {
    for cloud in [false, true] {
        let h = setup().await;
        let (run, _) = seed_pending(&h, cloud, "succeeded").await;
        let endpoint = format!("{}/operations/{}", base(cloud), run.id);
        let read = read_key(&h, cloud).await;
        let read_headers = [("x-agf-key", read.as_str())];
        assert_eq!(
            h.request_with("GET", &format!("{}/operations", base(cloud)), &read_headers, None).await.status,
            StatusCode::OK
        );
        for (method, path) in [("GET", endpoint.clone()), ("POST", format!("{endpoint}/recover"))] {
            assert_eq!(h.request_with(method, &path, &read_headers, None).await.status, StatusCode::FORBIDDEN);
            let token = format!("Bearer {}", h.admin);
            let tenant = h.other_tenant.to_string();
            assert_eq!(
                h.request_with(method, &path, &[("authorization", &token), ("x-agf-tenant", &tenant)], None)
                    .await
                    .status,
                StatusCode::NOT_FOUND
            );
        }
        let wrong =
            if cloud { "/api/v1/alicloud/connections/alicloud-apig" } else { "/api/v1/integrations/adapters/jira" };
        assert_eq!(
            h.request("POST", &format!("{wrong}/operations/{}/recover", run.id), Some(&h.admin), None).await.status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(rows(&h, PENDING).await.len(), 1);
        assert!(operation_audits(&h, run.id).await.is_empty());
    }
}

#[tokio::test]
async fn corrupt_aad_and_ciphertext_get_or_recovery_cannot_publish_or_audit() {
    for cloud in [false, true] {
        for corrupt_aad in [false, true] {
            let h = setup().await;
            let (run, _) = seed_pending(&h, cloud, "succeeded").await;
            let mut pending = rows(&h, PENDING).await.remove(0);
            if corrupt_aad {
                pending["run"]["result"]["aad"] =
                    json!(agf_storage::crypto::FieldCipher::make_aad(&h.other_tenant, &run.id));
            } else {
                pending["run"]["result"]["ciphertext_b64"] = json!("AAAA");
            }
            h.state.configurations.put(h.tenant, PENDING, run.id, &pending).await.unwrap();
            let before = (rows(&h, RUNS).await, rows(&h, PENDING).await, h.state.store.audit_stats(h.tenant).unwrap());
            let endpoint = format!("{}/operations/{}", base(cloud), run.id);
            assert!(h.get(&endpoint).await.status.is_server_error());
            assert!(
                h.request("POST", &format!("{endpoint}/recover"), Some(&h.admin), None).await.status.is_server_error()
            );
            assert_eq!(
                (rows(&h, RUNS).await, rows(&h, PENDING).await, h.state.store.audit_stats(h.tenant).unwrap()),
                before
            );
        }
    }
}

#[tokio::test]
async fn unknown_claim_is_never_deleted_reclaimed_or_blindly_retried() {
    let h = setup().await;
    configure(&h, false, true, "http://127.0.0.1:1").await;
    let body = body(false);
    let run = claim(&h, false, &body);
    h.state.configurations.put(h.tenant, RUNS, run.id, &run).await.unwrap();
    let endpoint = format!("{VENDOR}/operations/{}", run.id);
    assert_eq!(
        h.request("POST", &format!("{endpoint}/recover"), Some(&h.admin), None).await.status,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(h.post(&format!("{VENDOR}/operations"), body).await.status, StatusCode::CONFLICT);
    let calls = AtomicUsize::new(0);
    let retry =
        agf_api::integration_receipts::execute(&h.state, h.tenant, run.clone(), &BTreeMap::new(), true, async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(json!({"accepted":true}))
        })
        .await;
    assert!(matches!(retry, Err(agf_core::error::DomainError::Conflict(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(rows(&h, RUNS).await, vec![serde_json::to_value(&run).unwrap()]);
    assert!(operation_audits(&h, run.id).await.is_empty());
}

#[tokio::test]
async fn failed_and_uncertain_known_outcomes_preserve_provider_status_and_failure_audit() {
    let h = setup().await;
    for status in ["failed", "uncertain"] {
        let (run, _) = seed_pending(&h, false, status).await;
        let endpoint = format!("{VENDOR}/operations/{}", run.id);
        assert_eq!(h.get(&endpoint).await.json()["provider_status"], status);
        let recovered = h.request("POST", &format!("{endpoint}/recover"), Some(&h.admin), None).await;
        assert_eq!(recovered.status, StatusCode::OK, "{}", recovered.text);
        assert_eq!(recovered.json()["status"], status);
        let audits = operation_audits(&h, run.id).await;
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].outcome, AuditOutcome::Failure);
        assert_safe_audit(&audits[0], &run);
    }
}

#[tokio::test]
async fn actual_loopback_operations_seal_exactly_one_audit_and_reuse_complete_receipts() {
    for cloud in [false, true] {
        let mut h = setup().await;
        live(&mut h);
        let server = Loopback::new(false).await;
        configure(&h, cloud, false, &server.endpoint).await;
        let body = body(cloud);
        let endpoint = format!("{}/operations", base(cloud));
        let first = h.post(&endpoint, body.clone()).await;
        assert_eq!(first.status, StatusCode::OK, "{}", first.text);
        assert_eq!(first.json()["status"], "succeeded");
        assert_eq!(first.json()["completion_state"], "complete");
        let id: Id = serde_json::from_value(first.json()["id"].clone()).unwrap();
        let run = h
            .state
            .configurations
            .get::<agf_api::integration_receipts::Run>(h.tenant, RUNS, id)
            .await
            .unwrap()
            .unwrap();
        for response in [
            h.post(&endpoint, body).await,
            h.get(&format!("{endpoint}/{id}")).await,
            h.request("POST", &format!("{endpoint}/{id}/recover"), Some(&h.admin), None).await,
        ] {
            assert_eq!(response.status, StatusCode::OK, "{}", response.text);
            assert_eq!(response.json(), first.json());
        }
        assert_eq!(server.count(), 1);
        assert!(rows(&h, PENDING).await.is_empty());
        let audits = operation_audits(&h, id).await;
        assert_eq!(audits.len(), 1);
        assert_safe_audit(&audits[0], &run);
        assert_eq!(audits[0].actor.kind, "user");
    }
}

#[tokio::test]
async fn old_mock_probe_is_hidden_when_a_new_process_uses_live_mode_without_version_change() {
    let h = setup().await;
    for cloud in [false, true] {
        configure(&h, cloud, false, "http://127.0.0.1:1").await;
        let probe = h.post(&format!("{}/probe", base(cloud)), json!({"configuration_version":1})).await;
        assert_eq!(probe.status, StatusCode::OK, "{}", probe.text);
        assert_eq!(probe.json()["mocked"], true);
    }
    let mut next = h.clone();
    live(&mut next);
    for cloud in [false, true] {
        let view = next.get(&configuration_path(cloud)).await;
        assert_eq!(view.status, StatusCode::OK, "{}", view.text);
        assert_eq!(view.json()["version"], 1);
        assert!(view.json()["probe"].is_null(), "old effective Mock report must not become Live evidence");
    }
    let services = agf_api::cloud_status::services(&next.state, next.tenant).await.unwrap();
    let cms = services.iter().find(|item| item["name"] == "alicloud-cms").unwrap();
    assert_eq!(cms["serving"], false);
    assert!(cms["probe"].is_null());
}

#[tokio::test]
async fn mismatched_pending_configuration_or_mode_cannot_replace_the_original_claim() {
    let h = setup().await;
    for change in ["version", "mode"] {
        let (run, _) = seed_pending(&h, false, "succeeded").await;
        let mut pending: Value = h.state.configurations.get(h.tenant, PENDING, run.id).await.unwrap().unwrap();
        if change == "version" {
            pending["run"]["configuration_version"] = json!(2);
        } else {
            pending["run"]["mocked"] = json!(false);
        }
        h.state.configurations.put(h.tenant, PENDING, run.id, &pending).await.unwrap();
        let before = (rows(&h, RUNS).await, rows(&h, PENDING).await, h.state.store.audit_stats(h.tenant).unwrap());
        let endpoint = format!("{VENDOR}/operations/{}", run.id);
        assert_eq!(h.get(&endpoint).await.status, StatusCode::CONFLICT);
        assert_eq!(
            h.request("POST", &format!("{endpoint}/recover"), Some(&h.admin), None).await.status,
            StatusCode::CONFLICT
        );
        assert_eq!(
            (rows(&h, RUNS).await, rows(&h, PENDING).await, h.state.store.audit_stats(h.tenant).unwrap()),
            before
        );
    }
}

#[tokio::test]
async fn cancelling_the_borrowed_provider_future_keeps_an_unknown_claim_and_never_restarts_it() {
    let h = setup().await;
    let run = claim(&h, false, &body(false));
    let ready = Arc::new(tokio::sync::Semaphore::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let task_h = h.clone();
    let task_run = run.clone();
    let started = Arc::clone(&ready);
    let counter = Arc::clone(&calls);
    let task = tokio::spawn(async move {
        agf_api::integration_receipts::execute(
            &task_h.state,
            task_h.tenant,
            task_run,
            &BTreeMap::new(),
            true,
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                started.add_permits(1);
                std::future::pending::<agf_core::error::DomainResult<Value>>().await
            },
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(10), ready.acquire()).await.unwrap().unwrap().forget();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let retry =
        agf_api::integration_receipts::execute(&h.state, h.tenant, run.clone(), &BTreeMap::new(), true, async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(json!({"accepted":true}))
        })
        .await;
    assert!(matches!(retry, Err(agf_core::error::DomainError::Conflict(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(rows(&h, RUNS).await, vec![serde_json::to_value(&run).unwrap()]);
    assert!(rows(&h, PENDING).await.is_empty());
    assert!(operation_audits(&h, run.id).await.is_empty());
}
