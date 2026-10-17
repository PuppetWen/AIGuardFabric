//! Generic Scheduler receipts protect new and legacy carriers without replaying cloud reads.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod integration_completion_support;
mod scheduler_generic_receipts_support;
use agf_api::integration_receipts;
use agf_core::{audit::AuditOutcome, enums::AliCloudService, ids::Id};
use common::*;
use integration_completion_support::{assert_safe_audit, live, operation_audits, read_key};
use scheduler_generic_receipts_support::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method},
};

#[tokio::test]
async fn three_real_loopback_reads_store_only_safe_receipts_and_never_redispatch_on_replay() {
    let mut h = setup().await;
    live(&mut h);
    let server = MockServer::start().await;
    configure(&h, &server.uri(), false).await;
    for action in ["ListJobs", "ListJobExecutions", "GetJobExecution"] {
        Mock::given(method("GET"))
            .and(header("x-acs-action", action))
            .respond_with(ResponseTemplate::new(200).set_body_json(provider(action)))
            .expect(1)
            .mount(&server)
            .await;
        let body = request(action);
        let first = h.post(&format!("{PATH}/operations"), body.clone()).await;
        assert_eq!(first.status, StatusCode::OK);
        let value = first.json();
        assert_eq!(value["status"], "succeeded");
        assert_eq!(value["completion_state"], "complete");
        assert_eq!(value["mocked"], false);
        assert_projected(&value, action);
        let id: Id = serde_json::from_value(value["id"].clone()).unwrap();
        assert_eq!(decrypted(&h, id).await, value["receipt"], "both projections must be idempotent");
        let before = snapshot(&h).await;
        assert_eq!(h.post(&format!("{PATH}/operations"), body).await.json(), value);
        assert_eq!(h.get(&receipt_path(id)).await.json(), value);
        assert_eq!(
            h.request("POST", &format!("{}/recover", receipt_path(id)), Some(&h.admin), None).await.json(),
            value
        );
        assert_eq!(snapshot(&h).await, before, "replay and completed recovery must add no audit or data");
        let audits = operation_audits(&h, id).await;
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].outcome, AuditOutcome::Success);
    }
    let sent = server.received_requests().await.unwrap();
    assert_eq!(sent.len(), 3);
    assert!(sent.iter().all(|call| call.headers.contains_key("authorization")));
}

#[tokio::test]
async fn public_mock_examples_keep_success_and_pagination_even_when_message_sounds_like_error() {
    let h = setup().await;
    configure(&h, "http://127.0.0.1:1", true).await;
    for action in ["ListJobs", "ListJobExecutions", "GetJobExecution"] {
        let raw = agf_alicloud::openapi::fixture(AliCloudService::SchedulerX3, action).unwrap();
        assert!(raw["Message"].as_str().unwrap().contains("Parameter error"));
        let response = h.post(&format!("{PATH}/operations"), request(action)).await;
        assert_eq!(response.status, StatusCode::OK);
        let value = response.json();
        assert_eq!(value["status"], "succeeded");
        assert_eq!(value["mocked"], true);
        let safe = &value["receipt"]["response"];
        assert_eq!(safe["Code"], raw["Code"]);
        assert_eq!(safe["Success"], true);
        assert_eq!(safe["Message"], OMITTED);
        let row = result_row(safe, action);
        let raw_row = result_row(&raw, action);
        assert_eq!(row["JobId"], raw_row["JobId"]);
        for carrier in ["Parameters", "Script", "Xattrs", "XAttrs", "Result", "WorkAddr", "Executor"] {
            if let Some(original) = raw_row.get(carrier) {
                assert_opaque(
                    &row[carrier],
                    !original.is_null() && original.as_str().is_none_or(|text| !text.is_empty()),
                );
                assert_ne!(&row[carrier], original);
            }
        }
        if action != "GetJobExecution" {
            for field in ["PageNumber", "PageSize", "Total"] {
                assert_eq!(safe["Data"][field], raw["Data"][field]);
            }
        }
    }
}

#[tokio::test]
async fn provider_error_diagnostics_are_omitted_without_turning_failure_into_success() {
    let mut h = setup().await;
    live(&mut h);
    let server = MockServer::start().await;
    configure(&h, &server.uri(), false).await;
    Mock::given(method("GET"))
        .and(header("x-acs-action", "ListJobs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Code":"InvalidParameter","Success":false,"Message":PRIVATE,"RequestId":"owned-failed-request"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let response = h.post(&format!("{PATH}/operations"), request("ListJobs")).await;
    assert_eq!(response.status, StatusCode::OK);
    let value = response.json();
    assert_eq!(value["status"], "failed");
    assert_eq!(value["receipt"]["error"], OMITTED);
    assert_safe(&value);
    let id: Id = serde_json::from_value(value["id"].clone()).unwrap();
    let audits = operation_audits(&h, id).await;
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].outcome, AuditOutcome::Failure);
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn recognized_numeric_and_string_codes_preserve_the_pre_projection_business_outcome() {
    let mut h = setup().await;
    live(&mut h);
    let server = MockServer::start().await;
    configure(&h, &server.uri(), false).await;
    for (code, success, status) in [
        (json!(1), true, "succeeded"),
        (json!("SUCCESS"), true, "succeeded"),
        (json!("1"), false, "failed"),
        (json!(500), false, "failed"),
    ] {
        server.reset().await;
        let mut raw = provider("ListJobs");
        raw["Code"] = code.clone();
        raw["Success"] = json!(success);
        Mock::given(method("GET"))
            .and(header("x-acs-action", "ListJobs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(raw))
            .expect(1)
            .mount(&server)
            .await;
        let response = h.post(&format!("{PATH}/operations"), request("ListJobs")).await;
        assert_eq!(response.status, StatusCode::OK);
        let value = response.json();
        assert_eq!(value["status"], status);
        assert_safe(&value);
        if success {
            assert_eq!(value["receipt"]["response"]["Code"], code);
            assert_eq!(value["receipt"]["response"]["Message"], OMITTED);
        } else {
            assert_eq!(value["receipt"]["error"], OMITTED);
            assert!(value["receipt"].get("response").is_none());
        }
        let id: Id = serde_json::from_value(value["id"].clone()).unwrap();
        let audits = operation_audits(&h, id).await;
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].outcome, if success { AuditOutcome::Success } else { AuditOutcome::Failure });
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn legacy_encrypted_success_get_and_replay_are_safe_and_strictly_readonly() {
    let h = setup().await;
    let raw = json!({"response":provider("ListJobs"),"mocked":false});
    let (run, _) = seed(&h, NAME, "ListJobs", "succeeded", raw.clone(), false).await;
    let before = snapshot(&h).await;
    for _ in 0..2 {
        let response = h.get(&receipt_path(run.id)).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_projected(&response.json(), "ListJobs");
        assert_eq!(response.json()["actor"], run.actor);
        assert_eq!(response.json()["request_id"], json!(run.request_id));
        let history = h.get(&format!("{PATH}/operations")).await;
        assert_eq!(history.status, StatusCode::OK);
        assert!(history.json()["items"][0].get("receipt").is_none());
        assert_safe(&history.json());
    }
    let polls = AtomicUsize::new(0);
    let replay = integration_receipts::execute(&h.state, h.tenant, run.clone(), &BTreeMap::new(), false, async {
        polls.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"response":provider("ListJobs")}))
    })
    .await
    .unwrap();
    assert_projected(&replay, "ListJobs");
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(decrypted(&h, run.id).await, raw, "GET must not rewrite historical ciphertext");
    assert_eq!(snapshot(&h).await, before);
    assert!(operation_audits(&h, run.id).await.is_empty());
}

#[tokio::test]
async fn pending_legacy_get_and_disabled_source_recover_publish_once_without_a_provider_call() {
    let mut h = setup().await;
    live(&mut h);
    let server = MockServer::start().await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(500)).expect(0).mount(&server).await;
    configure(&h, &server.uri(), false).await;
    let (run, _) =
        seed(&h, NAME, "ListJobExecutions", "succeeded", json!({"response":provider("ListJobExecutions")}), true).await;
    let disabled = h.request("PUT", PATH, Some(&h.admin), Some(json!({
        "expected_version":1,"enabled":false,"mock":false,
        "settings":{"endpoint":server.uri(),"region_id":"cn-hangzhou","cluster_id":"owned-cluster","app_name":"owned-app"}
    }))).await;
    assert_eq!(disabled.status, StatusCode::OK);
    let before = snapshot(&h).await;
    let pending = h.get(&receipt_path(run.id)).await.json();
    assert_eq!(pending["completion_state"], "pending_audit");
    assert_eq!(pending["status"], "uncertain");
    assert_eq!(pending["provider_status"], "succeeded");
    assert_projected(&pending, "ListJobExecutions");
    h.get(&format!("{PATH}/operations")).await;
    assert_eq!(snapshot(&h).await, before);
    let recovered = h.request("POST", &format!("{}/recover", receipt_path(run.id)), Some(&h.admin), None).await;
    assert_eq!(recovered.status, StatusCode::OK);
    let value = recovered.json();
    assert_eq!(value["status"], "succeeded");
    assert_eq!(value["completion_state"], "complete");
    assert_eq!(value["actor"], run.actor);
    assert_eq!(value["configuration_version"], 1);
    assert_projected(&value, "ListJobExecutions");
    let after = snapshot(&h).await;
    assert_eq!(h.get(&receipt_path(run.id)).await.json(), value);
    assert_eq!(
        h.request("POST", &format!("{}/recover", receipt_path(run.id)), Some(&h.admin), None).await.json(),
        value
    );
    assert_eq!(snapshot(&h).await, after);
    let audits = operation_audits(&h, run.id).await;
    assert_eq!(audits.len(), 1);
    assert_safe_audit(&audits[0], &run);
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn pending_failed_and_uncertain_replay_preserve_outcomes_without_polling_provider() {
    let h = setup().await;
    for status in ["failed", "uncertain"] {
        let (run, _) = seed(&h, NAME, "GetJobExecution", status, json!({"error":PRIVATE}), true).await;
        let pending = h.get(&receipt_path(run.id)).await.json();
        assert_eq!(pending["provider_status"], status);
        assert_eq!(pending["receipt"]["error"], OMITTED);
        let polls = AtomicUsize::new(0);
        let replay = integration_receipts::execute(&h.state, h.tenant, run.clone(), &BTreeMap::new(), false, async {
            polls.fetch_add(1, Ordering::SeqCst);
            Ok(json!({"accepted":true}))
        })
        .await
        .unwrap();
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(replay["status"], status);
        assert_eq!(replay["completion_state"], "complete");
        assert_safe(&replay);
        let audits = operation_audits(&h, run.id).await;
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].outcome, AuditOutcome::Failure);
    }
}

#[tokio::test]
async fn private_receipt_permissions_and_foreign_tenant_or_adapter_cannot_read_or_recover() {
    let h = setup().await;
    let (run, _) = seed(&h, NAME, "ListJobs", "succeeded", json!({"response":provider("ListJobs")}), false).await;
    let key = read_key(&h, true).await;
    let headers = [("x-agf-key", key.as_str())];
    let before = snapshot(&h).await;
    let history = h.request_with("GET", &format!("{PATH}/operations"), &headers, None).await;
    assert_eq!(history.status, StatusCode::OK);
    assert!(history.json()["items"][0].get("receipt").is_none());
    for (method, path) in [("GET", receipt_path(run.id)), ("POST", format!("{}/recover", receipt_path(run.id)))] {
        assert_eq!(h.request(method, &path, None, None).await.status, StatusCode::UNAUTHORIZED);
        assert_eq!(h.request_with(method, &path, &headers, None).await.status, StatusCode::FORBIDDEN);
        let bearer = format!("Bearer {}", h.admin);
        let tenant = h.other_tenant.to_string();
        assert_eq!(
            h.request_with(method, &path, &[("authorization", &bearer), ("x-agf-tenant", &tenant)], None).await.status,
            StatusCode::NOT_FOUND
        );
        let wrong = path.replace(NAME, "alicloud-cms");
        assert_eq!(h.request(method, &wrong, Some(&h.admin), None).await.status, StatusCode::NOT_FOUND);
    }
    assert_eq!(snapshot(&h).await, before);
}

#[tokio::test]
async fn legacy_getapp_receipt_is_wholly_hidden_and_recovery_never_dispatches_getapp() {
    let mut h = setup().await;
    live(&mut h);
    let server = MockServer::start().await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(500)).expect(0).mount(&server).await;
    configure(&h, &server.uri(), false).await;
    for pending in [false, true] {
        let (run, body) = seed(
            &h,
            NAME,
            "GetApp",
            "succeeded",
            json!({
                "response":{"Code":200,"Success":true,"Data":{"Id":123,"AppName":"owned-app","AccessToken":PRIVATE}},
                "private":PRIVATE
            }),
            pending,
        )
        .await;
        let before = snapshot(&h).await;
        let read = h.get(&receipt_path(run.id)).await;
        assert_eq!(read.status, StatusCode::OK);
        let read_value = read.json();
        let receipt = &read_value["receipt"];
        assert_eq!(receipt.as_object().unwrap().len(), 1);
        assert_eq!(receipt["error"], "Use the dedicated Scheduler native observation endpoint");
        assert_safe(&read.json());
        assert_eq!(snapshot(&h).await, before);
        let blocked = h.post(&format!("{PATH}/operations"), body).await;
        assert_eq!(blocked.status, StatusCode::PRECONDITION_FAILED);
        assert_eq!(snapshot(&h).await, before);
        let recovered = h.request("POST", &format!("{}/recover", receipt_path(run.id)), Some(&h.admin), None).await;
        assert_eq!(recovered.status, StatusCode::OK);
        assert_eq!(recovered.json()["receipt"], *receipt);
        assert_eq!(operation_audits(&h, run.id).await.len(), usize::from(pending));
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn nested_aliases_empty_carriers_and_forged_markers_cannot_escape_or_change_on_second_projection() {
    let mut h = setup().await;
    live(&mut h);
    let server = MockServer::start().await;
    configure(&h, &server.uri(), false).await;
    let mut row = provider("GetJobExecution")["Data"].clone();
    row["Parameters"] = json!("");
    row["Script"] = Value::Null;
    row["XAttrs"] = json!({});
    row["INSTANCE_PARAMETERS"] = json!([]);
    row["JobHandler"] = json!({"opaque":true,"present":true,"sha256":"a".repeat(64),"leak":PRIVATE});
    let unicode_key = "Parameters客户密码";
    let control_key = "Parameters\n";
    let oversized_key = format!("Parameters{}", "_".repeat(65));
    for key in [unicode_key, control_key, oversized_key.as_str()] {
        row[key] = json!(PRIVATE);
    }
    let raw = json!({"Code":200,"Success":true,"Data":{"Records":[row,PRIVATE],"jobs":PRIVATE},"Message":PRIVATE});
    Mock::given(method("GET"))
        .and(header("x-acs-action", "ListJobs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(raw))
        .expect(1)
        .mount(&server)
        .await;
    let response = h.post(&format!("{PATH}/operations"), request("ListJobs")).await;
    assert_eq!(response.status, StatusCode::OK);
    let value = response.json();
    assert_safe(&value);
    let data = &value["receipt"]["response"]["Data"];
    for key in [unicode_key, control_key, oversized_key.as_str()] {
        assert!(data["Records"][0].get(key).is_none(), "invalid field names must not become public labels");
    }
    for carrier in ["Parameters", "Script"] {
        assert_opaque(&data["Records"][0][carrier], false);
    }
    for carrier in ["XAttrs", "INSTANCE_PARAMETERS", "JobHandler"] {
        assert_opaque(&data["Records"][0][carrier], true);
    }
    assert_opaque(&data["Records"][1], true);
    assert_opaque(&data["jobs"], true);
    let id: Id = serde_json::from_value(value["id"].clone()).unwrap();
    assert_eq!(decrypted(&h, id).await, value["receipt"]);
    assert_eq!(h.get(&receipt_path(id)).await.json(), value);
}

#[tokio::test]
async fn legacy_error_code_and_existing_safe_marker_have_a_stable_safe_projection() {
    let h = setup().await;
    let marker = json!({"opaque":true,"present":true,"sha256":"a".repeat(64)});
    let (run, _) = seed(
        &h,
        NAME,
        "ListJobs",
        "failed",
        json!({
            "response":{"Code":PRIVATE,"Success":false,"Message":PRIVATE,"Data":{"Records":[{"Parameters":marker}]}},
            "error":PRIVATE
        }),
        false,
    )
    .await;
    let before = snapshot(&h).await;
    let response = h.get(&receipt_path(run.id)).await;
    assert_eq!(response.status, StatusCode::OK);
    let value = response.json();
    assert_eq!(value["status"], "failed");
    assert_eq!(value["receipt"]["response"]["Code"], "omitted");
    assert_eq!(value["receipt"]["error"], OMITTED);
    assert_eq!(value["receipt"]["response"]["Data"]["Records"][0]["Parameters"], marker);
    assert_safe(&value);
    assert_eq!(snapshot(&h).await, before);
}

#[tokio::test]
async fn unrelated_adapter_preserves_its_receipt_on_new_execution_and_legacy_get() {
    let h = setup().await;
    let body = request("DescribeAlertHistoryList");
    let run = claim(&h, "alicloud-cms", "DescribeAlertHistoryList", &body);
    let raw = json!({"response":{"Code":200,"Message":PRIVATE,"Parameters":PRIVATE,"custom":PRIVATE}});
    let result = integration_receipts::execute(&h.state, h.tenant, run.clone(), &BTreeMap::new(), false, async {
        Ok(raw.clone())
    })
    .await
    .unwrap();
    assert_eq!(result["receipt"], raw);
    assert_eq!(decrypted(&h, run.id).await, raw);
    let (legacy, _) = seed(&h, "alicloud-cms", "DescribeAlertHistoryList", "succeeded", raw.clone(), false).await;
    let before = snapshot(&h).await;
    let read = h.get(&format!("/api/v1/alicloud/connections/alicloud-cms/operations/{}", legacy.id)).await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.json()["receipt"], raw);
    assert_eq!(snapshot(&h).await, before);
}
