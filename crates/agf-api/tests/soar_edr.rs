//! A reviewed case may call EDR once; rejected targets never produce integration receipts.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::soar_workflow::{self as workflow, Run, Status};
use agf_core::time::Timestamp;
use common::*;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path},
};

async fn fixture(live_endpoint: Option<String>) -> (Harness, String, String) {
    let mut h = setup().await;
    if live_endpoint.is_some() {
        Arc::make_mut(&mut h.state.config).mock_mode = false;
        h.app = build_router(h.state.clone());
    }
    let asset = h
        .post(
            "/api/v1/assets/register",
            json!({
                "request_id":agf_core::ids::Id::new().to_string(),
                "fingerprint":format!("edr-host-{}", agf_core::ids::Id::new()),
                "kind":"compute-node","name":"EDR test host","owner":"soc",
                "data_class":"internal","note":"SOAR EDR integration test",
                "edr_host_id":"host-42"
            }),
        )
        .await;
    assert_eq!(asset.status, StatusCode::OK, "{}", asset.text);
    let asset_id = asset.json()["asset"]["id"].as_str().unwrap().to_string();
    let case = h
        .post(
            "/api/v1/cases",
            json!({
                "title":"EDR case","severity":"high","asset_ids":[asset_id]
            }),
        )
        .await;
    assert_eq!(case.status, StatusCode::CREATED, "{}", case.text);
    let case_id = case.json()["case"]["id"].as_str().unwrap().to_string();
    let mock = live_endpoint.is_none();
    let saved = h
        .request(
            "PUT",
            "/api/v1/integrations/adapters/edr-isolation/configuration",
            Some(&h.admin),
            Some(json!({
                "expected_version":0,"enabled":true,"mock":mock,
                "settings":live_endpoint.map_or_else(|| json!({}),
                    |endpoint| json!({"endpoint":endpoint,"dry_run":false})),
                "secrets":if mock { json!({}) } else { json!({"api_token":"test-edr-token"}) }
            })),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    (h, asset_id, case_id)
}

fn book(asset_id: &str, host: &str) -> Value {
    json!({"playbook":{
        "key":"reviewed-edr-host","name":"Reviewed EDR isolation",
        "trigger":{},"timeout_secs":120,
        "steps":[{"name":"Isolate exact host","action":"isolate-host",
            "params":{"asset_id":asset_id,"host_id":host,
                "configuration_version":1,"reason":"Confirmed malicious activity"}}]
    }})
}

async fn approve(h: &Harness, path: &str, run: &Run) {
    let response = h
        .post(
            &format!("{path}/{}/decision", run.id),
            json!({
                "expected_version":run.version,"action":"approve","reason":"Matched case asset and EDR host"
            }),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
}

#[tokio::test]
async fn edr_requires_approval_and_reuses_one_mock_receipt() {
    let (h, asset, case) = fixture(None).await;
    let path = format!("/api/v1/cases/{case}/playbook-runs");
    let response = h.post(&path, book(&asset, "host-42")).await;
    assert_eq!(response.status, StatusCode::ACCEPTED, "{}", response.text);
    let run: Run = serde_json::from_value(response.json()["run"].clone()).unwrap();
    assert_eq!(run.status, Status::Approval);
    assert!(agf_api::integration_runtime::history(&h.state, h.tenant, "edr-isolation").await.unwrap().is_empty());
    approve(&h, &path, &run).await;
    let finished = workflow::advance(&h.state, h.tenant, run.id, Timestamp::now()).await.unwrap();
    assert_eq!(finished.status, Status::Completed, "{:?}", finished.reason);
    assert!(finished.trace[0].note.contains("EDR Mock 隔离"));
    workflow::advance(&h.state, h.tenant, run.id, Timestamp::now()).await.unwrap();
    let receipts = agf_api::integration_runtime::history(&h.state, h.tenant, "edr-isolation").await.unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["status"], "succeeded");
    assert_eq!(receipts[0]["mocked"], true);
}

#[tokio::test]
async fn approved_live_edr_call_posts_once_to_exact_host() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/hosts/host-42/isolate"))
        .and(header("authorization", "Bearer test-edr-token"))
        .and(header("X-AGF-Dry-Run", "false"))
        .and(body_partial_json(json!({"host_id":"host-42","dry_run":false})))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({"task_id":"edr-task-7"})))
        .expect(1)
        .mount(&server)
        .await;
    let (h, asset, case) = fixture(Some(server.uri())).await;
    let direct_message = agf_adapters::contract::AdapterMessage::event(
        "enforce.isolate",
        agf_core::enums::Severity::High,
        "Direct integration bypass",
        "Must require case approval",
        json!({}),
    )
    .with_label("host_id", "host-42")
    .with_label("action", "isolate");
    let direct = h
        .post(
            "/api/v1/integrations/adapters/edr-isolation/operations",
            json!({"request_id":agf_core::ids::Id::new(),"configuration_version":1,
                "confirm_live":true,"operation":"send","payload":direct_message}),
        )
        .await;
    assert_eq!(direct.status, StatusCode::PRECONDITION_FAILED, "{}", direct.text);
    assert!(server.received_requests().await.unwrap().is_empty());
    let path = format!("/api/v1/cases/{case}/playbook-runs");
    let response = h.post(&path, book(&asset, "host-42")).await;
    assert_eq!(response.status, StatusCode::ACCEPTED, "{}", response.text);
    let run: Run = serde_json::from_value(response.json()["run"].clone()).unwrap();
    assert_eq!(run.status, Status::Approval);
    assert!(server.received_requests().await.unwrap().is_empty());
    approve(&h, &path, &run).await;
    let finished = workflow::advance(&h.state, h.tenant, run.id, Timestamp::now()).await.unwrap();
    assert_eq!(finished.status, Status::Completed, "{:?}", finished.reason);
    assert!(finished.trace[0].note.contains("EDR Live 隔离"));
    workflow::advance(&h.state, h.tenant, run.id, Timestamp::now()).await.unwrap();
    server.verify().await;
    let receipts = agf_api::integration_runtime::history(&h.state, h.tenant, "edr-isolation").await.unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["mocked"], false);
}

#[tokio::test]
async fn edr_rejects_mismatched_and_unsafe_hosts_without_receipt() {
    let (h, asset, case) = fixture(None).await;
    let path = format!("/api/v1/cases/{case}/playbook-runs");
    for host in ["host-43", "../other"] {
        let response = h.post(&path, book(&asset, host)).await;
        assert_eq!(response.status, StatusCode::ACCEPTED, "{}", response.text);
        let run: Run = serde_json::from_value(response.json()["run"].clone()).unwrap();
        assert_eq!(run.status, Status::Approval);
        approve(&h, &path, &run).await;
        let finished = workflow::advance(&h.state, h.tenant, run.id, Timestamp::now()).await.unwrap();
        assert_eq!(finished.status, Status::Aborted, "{:?}", finished.reason);
    }
    assert!(agf_api::integration_runtime::history(&h.state, h.tenant, "edr-isolation").await.unwrap().is_empty());
}

#[tokio::test]
async fn interrupted_edr_receipt_requires_review_and_cannot_replay() {
    let (h, asset, case) = fixture(None).await;
    let path = format!("/api/v1/cases/{case}/playbook-runs");
    let response = h.post(&path, book(&asset, "host-42")).await;
    let run: Run = serde_json::from_value(response.json()["run"].clone()).unwrap();
    approve(&h, &path, &run).await;
    let request_id = agf_core::ids::deterministic_id("agf.soar.edr", &format!("{}:0", run.id));
    let receipt_id =
        agf_core::ids::deterministic_id("agf.integration.run", &format!("{}:edr-isolation:{request_id}", h.tenant));
    let prior = agf_api::integration_receipts::Run {
        id: receipt_id,
        request_id,
        adapter: "edr-isolation".into(),
        operation: "send".into(),
        configuration_version: 1,
        request_hash: "interrupted".into(),
        actor: "test".into(),
        started_at: Timestamp::now(),
        finished_at: None,
        status: "started".into(),
        mocked: true,
        result: None,
    };
    h.state.configurations.put(h.tenant, "integration-operation", receipt_id, &prior).await.unwrap();
    let reviewed = workflow::advance(&h.state, h.tenant, run.id, Timestamp::now()).await.unwrap();
    assert_eq!(reviewed.status, Status::Review, "{:?}", reviewed.reason);
    assert!(reviewed.reason.unwrap().contains("EDR_UNCERTAIN:"));
    assert_eq!(agf_api::integration_runtime::history(&h.state, h.tenant, "edr-isolation").await.unwrap().len(), 1);
}

#[tokio::test]
async fn existing_asset_binding_is_versioned_and_required_for_isolation() {
    let (h, asset, case) = fixture(None).await;
    let asset_path = format!("/api/v1/assets/{asset}");
    let binding_path = format!("{asset_path}/edr-host");
    let detail = h.get(&asset_path).await;
    let first_revision = detail.json()["governance"]["updated_at"].as_str().unwrap().to_string();
    let clear = h
        .request(
            "PUT",
            &binding_path,
            Some(&h.admin),
            Some(json!({"host_id":"","expected_updated_at":first_revision,"reason":"Retire stale host mapping"})),
        )
        .await;
    assert_eq!(clear.status, StatusCode::OK, "{}", clear.text);
    assert!(clear.json()["asset"]["attributes"].get("edr_host_id").is_none());
    let stale = h
        .request(
            "PUT",
            &binding_path,
            Some(&h.admin),
            Some(json!({"host_id":"host-99","expected_updated_at":first_revision,"reason":"Stale administrator"})),
        )
        .await;
    assert_eq!(stale.status, StatusCode::CONFLICT, "{}", stale.text);

    let path = format!("/api/v1/cases/{case}/playbook-runs");
    let unbound = h.post(&path, book(&asset, "host-42")).await;
    let unbound_run: Run = serde_json::from_value(unbound.json()["run"].clone()).unwrap();
    approve(&h, &path, &unbound_run).await;
    let aborted = workflow::advance(&h.state, h.tenant, unbound_run.id, Timestamp::now()).await.unwrap();
    assert_eq!(aborted.status, Status::Aborted);
    assert!(agf_api::integration_runtime::history(&h.state, h.tenant, "edr-isolation").await.unwrap().is_empty());

    let current_revision = clear.json()["asset"]["updated_at"].as_str().unwrap().to_string();
    let rebound = h
        .request(
            "PUT",
            &binding_path,
            Some(&h.admin),
            Some(json!({"host_id":"host-42","expected_updated_at":current_revision,"reason":"Verified EDR host"})),
        )
        .await;
    assert_eq!(rebound.status, StatusCode::OK, "{}", rebound.text);
    let approved = h.post(&path, book(&asset, "host-42")).await;
    let approved_run: Run = serde_json::from_value(approved.json()["run"].clone()).unwrap();
    approve(&h, &path, &approved_run).await;
    let finished = workflow::advance(&h.state, h.tenant, approved_run.id, Timestamp::now()).await.unwrap();
    assert_eq!(finished.status, Status::Completed, "{:?}", finished.reason);
}
