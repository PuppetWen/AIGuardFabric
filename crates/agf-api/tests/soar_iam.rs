//! A reviewed case can deactivate only its exact bound SCIM identity.
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
                "fingerprint":format!("scim-user-{}", agf_core::ids::Id::new()),
                "kind":"credential","name":"External account","owner":"soc",
                "data_class":"internal","note":"SOAR SCIM integration test",
                "scim_user_id":"user-42"
            }),
        )
        .await;
    assert_eq!(asset.status, StatusCode::OK, "{}", asset.text);
    let asset_id = asset.json()["asset"]["id"].as_str().unwrap().to_string();
    let case = h
        .post(
            "/api/v1/cases",
            json!({
                "title":"SCIM case","severity":"high","asset_ids":[asset_id]
            }),
        )
        .await;
    assert_eq!(case.status, StatusCode::CREATED, "{}", case.text);
    let case_id = case.json()["case"]["id"].as_str().unwrap().to_string();
    let mock = live_endpoint.is_none();
    let config = h
        .request(
            "PUT",
            "/api/v1/integrations/adapters/iam-scim/configuration",
            Some(&h.admin),
            Some(json!({"expected_version":0,"enabled":true,"mock":mock,
                "settings":live_endpoint.map_or_else(|| json!({}), |endpoint| json!({"endpoint":endpoint})),
                "secrets":if mock { json!({}) } else { json!({"api_token":"test-scim-token"}) }
            })),
        )
        .await;
    assert_eq!(config.status, StatusCode::OK, "{}", config.text);
    (h, asset_id, case_id)
}

fn book(asset_id: &str, user: &str) -> Value {
    json!({"playbook":{
        "key":"reviewed-scim-user","name":"Reviewed identity deactivation",
        "trigger":{},"timeout_secs":120,
        "steps":[{"name":"Deactivate exact user","action":"deactivate-external-user",
            "params":{"asset_id":asset_id,"user_id":user,
                "configuration_version":1,"reason":"Confirmed account compromise"}}]
    }})
}

async fn approve(h: &Harness, path: &str, run: &Run) {
    let response = h
        .post(
            &format!("{path}/{}/decision", run.id),
            json!({
                "expected_version":run.version,"action":"approve","reason":"Matched case identity and SCIM user"
            }),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
}

#[tokio::test]
async fn iam_requires_approval_and_reuses_one_mock_receipt() {
    let (h, asset, case) = fixture(None).await;
    let path = format!("/api/v1/cases/{case}/playbook-runs");
    let response = h.post(&path, book(&asset, "user-42")).await;
    assert_eq!(response.status, StatusCode::ACCEPTED, "{}", response.text);
    let run: Run = serde_json::from_value(response.json()["run"].clone()).unwrap();
    assert_eq!(run.status, Status::Approval);
    assert!(agf_api::integration_runtime::history(&h.state, h.tenant, "iam-scim").await.unwrap().is_empty());
    approve(&h, &path, &run).await;
    let finished = workflow::advance(&h.state, h.tenant, run.id, Timestamp::now()).await.unwrap();
    assert_eq!(finished.status, Status::Completed, "{:?}", finished.reason);
    assert!(finished.trace[0].note.contains("SCIM Mock"));
    workflow::advance(&h.state, h.tenant, run.id, Timestamp::now()).await.unwrap();
    let receipts = agf_api::integration_runtime::history(&h.state, h.tenant, "iam-scim").await.unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["mocked"], true);
}

#[tokio::test]
async fn approved_live_scim_call_patches_exact_user_once() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/scim/v2/Users/user-42"))
        .and(header("authorization", "Bearer test-scim-token"))
        .and(header("content-type", "application/scim+json"))
        .and(body_partial_json(json!({"Operations":[{"op":"replace","path":"active","value":false}]})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":"user-42","active":false})))
        .expect(1)
        .mount(&server)
        .await;
    let (h, asset, case) = fixture(Some(format!("{}/scim/v2", server.uri()))).await;
    let direct = h
        .post(
            "/api/v1/integrations/adapters/iam-scim/operations",
            json!({
                "request_id":agf_core::ids::Id::new(),"configuration_version":1,"confirm_live":true,
                "operation":"send","payload":{
                    "kind":"event","event_type":"enforce.deactivate-user","severity":"high",
                    "title":"Direct bypass","summary":"Must fail","body":{},
                    "idempotency_key":"direct-bypass","occurred_at":Timestamp::now(),
                    "labels":{"action":"deactivate","user_id":"user-42"}
                }
            }),
        )
        .await;
    assert_eq!(direct.status, StatusCode::PRECONDITION_FAILED, "{}", direct.text);
    assert!(server.received_requests().await.unwrap().is_empty());
    let path = format!("/api/v1/cases/{case}/playbook-runs");
    let response = h.post(&path, book(&asset, "user-42")).await;
    let run: Run = serde_json::from_value(response.json()["run"].clone()).unwrap();
    assert_eq!(run.status, Status::Approval);
    approve(&h, &path, &run).await;
    let finished = workflow::advance(&h.state, h.tenant, run.id, Timestamp::now()).await.unwrap();
    assert_eq!(finished.status, Status::Completed, "{:?}", finished.reason);
    assert!(finished.trace[0].note.contains("SCIM Live"));
    workflow::advance(&h.state, h.tenant, run.id, Timestamp::now()).await.unwrap();
    server.verify().await;
}

#[tokio::test]
async fn iam_rejects_wrong_identity_and_binding_is_versioned() {
    let (h, asset, case) = fixture(None).await;
    let path = format!("/api/v1/cases/{case}/playbook-runs");
    for user in ["user-43", "../admin"] {
        let response = h.post(&path, book(&asset, user)).await;
        let run: Run = serde_json::from_value(response.json()["run"].clone()).unwrap();
        approve(&h, &path, &run).await;
        let finished = workflow::advance(&h.state, h.tenant, run.id, Timestamp::now()).await.unwrap();
        assert_eq!(finished.status, Status::Aborted, "{:?}", finished.reason);
    }
    assert!(agf_api::integration_runtime::history(&h.state, h.tenant, "iam-scim").await.unwrap().is_empty());
    let detail = h.get(&format!("/api/v1/assets/{asset}")).await;
    let revision = detail.json()["governance"]["updated_at"].as_str().unwrap().to_string();
    let binding = format!("/api/v1/assets/{asset}/scim-user");
    let cleared = h
        .request(
            "PUT",
            &binding,
            Some(&h.admin),
            Some(json!({
                "user_id":"","expected_updated_at":revision,"reason":"Retire mapping"
            })),
        )
        .await;
    assert_eq!(cleared.status, StatusCode::OK, "{}", cleared.text);
    let stale = h
        .request(
            "PUT",
            &binding,
            Some(&h.admin),
            Some(json!({
                "user_id":"user-99","expected_updated_at":revision,"reason":"Stale update"
            })),
        )
        .await;
    assert_eq!(stale.status, StatusCode::CONFLICT, "{}", stale.text);
}

#[tokio::test]
async fn interrupted_iam_receipt_pauses_for_manual_review() {
    let (h, asset, case) = fixture(None).await;
    let path = format!("/api/v1/cases/{case}/playbook-runs");
    let response = h.post(&path, book(&asset, "user-42")).await;
    let run: Run = serde_json::from_value(response.json()["run"].clone()).unwrap();
    approve(&h, &path, &run).await;
    let request_id = agf_core::ids::deterministic_id("agf.soar.edr", &format!("{}:0", run.id));
    let receipt_id =
        agf_core::ids::deterministic_id("agf.integration.run", &format!("{}:iam-scim:{request_id}", h.tenant));
    let prior = agf_api::integration_receipts::Run {
        id: receipt_id,
        request_id,
        adapter: "iam-scim".into(),
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
    assert!(reviewed.reason.unwrap().contains("IAM_UNCERTAIN:"));
}
