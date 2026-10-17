//! Cloud account configuration and operations use isolated local HTTP servers.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::time::Timestamp;
use common::*;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, query_param},
};
const CMS: &str = "/api/v1/alicloud/connections/alicloud-cms";
async fn live() -> Harness {
    let mut h = setup().await;
    std::sync::Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = agf_api::build_router(h.state.clone());
    h
}
async fn save(h: &Harness, path: &str, body: Value) -> Resp {
    h.request("PUT", path, Some(&h.admin), Some(body)).await
}
fn secrets() -> Value {
    json!({"access_key_id":"LOCAL-TEST-AK","access_key_secret":"LOCAL-TEST-SECRET"})
}
fn operation(version: u64) -> Value {
    json!({"request_id":uuid::Uuid::new_v4(),"configuration_version":version,
    "action":"PutCustomEvent","confirm_live":true,"parameters":{"EventInfo":[{"EventName":"agf-test","Content":"test-event"}]}})
}
#[tokio::test]
async fn cloud_secrets_are_tenant_bound_masked_versioned_and_never_sent_on_save() {
    let h = live().await;
    let server = MockServer::start().await;
    let body = json!({"expected_version":0,"enabled":true,"mock":false,"settings":{"endpoint":server.uri()},"secrets":secrets()});
    let saved = save(&h, CMS, body.clone()).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert!(!saved.text.contains("LOCAL-TEST-SECRET") && !saved.text.contains("LOCAL-TEST-AK"));
    assert!(server.received_requests().await.unwrap().is_empty());
    let row = agf_api::cloud_store::load(&h.state, h.tenant, "alicloud-cms").await.unwrap().unwrap();
    assert!(!serde_json::to_string(&row).unwrap().contains("LOCAL-TEST-SECRET"));
    assert!(agf_api::integration_store::decrypt(&h.state, h.other_tenant, &row).is_err());
    assert_eq!(save(&h, CMS, body.clone()).await.status, StatusCode::CONFLICT);
    assert_eq!(h.request("GET", CMS, Some(&h.viewer), None).await.status, StatusCode::FORBIDDEN);
    let foreign = h
        .request_with(
            "GET",
            CMS,
            &[("Authorization", &format!("Bearer {}", h.admin)), ("X-AGF-Tenant", &h.other_tenant.to_string())],
            None,
        )
        .await;
    assert_eq!(foreign.json()["version"], 0);
    let mut equivalent = body.clone();
    equivalent["expected_version"] = json!(1);
    equivalent["secrets"] = json!({});
    equivalent["settings"]["credential_source"] = json!("access-key");
    equivalent["settings"]["region_id"] = json!("cn-hangzhou");
    let kept = save(&h, CMS, equivalent).await;
    assert_eq!(kept.status, StatusCode::OK, "{}", kept.text);
    assert_eq!(kept.json()["secret_keys"].as_array().unwrap().len(), 2);
    let mut draft = body;
    draft["expected_version"] = json!(2);
    draft["enabled"] = json!(false);
    draft["secrets"] = json!({});
    draft["settings"]["endpoint"] = json!("https://different.example.test");
    let draft = save(&h, CMS, draft).await;
    assert_eq!(draft.status, StatusCode::OK, "{}", draft.text);
    assert_eq!(draft.json()["secret_keys"], json!([]));
}
#[tokio::test]
async fn assume_role_refresh_cache_and_durable_receipts_prevent_repeat_writes() {
    let h = live().await;
    let sts = MockServer::start().await;
    let cloud = MockServer::start().await;
    Mock::given(method("POST"))
        .and(query_param("Action", "AssumeRole"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Credentials":{
            "AccessKeyId":"LOCAL-STS-ID","AccessKeySecret":"LOCAL-STS-SECRET","SecurityToken":"LOCAL-STS-TOKEN",
            "Expiration":Timestamp::now().offset_secs(1800).to_rfc3339()}})))
        .expect(1)
        .mount(&sts)
        .await;
    Mock::given(method("POST"))
        .and(header("x-acs-action", "PutCustomEvent"))
        .and(header("x-acs-security-token", "LOCAL-STS-TOKEN"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Code":"200","RequestId":"cloud-local-receipt"})))
        .expect(2)
        .mount(&cloud)
        .await;
    let saved = save(
        &h,
        CMS,
        json!({"expected_version":0,"enabled":true,"mock":false,"settings":{
        "endpoint":cloud.uri(),"credential_source":"assume-role","sts_endpoint":sts.uri(),
        "role_arn":"acs:ram::1234567890123456:role/agf-test"},"secrets":secrets()}),
    )
    .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert!(sts.received_requests().await.unwrap().is_empty());
    let body = operation(1);
    let call = h.post(&format!("{CMS}/operations"), body.clone()).await;
    assert_eq!(call.status, StatusCode::OK, "{}", call.text);
    assert_eq!(call.json()["status"], "succeeded", "{}", call.text);
    let duplicate = h.post(&format!("{CMS}/operations"), body.clone()).await;
    assert_eq!(duplicate.json(), call.json());
    let second = h.post(&format!("{CMS}/operations"), operation(1)).await;
    assert_eq!(second.json()["status"], "succeeded", "{}", second.text);
    let id = call.json()["id"].as_str().unwrap().to_string();
    assert_eq!(h.get(&format!("{CMS}/operations/{id}")).await.json(), call.json());
    assert_eq!(
        h.get(&format!("/api/v1/alicloud/connections/alicloud-apig/operations/{id}")).await.status,
        StatusCode::NOT_FOUND
    );
    let mut collision = body.clone();
    collision["parameters"]["EventInfo"][0]["Content"] = json!("changed");
    assert_eq!(h.post(&format!("{CMS}/operations"), collision).await.status, StatusCode::CONFLICT);
    let mut unconfirmed = operation(1);
    unconfirmed["confirm_live"] = json!(false);
    assert_eq!(h.post(&format!("{CMS}/operations"), unconfirmed).await.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(h.post(&format!("{CMS}/operations"), operation(0)).await.status, StatusCode::CONFLICT);
    assert_eq!(h.get(&format!("{CMS}/operations")).await.json()["items"].as_array().unwrap().len(), 2);
}
#[tokio::test]
async fn mock_operations_never_contact_endpoints_and_probe_checks_actual_read_permission() {
    let h = live().await;
    let server = MockServer::start().await;
    let settings = json!({"endpoint":server.uri(),"region_id":"cn-hangzhou"});
    assert_eq!(
        save(&h, CMS, json!({"expected_version":0,"enabled":true,"mock":true,"settings":settings})).await.status,
        StatusCode::OK
    );
    let mock = h.post(&format!("{CMS}/operations"), operation(1)).await;
    assert_eq!(mock.json()["status"], "succeeded");
    assert_eq!(mock.json()["receipt"]["mocked"], true);
    h.post(&format!("{CMS}/probe"), json!({"configuration_version":1})).await;
    let mock_checks = h.get("/api/v1/alicloud/self-check").await;
    assert!(mock_checks.json().as_array().unwrap().iter().all(|item| item["result"] != "pass"));
    assert!(server.received_requests().await.unwrap().is_empty());
    Mock::given(method("GET"))
        .and(header("x-acs-action", "DescribeAlertHistoryList"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"Code":"200","AlarmHistoryList":{"AlarmHistory":[]}})),
        )
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        save(
            &h,
            CMS,
            json!({"expected_version":1,"enabled":true,"mock":false,"settings":settings,"secrets":secrets()})
        )
        .await
        .status,
        StatusCode::OK
    );
    let probe = h.post(&format!("{CMS}/probe"), json!({"configuration_version":2,"confirm_live":true})).await;
    assert_eq!(probe.json()["status"], "succeeded", "{}", probe.text);
    assert_eq!(probe.json()["mocked"], false);
    let checks = h.get("/api/v1/alicloud/self-check").await;
    let checks = checks.json();
    let cms_checks: Vec<_> = checks
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["id"].as_str().unwrap_or_default().starts_with("alicloud-cms-"))
        .collect();
    assert_eq!(cms_checks.len(), 3);
    assert_eq!(cms_checks.iter().filter(|item| item["result"] == "pass").count(), 1);
    assert!(cms_checks.iter().filter(|item| item["category"] != "connectivity").all(|item| item["result"] == "warn"));
    let current = h.get(CMS).await;
    assert_eq!(current.json()["probe"]["version"], 2);
    let invalid=h.post(&format!("{CMS}/operations"),json!({"request_id":uuid::Uuid::new_v4(),"configuration_version":2,"action":"PutResourceMetricData","confirm_live":true,"parameters":{}})).await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
    let changed = save(&h, CMS, json!({"expected_version":2,"enabled":true,"mock":false,"settings":settings})).await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    assert!(changed.json()["probe"].is_null());
    let stale_checks = h.get("/api/v1/alicloud/self-check").await;
    assert!(stale_checks.json().as_array().unwrap().iter().all(|item| item["result"] != "pass"));
}
