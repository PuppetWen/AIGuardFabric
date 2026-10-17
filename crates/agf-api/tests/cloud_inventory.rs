//! 完整分页、失败保留快照、账号隔离和盘点后资产链接的本地联调。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, query_param},
};
const CONFIG: &str = "/api/v1/alicloud/connections/alicloud-agentteams";
const SYNC: &str = "/api/v1/alicloud/agentteams/sync";
const TEAMS: &str = "/api/v1/alicloud/agentteams";
async fn setup_live() -> Harness {
    let mut h = setup().await;
    std::sync::Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = agf_api::build_router(h.state.clone());
    h
}
fn body() -> Value {
    json!({"request_id":uuid::Uuid::new_v4(),"configuration_version":1,"confirm_live":true})
}
#[tokio::test]
async fn mock_sync_populates_scoped_assets_preserves_manual_governance_and_never_calls_cloud() {
    let h = setup_live().await;
    let server = MockServer::start().await;
    let saved = h
        .request(
            "PUT",
            CONFIG,
            Some(&h.admin),
            Some(json!({"expected_version":0,"enabled":true,"mock":true,
        "settings":{"endpoint":server.uri(),"instance_id":"inst-demo"}})),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let request = body();
    let synced = h.post(SYNC, request.clone()).await;
    assert_eq!(synced.status, StatusCode::OK, "{}", synced.text);
    assert_eq!(synced.json()["assets"], 1);
    let teams = h.get(TEAMS).await.json();
    let team = &teams[0];
    assert_eq!(team["name"], "my-team");
    assert_eq!(team["mocked"], true);
    assert_eq!(team["metricsAvailable"], false);
    assert_eq!(team["tasks"][0]["assignedTo"], "worker-demo");
    assert_eq!(team["tasks"][0]["taskTitle"], "数据分析任务");
    assert_eq!(team["humanMembers"][0]["name"], "member-user");
    let id = agf_core::ids::Id::parse(team["members"][0]["assetId"].as_str().unwrap()).unwrap();
    let mut asset = h.state.store.asset_get(h.tenant, id).unwrap().unwrap();
    asset.owner = Some("manual-owner".into());
    asset.data_class = agf_core::enums::DataClass::Confidential;
    asset.lifecycle = agf_core::enums::LifecycleState::Production;
    h.state.store.asset_upsert(&asset).unwrap();
    assert_eq!(h.post(SYNC, request).await.status, StatusCode::OK);
    let unchanged = h.state.store.asset_get(h.tenant, id).unwrap().unwrap();
    assert_eq!(unchanged.owner, asset.owner);
    assert_eq!(unchanged.lifecycle, asset.lifecycle);
    assert_eq!(unchanged.data_class, asset.data_class);
    assert_eq!(h.state.store.asset_list_all(h.tenant).unwrap().len(), 1);
    assert!(!serde_json::to_string(&unchanged).unwrap().contains("ClientSecret"));
    assert!(server.received_requests().await.unwrap().is_empty());
    assert!(agf_api::cloud_inventory::load(&h.state, h.other_tenant).await.unwrap().is_none());
    let raw = h
        .state
        .configurations
        .get::<Value>(h.tenant, "cloud-inventory", agf_api::integration_store::id(h.tenant, "alicloud-agentteams"))
        .await
        .unwrap()
        .unwrap();
    assert!(!raw.to_string().contains("worker-demo"));
    assert_eq!(h.request("POST", SYNC, Some(&h.viewer), Some(body())).await.status, StatusCode::FORBIDDEN);
}
#[tokio::test]
async fn live_inventory_follows_all_pages_and_repeated_token_does_not_replace_previous_snapshot() {
    let h = setup_live().await;
    let server = MockServer::start().await;
    let saved=h.request("PUT",CONFIG,Some(&h.admin),Some(json!({"expected_version":0,"enabled":true,"mock":false,
        "settings":{"endpoint":server.uri(),"instance_id":"instance-local"},"secrets":{"access_key_id":"LOCAL-ID","access_key_secret":"LOCAL-SECRET"}}))).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert!(h.get(TEAMS).await.json().as_array().unwrap().is_empty());
    let first = json!({"Items":[{"Name":"first-team","WorkerNames":["worker-local"]}],"NextToken":"page-2"});
    Mock::given(header("x-acs-action", "ListTeams"))
        .respond_with(ResponseTemplate::new(200).set_body_json(first))
        .mount(&server)
        .await;
    Mock::given(header("x-acs-action", "ListTeams"))
        .and(query_param("NextToken", "page-2"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"Items":[{"Name":"second-team","WorkerNames":[]}],"NextToken":""})),
        )
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(header("x-acs-action", "ListWorkers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Items":[{"Name":"worker-local"}]})))
        .mount(&server)
        .await;
    for (name, workers) in [("first-team", json!(["worker-local"])), ("second-team", json!([]))] {
        Mock::given(header("x-acs-action", "GetTeam"))
            .and(query_param("Name", name))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Data":{
                "InstanceId":"instance-local","Name":name,"WorkerNames":workers
            }})))
            .mount(&server)
            .await;
    }
    Mock::given(header("x-acs-action", "GetWorker"))
        .and(query_param("Name", "worker-local"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"Data":{"InstanceId":"instance-local","Name":"worker-local","Status":"Running","Model":{"ModelName":"test-model"}}}),
        ))
        .mount(&server)
        .await;
    Mock::given(header("x-acs-action", "ListTeamTasks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Items":[]})))
        .mount(&server)
        .await;
    let request = body();
    let result = h.post(SYNC, request.clone()).await;
    assert_eq!(result.status, StatusCode::OK, "{}", result.text);
    assert_eq!(result.json()["teams"], 2);
    let count = server.received_requests().await.unwrap().len();
    assert_eq!(count, 8);
    assert_eq!(h.post(SYNC, request).await.status, StatusCode::OK);
    assert_eq!(server.received_requests().await.unwrap().len(), count, "retry must reuse durable read receipts");
    let snapshot = agf_api::cloud_inventory::load(&h.state, h.tenant).await.unwrap().unwrap();
    server.reset().await;
    Mock::given(header("x-acs-action", "ListTeams"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Items":[],"NextToken":"same-token"})))
        .mount(&server)
        .await;
    assert_ne!(h.post(SYNC, body()).await.status, StatusCode::OK);
    let retained = agf_api::cloud_inventory::load(&h.state, h.tenant).await.unwrap().unwrap();
    assert_eq!(retained.checked_at, snapshot.checked_at);
    assert_eq!(h.get(TEAMS).await.json().as_array().unwrap().len(), 2);
    assert!(h.get("/api/v1/alicloud/cross-team-calls").await.json().as_array().unwrap().is_empty());
}
