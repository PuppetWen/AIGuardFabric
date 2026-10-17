//! Malformed cloud pagination and wrong instance responses cannot publish inventory.
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
const INSTANCE: &str = "instance-consistency";

fn request() -> Value {
    json!({"request_id":uuid::Uuid::new_v4(),"configuration_version":1,"confirm_live":true})
}

async fn fixture(mocked: bool) -> (Harness, MockServer) {
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    let server = MockServer::start().await;
    let response = h
        .request(
            "PUT",
            CONFIG,
            Some(&h.admin),
            Some(json!({
                "expected_version":0,"enabled":true,"mock":mocked,
                "settings":{"endpoint":server.uri(),"instance_id":INSTANCE},
                "secrets":{"access_key_id":"LOCAL-ID","access_key_secret":"LOCAL-SECRET"}
            })),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    (h, server)
}

async fn response(server: &MockServer, action: &str, body: Value, priority: u8) {
    Mock::given(header("x-acs-action", action))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .with_priority(priority)
        .mount(server)
        .await;
}

async fn valid_inventory(server: &MockServer, status: &str) {
    for (action, items) in [
        ("ListTeams", json!([{"InstanceId":INSTANCE,"Name":"team-local","WorkerNames":["worker-local"]}])),
        ("ListWorkers", json!([{"InstanceId":INSTANCE,"Name":"worker-local"}])),
        ("ListTeamTasks", json!([{"TaskId":"task-local","TaskTitle":"Original task","AssignedTo":"worker-local"}])),
    ] {
        response(server, action, json!({"Items":items,"TotalCount":1,"NextToken":""}), 10).await;
    }
    response(
        server,
        "GetTeam",
        json!({"Data":{"InstanceId":INSTANCE,"Name":"team-local","WorkerNames":["worker-local"]}}),
        10,
    )
    .await;
    response(
        server,
        "GetWorker",
        json!({"Data":{
            "InstanceId":INSTANCE,"Name":"worker-local","Status":status,"VersionCode":"baseline"
        }}),
        10,
    )
    .await;
}

async fn saved_inventory(h: &Harness) -> (Value, Value, Value) {
    let snapshot = agf_api::cloud_inventory::load(&h.state, h.tenant).await.unwrap().unwrap();
    let reported = h.get(TEAMS).await;
    assert_eq!(reported.status, StatusCode::OK, "{}", reported.text);
    let mut teams = reported.json();
    // Observation windows follow the request clock; all inventory and metric
    // fields must still remain identical after a rejected inventory refresh.
    for team in teams.as_array_mut().expect("teams must remain an array") {
        let team = team.as_object_mut().expect("each team must remain an object");
        team.remove("windowFrom");
        team.remove("windowTo");
    }
    (
        serde_json::to_value(snapshot).unwrap(),
        serde_json::to_value(h.state.store.asset_list_all(h.tenant).unwrap()).unwrap(),
        teams,
    )
}

async fn reject_and_retain(h: &Harness, before: &(Value, Value, Value), label: &str) {
    let rejected = h.post(SYNC, request()).await;
    assert!(!rejected.status.is_success(), "{label} must reject incomplete inventory: {}", rejected.text);
    assert_eq!(saved_inventory(h).await, *before, "{label} must retain the complete snapshot and original assets");
}

fn item(action: &str, name: &str) -> Value {
    match action {
        "ListTeamTasks" => json!({"TaskId":name,"TaskTitle":"Unpublished task"}),
        "ListTeams" => json!({"Name":name,"WorkerNames":[]}),
        _ => json!({"Name":name}),
    }
}

fn invalid_pages() -> Vec<(&'static str, &'static str, Value, Option<Value>)> {
    let mut cases = Vec::new();
    for action in ["ListTeams", "ListWorkers", "ListTeamTasks"] {
        let first = item(action, "first-unpublished");
        let second = item(action, "second-unpublished");
        cases.extend([
            (action, "duplicate identity within page", json!({"Items":[first,first]}), None),
            (
                action,
                "duplicate identity across pages",
                json!({"Items":[first],"NextToken":"next"}),
                Some(json!({"Items":[first],"NextToken":""})),
            ),
            (action, "premature last page", json!({"Items":[first],"TotalCount":2}), None),
            (action, "more rows than reported", json!({"Items":[first],"TotalCount":0}), None),
            (
                action,
                "changing total count",
                json!({"Items":[first],"TotalCount":2,"NextToken":"next"}),
                Some(json!({"Items":[second],"TotalCount":3,"NextToken":""})),
            ),
            (
                action,
                "repeated pagination token",
                json!({"Items":[first],"NextToken":"next"}),
                Some(json!({"Items":[second],"NextToken":"next"})),
            ),
            (action, "missing resource identity", json!({"Items":[{}]}), None),
            (action, "invalid total count", json!({"Items":[first],"TotalCount":"1"}), None),
            (action, "invalid pagination token", json!({"Items":[first],"NextToken":42}), None),
        ]);
    }
    cases.push((
        "ListTeams",
        "resource count exceeds single inventory budget",
        json!({"Items":(0..201).map(|index|item("ListTeams",&format!("too-many-{index}"))).collect::<Vec<_>>() }),
        None,
    ));
    cases
}

#[tokio::test]
async fn incomplete_or_conflicting_pages_preserve_previous_snapshot_and_assets() {
    let (h, server) = fixture(false).await;
    valid_inventory(&server, "Running").await;
    let synced = h.post(SYNC, request()).await;
    assert_eq!(synced.status, StatusCode::OK, "{}", synced.text);
    // TaskId is the documented task identity; valid tasks have no Name property.
    assert_eq!(synced.json()["tasks"], 1);
    let before = saved_inventory(&h).await;
    for (action, label, first, next) in invalid_pages() {
        server.reset().await;
        valid_inventory(&server, "Failed").await;
        response(&server, action, first, 5).await;
        if let Some(next) = next {
            Mock::given(header("x-acs-action", action))
                .and(query_param("NextToken", "next"))
                .respond_with(ResponseTemplate::new(200).set_body_json(next))
                .with_priority(1)
                .mount(&server)
                .await;
        }
        reject_and_retain(&h, &before, &format!("{action}: {label}")).await;
    }
}

#[tokio::test]
async fn worker_details_must_match_requested_name_and_instance() {
    let (h, server) = fixture(false).await;
    valid_inventory(&server, "Running").await;
    assert_eq!(h.post(SYNC, request()).await.status, StatusCode::OK);
    let before = saved_inventory(&h).await;
    for (label, body) in [
        ("wrong instance", json!({"Data":{"Name":"worker-local","InstanceId":"foreign-instance","Status":"Failed"}})),
        ("missing instance", json!({"Data":{"Name":"worker-local","Status":"Failed"}})),
        ("wrong name", json!({"Data":{"Name":"foreign-worker","InstanceId":INSTANCE}})),
        ("missing data object", json!({"Data":[]})),
    ] {
        server.reset().await;
        valid_inventory(&server, "Failed").await;
        response(&server, "GetWorker", body, 5).await;
        reject_and_retain(&h, &before, label).await;
    }
}

#[tokio::test]
async fn null_optional_pagination_fields_do_not_reject_complete_inventory() {
    let (h, server) = fixture(false).await;
    valid_inventory(&server, "Running").await;
    for (action, items) in [
        ("ListTeams", json!([{"Name":"team-local","WorkerNames":["worker-local"]}])),
        ("ListWorkers", json!([{"Name":"worker-local"}])),
        ("ListTeamTasks", json!([{"TaskId":"task-local","TaskTitle":"Task without Name"}])),
    ] {
        response(&server, action, json!({"Items":items,"TotalCount":null,"NextToken":null}), 5).await;
    }
    let synced = h.post(SYNC, request()).await;
    assert_eq!(synced.status, StatusCode::OK, "{}", synced.text);
    assert_eq!(synced.json()["teams"], 1);
    assert_eq!(synced.json()["workers"], 1);
    assert_eq!(synced.json()["tasks"], 1);
    assert_eq!(server.received_requests().await.unwrap().len(), 5);
}

#[tokio::test]
async fn mock_fixture_worker_identity_is_scoped_to_the_selected_test_instance() {
    let (h, server) = fixture(true).await;
    let synced = h.post(SYNC, request()).await;
    assert_eq!(synced.status, StatusCode::OK, "{}", synced.text);
    let snapshot = agf_api::cloud_inventory::load(&h.state, h.tenant).await.unwrap().unwrap();
    assert_eq!(snapshot.instance_id, INSTANCE);
    assert_eq!(snapshot.workers[0]["InstanceId"], INSTANCE);
    assert_eq!(snapshot.teams[0]["InstanceId"], INSTANCE);
    assert_eq!(snapshot.tasks["my-team"][0]["TaskId"], "task-xxx");
    let asset = h.state.store.asset_get(h.tenant, snapshot.assets["worker-demo"]).unwrap().unwrap();
    assert_eq!(asset.attributes["cloud_instance_id"], INSTANCE);
    assert!(asset.fingerprint.contains(INSTANCE));
    assert!(server.received_requests().await.unwrap().is_empty());
}
