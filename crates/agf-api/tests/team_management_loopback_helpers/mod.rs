//! A stateful public-schema RPC server; every request goes through the real Reqwest transport.
#![allow(dead_code, unused_imports, unreachable_pub)]
use crate::{common::*, team_management_helpers::*};
use agf_core::{enums::AliCloudService, ids::Id};
use std::{collections::VecDeque, sync::Mutex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::any};

#[derive(Clone, Copy)]
pub enum Failure {
    Forbidden,
    Html404,
    MissingRequestId404,
    MalformedIdentity,
    Unknown,
}
pub struct Cloud {
    pub teams: BTreeMap<String, Value>,
    pub workers: Vec<Value>,
    pub users: BTreeMap<String, Value>,
    pub user_pages: VecDeque<(u16, Value)>,
    pub team_failure: Option<Failure>,
    pub user_failure: Option<Failure>,
    pub write_unknown: bool,
    pub write_denied: bool,
    pub leave_old_description: bool,
    pub write_delay: bool,
    pub read_delay: Option<String>,
    pub writes: Vec<(String, BTreeMap<String, String>)>,
}
impl Cloud {
    pub fn seeded() -> Self {
        let sample = |action| agf_alicloud::openapi::fixture(AliCloudService::AgentTeams, action).unwrap();
        let mut team = sample("GetTeam")["Data"].clone();
        team["InstanceId"] = json!(INSTANCE);
        let mut worker = sample("GetWorker")["Data"].clone();
        worker["InstanceId"] = json!(INSTANCE);
        let mut users = BTreeMap::new();
        for mut user in sample("ListUsers")["Items"].as_array().unwrap().clone() {
            user["InstanceId"] = json!(INSTANCE);
            users.insert(user["Name"].as_str().unwrap().to_owned(), user);
        }
        Self {
            teams: BTreeMap::from([(TEAM.into(), team)]),
            workers: vec![worker],
            users,
            user_pages: VecDeque::new(),
            team_failure: None,
            user_failure: None,
            write_unknown: false,
            write_denied: false,
            leave_old_description: false,
            write_delay: false,
            read_delay: None,
            writes: vec![],
        }
    }
}
#[derive(Clone)]
struct Rpc {
    cloud: Arc<Mutex<Cloud>>,
    written: tokio::sync::mpsc::UnboundedSender<()>,
    observed: tokio::sync::mpsc::UnboundedSender<String>,
}
fn success(body: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(body)
}
pub fn absent() -> ResponseTemplate {
    ResponseTemplate::new(404).set_body_json(json!({"Code":"Resource.NotFound","Success":false,
        "Message":"The specified resource does not exist.","RequestId":"loopback-resource-not-found"}))
}
fn failed(mode: Failure) -> ResponseTemplate {
    match mode {
        Failure::Forbidden => ResponseTemplate::new(403).set_body_json(json!({"Code":"Forbidden.RAM",
            "Message":"PRIVATE-UPSTREAM-DETAIL","RequestId":"loopback-forbidden"})),
        Failure::Html404 => {
            ResponseTemplate::new(404).set_body_raw("<html>PRIVATE-UPSTREAM-DETAIL</html>", "text/html")
        }
        Failure::MissingRequestId404 => ResponseTemplate::new(404).set_body_json(json!({"Code":"Resource.NotFound"})),
        Failure::MalformedIdentity => {
            success(json!({"Data":{"Name":"foreign-resource","InstanceId":"foreign-instance"}}))
        }
        Failure::Unknown => ResponseTemplate::new(500).set_body_json(json!({"Code":"InternalError",
            "Message":"PRIVATE-UPSTREAM-DETAIL","RequestId":"loopback-unknown"})),
    }
}
impl Respond for Rpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let action = request.headers.get("x-acs-action").unwrap().to_str().unwrap();
        let _ = self.observed.send(action.into());
        let mut parameters: BTreeMap<String, String> =
            request.url.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
        for (key, value) in url::form_urlencoded::parse(&request.body) {
            parameters.insert(key.into_owned(), value.into_owned());
        }
        let name = parameters.get("Name").map(String::as_str).unwrap_or("");
        let mut cloud = self.cloud.lock().unwrap();
        let response = match action {
            "ListTeams" => success(
                json!({"Items":cloud.teams.values().collect::<Vec<_>>(),"TotalCount":cloud.teams.len(),"NextToken":null}),
            ),
            "GetTeam" => {
                if let Some(failure) = cloud.team_failure {
                    return failed(failure);
                }
                cloud.teams.get(name).map_or_else(absent, |team| success(json!({"Data":team})))
            }
            "ListWorkers" => success(json!({"Items":cloud.workers,"TotalCount":cloud.workers.len(),"NextToken":null})),
            "GetWorker" => cloud
                .workers
                .iter()
                .find(|worker| worker["Name"] == name)
                .map_or_else(absent, |worker| success(json!({"Data":worker}))),
            "ListTeamTasks" => success(json!({"Items":[],"TotalCount":0,"NextToken":null})),
            "ListUsers" => {
                if let Some((status, body)) = cloud.user_pages.pop_front() {
                    return ResponseTemplate::new(status).set_body_json(body);
                }
                let query = parameters.get("NameLike");
                let items: Vec<_> = cloud
                    .users
                    .values()
                    .filter(|user| query.is_none_or(|query| user["Name"].as_str().unwrap().contains(query)))
                    .collect();
                success(json!({"Items":items,"TotalCount":items.len(),"NextToken":null}))
            }
            "GetUser" => {
                if let Some(failure) = cloud.user_failure {
                    return failed(failure);
                }
                cloud.users.get(name).map_or_else(absent, |user| success(json!({"Data":user})))
            }
            "CreateTeam" | "UpdateTeam" | "DeleteTeam" => {
                assert_eq!(parameters.get("InstanceId").map(String::as_str), Some(INSTANCE));
                for forbidden in ["WorkerNames", "Groups", "LeaderName"] {
                    assert!(!parameters.contains_key(forbidden));
                }
                if action == "UpdateTeam" {
                    assert!(!parameters.contains_key("AdminName"));
                }
                if action == "DeleteTeam" {
                    assert!(!parameters.contains_key("ClientToken"));
                } else {
                    assert!(parameters.get("ClientToken").is_some_and(|token| !token.is_empty()));
                }
                cloud.writes.push((action.into(), parameters.clone()));
                if cloud.write_denied {
                    return failed(Failure::Forbidden);
                }
                if action == "CreateTeam" {
                    if cloud.teams.contains_key(name) {
                        return ResponseTemplate::new(409)
                            .set_body_json(json!({"Code":"Resource.AlreadyExists","RequestId":"loopback-conflict"}));
                    }
                    let mut team = json!({"InstanceId":INSTANCE,"Name":name,"Description":"","TeamMembers":[],"WorkerNames":[],"Rooms":[],"Status":"Running"});
                    for key in ["Description", "AdminName"] {
                        if let Some(value) = parameters.get(key) {
                            team[key] = json!(value);
                        }
                    }
                    if let Some(value) = parameters.get("TeamMembers") {
                        team["TeamMembers"] = serde_json::from_str(value).unwrap();
                    }
                    cloud.teams.insert(name.into(), team);
                } else if action == "UpdateTeam" {
                    let leave = cloud.leave_old_description;
                    let Some(team) = cloud.teams.get_mut(name) else {
                        return absent();
                    };
                    if !leave {
                        if let Some(value) = parameters.get("Description") {
                            team["Description"] = json!(value);
                        }
                    }
                    if let Some(value) = parameters.get("TeamMembers") {
                        team["TeamMembers"] = serde_json::from_str(value).unwrap();
                    }
                } else if let Some(team) = cloud.teams.get_mut(name) {
                    team["Status"] = json!("Deleting");
                }
                let _ = self.written.send(());
                if cloud.write_unknown {
                    return failed(Failure::Unknown);
                }
                let response = success(json!({"Success":true,"Code":"SUCCESS","RequestId":"loopback-write"}));
                if cloud.write_delay { response.set_delay(std::time::Duration::from_millis(600)) } else { response }
            }
            _ => panic!("Unexpected Team loopback action {action}"),
        };
        if cloud.read_delay.as_deref() == Some(action) {
            response.set_delay(std::time::Duration::from_millis(700))
        } else {
            response
        }
    }
}
pub struct FixtureRpc {
    pub f: Fixture,
    pub server: MockServer,
    pub cloud: Arc<Mutex<Cloud>>,
    pub written: tokio::sync::mpsc::UnboundedReceiver<()>,
    pub observed: tokio::sync::mpsc::UnboundedReceiver<String>,
}
impl FixtureRpc {
    pub async fn new() -> Self {
        Self::with_settings(json!({})).await
    }
    pub async fn with_settings(extra: Value) -> Self {
        let server = MockServer::start().await;
        let cloud = Arc::new(Mutex::new(Cloud::seeded()));
        let (written, sent) = tokio::sync::mpsc::unbounded_channel();
        let (observed, received) = tokio::sync::mpsc::unbounded_channel();
        Mock::given(any()).respond_with(Rpc { cloud: cloud.clone(), written, observed }).mount(&server).await;
        let mut h = setup().await;
        Arc::make_mut(&mut h.state.config).mock_mode = false;
        h.app = build_router(h.state.clone());
        let mut settings = json!({"instance_id":INSTANCE,"account_id":"team-test-account","endpoint":server.uri()});
        settings.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        let saved = h
            .request(
                "PUT",
                CLOUD,
                Some(&h.admin),
                Some(json!({"expected_version":0,"enabled":true,"mock":false,
            "settings":settings,"secrets":{"access_key_id":"LOOPBACK-ID","access_key_secret":"LOOPBACK-SECRET"}})),
            )
            .await;
        assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
        let f = Fixture { h, mocked: false };
        result(f.sync().await);
        Self { f, server, cloud, written: sent, observed: received }
    }
    pub fn restart_runtime(&mut self) {
        self.f.h.state.cloud_runtime = Arc::new(agf_api::cloud_runtime::Registry::default());
        self.f.h.app = build_router(self.f.h.state.clone());
    }
    pub async fn wait_action(&mut self, wanted: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while self.observed.recv().await.as_deref() != Some(wanted) {}
        })
        .await
        .unwrap();
    }
    pub fn write_count(&self, action: &str) -> usize {
        self.cloud.lock().unwrap().writes.iter().filter(|(name, _)| name == action).count()
    }
    pub async fn actions(&self) -> Vec<String> {
        self.server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|request| request.headers.get("x-acs-action").unwrap().to_str().unwrap().to_owned())
            .collect()
    }
    pub fn complete_delete(&self, name: &str) {
        let mut cloud = self.cloud.lock().unwrap();
        cloud.teams.remove(name);
        for worker in &mut cloud.workers {
            worker["Groups"].as_array_mut().unwrap().retain(|group| group["Type"] != "team" || group["Name"] != name);
        }
    }
}
