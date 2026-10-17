//! Loopback directory observations shared by inventory and audit relationship tests.
#![allow(dead_code, unused_imports, unreachable_pub)]
use crate::common::*;
use agf_core::{
    enums::{DataClass, LifecycleState},
    ids::Id,
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, query_param},
};

pub const CONFIG: &str = "/api/v1/alicloud/connections/alicloud-agentteams";
pub const SYNC: &str = "/api/v1/alicloud/agentteams/sync";
pub const TEAMS: &str = "/api/v1/alicloud/agentteams";
pub const SOURCES: &str = "/api/v1/alicloud/agentteams/audit-sources";
pub const INSTANCE: &str = "instance-relations";
pub const TEAM: &str = "team-local";
pub const WORKER: &str = "worker-local";

#[derive(Clone)]
pub struct Directory {
    pub teams: Vec<Value>,
    pub team_details: Vec<Value>,
    pub workers: Vec<Value>,
    pub worker_details: Vec<Value>,
    pub tasks: Vec<Value>,
}
impl Directory {
    pub fn valid() -> Self {
        let team = json!({"InstanceId":INSTANCE,"Name":TEAM,"Description":"Original team",
            "WorkerNames":[WORKER],"TeamMembers":[{"Name":"human-local"}],"Status":"Running"});
        let worker = json!({"InstanceId":INSTANCE,"Name":WORKER,"Status":"Running","VersionCode":"baseline",
            "Groups":[{"Type":"team","Name":TEAM,"Role":"member"}],"Model":{"ModelName":"local-model"}});
        let mut detail = team.clone();
        detail["UpdatedAt"] = json!("2026-09-01T00:00:00Z");
        Self {
            teams: vec![team],
            team_details: vec![detail],
            workers: vec![worker.clone()],
            worker_details: vec![worker],
            tasks: vec![],
        }
    }
    pub fn team_field(&mut self, field: &str, value: Option<Value>) {
        for row in [&mut self.teams[0], &mut self.team_details[0]] {
            match &value {
                Some(value) => {
                    row[field] = value.clone();
                }
                None => {
                    row.as_object_mut().unwrap().remove(field);
                }
            }
        }
    }
    pub fn worker_field(&mut self, field: &str, value: Option<Value>) {
        for row in [&mut self.workers[0], &mut self.worker_details[0]] {
            match &value {
                Some(value) => {
                    row[field] = value.clone();
                }
                None => {
                    row.as_object_mut().unwrap().remove(field);
                }
            }
        }
    }
    pub fn add_worker(&mut self, name: &str, groups: Option<Value>) {
        let mut worker = json!({"InstanceId":INSTANCE,"Name":name,"Status":"Running"});
        if let Some(groups) = groups {
            worker["Groups"] = groups;
        }
        self.workers.push(worker.clone());
        self.worker_details.push(worker);
    }
    pub fn add_team(&mut self, name: &str, workers: Value) {
        let team = json!({"InstanceId":INSTANCE,"Name":name,"WorkerNames":workers,"TeamMembers":[]});
        self.teams.push(team.clone());
        self.team_details.push(team);
    }
    pub async fn mount(&self, server: &MockServer) {
        for (action, rows) in [("ListTeams", &self.teams), ("ListWorkers", &self.workers)] {
            response(server, action, json!({"Items":rows,"TotalCount":rows.len(),"NextToken":""})).await;
        }
        for (action, rows) in [("GetTeam", &self.team_details), ("GetWorker", &self.worker_details)] {
            for (index, row) in rows.iter().enumerate() {
                // Match the requested identity even in a deliberately mismatched response.
                let names = if action == "GetTeam" { &self.teams } else { &self.workers };
                Mock::given(header("x-acs-action", action))
                    .and(query_param("Name", names[index]["Name"].as_str().unwrap()))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Data":row})))
                    .mount(server)
                    .await;
            }
        }
        response(server, "ListTeamTasks", json!({"Items":self.tasks,"TotalCount":self.tasks.len(),"NextToken":""}))
            .await;
    }
}
pub async fn response(server: &MockServer, action: &str, body: Value) {
    Mock::given(header("x-acs-action", action))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

pub struct Fixture {
    pub h: Harness,
    pub server: MockServer,
}
impl Fixture {
    pub async fn new() -> Self {
        let mut h = setup().await;
        Arc::make_mut(&mut h.state.config).mock_mode = false;
        h.app = build_router(h.state.clone());
        let server = MockServer::start().await;
        let cloud = h
            .request(
                "PUT",
                CONFIG,
                Some(&h.admin),
                Some(json!({"expected_version":0,"enabled":true,"mock":false,
            "settings":{"endpoint":server.uri(),"instance_id":INSTANCE},
            "secrets":{"access_key_id":"LOOPBACK-ID","access_key_secret":"LOOPBACK-SECRET"}})),
            )
            .await;
        assert_eq!(cloud.status, StatusCode::OK, "{}", cloud.text);
        Self { h, server }
    }
    pub async fn install(&self, directory: &Directory) {
        self.server.reset().await;
        directory.mount(&self.server).await;
    }
    pub async fn sync(&self) -> Resp {
        self.h.post(SYNC, json!({"request_id":Id::new(),"configuration_version":1,"confirm_live":true})).await
    }
    pub async fn succeed(&self, directory: &Directory) -> Value {
        self.install(directory).await;
        let synced = self.sync().await;
        assert_eq!(synced.status, StatusCode::OK, "{}", synced.text);
        let result = self.h.get(TEAMS).await;
        assert_eq!(result.status, StatusCode::OK, "{}", result.text);
        result.json()
    }
    pub async fn governed_baseline(&self) -> Value {
        self.succeed(&Directory::valid()).await;
        let snapshot = agf_api::cloud_inventory::load(&self.h.state, self.h.tenant).await.unwrap().unwrap();
        let mut asset = self.h.state.store.asset_get(self.h.tenant, snapshot.assets[WORKER]).unwrap().unwrap();
        asset.owner = Some("manual-owner".into());
        asset.data_class = DataClass::Confidential;
        asset.lifecycle = LifecycleState::Production;
        asset.attributes.insert("manual-note".into(), json!("keep me"));
        self.h.state.store.asset_upsert(&asset).unwrap();
        self.capture().await
    }
    pub async fn capture(&self) -> Value {
        let snapshot = agf_api::cloud_inventory::load(&self.h.state, self.h.tenant).await.unwrap().unwrap();
        let teams = self.h.get(TEAMS).await;
        assert_eq!(teams.status, StatusCode::OK, "{}", teams.text);
        let mut teams = teams.json();
        for team in teams.as_array_mut().unwrap() {
            let fields = team.as_object_mut().unwrap();
            fields.remove("windowFrom");
            fields.remove("windowTo");
        }
        json!({"snapshot":snapshot,"assets":self.h.state.store.asset_list_all(self.h.tenant).unwrap(),"teams":teams})
    }
    pub async fn reject(&self, directory: &Directory, before: &Value, label: &str) -> Resp {
        self.install(directory).await;
        let rejected = self.sync().await;
        assert!(
            matches!(rejected.status, StatusCode::BAD_REQUEST | StatusCode::CONFLICT | StatusCode::PRECONDITION_FAILED),
            "{label} must reject a relationship observation: {} {}",
            rejected.status,
            rejected.text
        );
        assert!(rejected.content_type().starts_with("application/problem+json"), "{}", rejected.text);
        assert_eq!(self.capture().await, *before, "{label}: full snapshot and manual governance must survive");
        rejected
    }
}
pub fn row<'a>(teams: &'a Value, name: &str) -> &'a Value {
    teams.as_array().unwrap().iter().find(|row| row["name"] == name).unwrap()
}
pub async fn store_snapshot(h: &Harness, snapshot: &agf_api::cloud_inventory::Snapshot) {
    let cfg = agf_api::cloud_store::load(&h.state, h.tenant, agf_api::cloud_inventory::NAME).await.unwrap().unwrap();
    let mut private = agf_api::integration_store::Private::default();
    private.settings.insert("snapshot".into(), serde_json::to_value(snapshot).unwrap());
    let saved = agf_api::integration_store::Stored {
        private: agf_api::model_gateway::encrypt(&h.state, h.tenant, cfg.id, serde_json::to_string(&private).unwrap())
            .unwrap(),
        updated_at: snapshot.checked_at,
        ..cfg
    };
    h.state.configurations.put(h.tenant, "cloud-inventory", saved.id, &saved).await.unwrap();
}
