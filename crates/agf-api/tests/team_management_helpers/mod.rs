//! HTTP-only clients for native Team management; no private production hooks.
#![allow(dead_code, unused_imports, unreachable_pub)]
use crate::common::*;
use agf_core::ids::Id;

pub const BASE: &str = "/api/v1/alicloud/agentteams/team-management";
pub const CLOUD: &str = "/api/v1/alicloud/connections/alicloud-agentteams";
pub const SYNC: &str = "/api/v1/alicloud/agentteams/sync";
pub const TEAM: &str = "my-team";
pub const INSTANCE: &str = "instance-team-tests";
pub const STATE_KIND: &str = "agentteams-team-state";
pub const RUN_KIND: &str = "agentteams-team-operation";
pub const PREVIEW_KIND: &str = "agentteams-team-preview";

pub struct Fixture {
    pub h: Harness,
    pub mocked: bool,
}
impl Fixture {
    pub async fn mock() -> Self {
        let mut h = setup().await;
        Arc::make_mut(&mut h.state.config).mock_mode = false;
        h.app = build_router(h.state.clone());
        Self::configured(h, true, None).await
    }
    pub async fn configured(h: Harness, mocked: bool, endpoint: Option<&str>) -> Self {
        let mut body = json!({"expected_version":0,"enabled":true,"mock":mocked,
            "settings":{"instance_id":INSTANCE,"account_id":"team-test-account"}});
        if let Some(endpoint) = endpoint {
            body["settings"]["endpoint"] = json!(endpoint);
            body["secrets"] = json!({"access_key_id":"LOOPBACK-ID","access_key_secret":"LOOPBACK-SECRET"});
        }
        let configured = h.request("PUT", CLOUD, Some(&h.admin), Some(body)).await;
        assert_eq!(configured.status, StatusCode::OK, "{}", configured.text);
        let f = Self { h, mocked };
        let synced = f.sync().await;
        assert_eq!(synced.status, StatusCode::OK, "{}", synced.text);
        f
    }
    pub async fn sync(&self) -> Resp {
        self.h.post(SYNC, json!({"request_id":Id::new(),"configuration_version":1,"confirm_live":!self.mocked})).await
    }
    pub async fn list(&self) -> Value {
        result(self.h.get(BASE).await)
    }
    pub async fn version(&self, name: &str) -> u64 {
        self.list().await["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|team| team["teamName"] == name)
            .map_or(0, |team| team["stateVersion"].as_u64().unwrap())
    }
    pub async fn users(&self, extra: Value) -> Resp {
        let mut body = json!({"request_id":Id::new(),"configuration_version":1,"confirm_live":!self.mocked});
        body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        self.h.post(&format!("{BASE}/users/observe"), body).await
    }
    pub async fn preview(&self, change: Value) -> Resp {
        let version = self.version(change["team_name"].as_str().unwrap()).await;
        let members = change["member_names"].as_array().is_some_and(|names| !names.is_empty())
            || change["members"]["names"].as_array().is_some_and(|names| !names.is_empty())
            || change["admin_name"].as_str().is_some();
        let mut body = preview_body(change, version, !self.mocked);
        if members {
            let directory = result(self.users(json!({})).await);
            body["user_snapshot_id"] = directory["snapshotId"].clone();
        }
        self.h.post(&format!("{BASE}/previews"), body).await
    }
    pub async fn apply(&self, preview: &Value, request: Id) -> Resp {
        self.h.post(&format!("{BASE}/operations"), apply_body(preview, request, !self.mocked)).await
    }
    pub async fn recover(&self, operation: &Value, phase: &str) -> Resp {
        self.h
            .post(
                &format!("{BASE}/operations/{}/{phase}", operation["id"].as_str().unwrap()),
                json!({"request_id":Id::new(),"configuration_version":1,"confirm_live":!self.mocked}),
            )
            .await
    }
    pub async fn cloud_team(&self, name: &str) -> Value {
        let response = self
            .h
            .post(
                &format!("{CLOUD}/operations"),
                json!({"request_id":Id::new(),
            "configuration_version":1,"confirm_live":!self.mocked,"action":"GetTeam","parameters":{"Name":name}}),
            )
            .await;
        let operation = result(response);
        assert_eq!(operation["status"], "succeeded", "{operation}");
        operation["receipt"]["response"]["Data"].clone()
    }
    pub async fn writes(&self, action: &str) -> usize {
        agf_api::integration_receipts::history(&self.h.state, self.h.tenant, "alicloud-agentteams")
            .await
            .unwrap()
            .iter()
            .filter(|row| row["operation"] == action)
            .count()
    }
}

pub fn result(response: Resp) -> Value {
    assert!(response.status.is_success(), "{} {}", response.status, response.text);
    response.json()
}
pub fn preview_body(change: Value, version: u64, live: bool) -> Value {
    json!({"request_id":Id::new(),"configuration_version":1,"expected_state_version":version,
        "confirm_live":live,"change":change})
}
pub fn apply_body(preview: &Value, request: Id, live: bool) -> Value {
    json!({"request_id":request,"preview_id":preview["id"],"configuration_version":preview["configurationVersion"],
        "expected_state_version":preview["expectedStateVersion"],"confirm_live":live,"confirm_apply":true})
}
pub fn create(name: &str, members: Value) -> Value {
    json!({"action":"create","team_name":name,"description":"Managed team","member_names":members})
}
pub fn update(name: &str, description: &str) -> Value {
    json!({"action":"update","team_name":name,"description":description})
}
pub fn replace(name: &str, members: Value) -> Value {
    json!({"action":"update","team_name":name,"members":{"mode":"replace","names":members,
        "confirm_full_replacement":true}})
}
pub fn delete(name: &str) -> Value {
    json!({"action":"delete","team_name":name,"confirm_team_name":name,"confirm_async_cleanup":true})
}
pub fn verified(operation: &Value) {
    assert_eq!(operation["status"], "verified", "{operation}");
    assert_eq!(operation["cloudWrite"]["status"], "accepted", "{operation}");
    assert_eq!(operation["inventoryPublish"]["status"], "published", "{operation}");
    assert!(!operation["allowedActions"].as_array().unwrap().contains(&json!("retry_write")));
}
pub async fn scoped(h: &Harness, tenant: TenantId, method: &str, uri: &str, body: Option<Value>) -> Resp {
    let bearer = format!("Bearer {}", h.admin);
    let tenant = tenant.to_string();
    h.request_with(method, uri, &[("authorization", &bearer), ("x-agf-tenant", &tenant)], body).await
}
pub async fn snapshot(h: &Harness) -> Value {
    serde_json::to_value(agf_api::cloud_inventory::load(&h.state, h.tenant).await.unwrap()).unwrap()
}
