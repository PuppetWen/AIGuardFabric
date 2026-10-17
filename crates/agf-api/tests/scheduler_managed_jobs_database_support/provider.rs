//! Explicit synthetic signed HTTP fixture; mutates a disabled existing HTTP Job once.
use super::{
    signature,
    wire::{self, Reply, Server},
};
use crate::{
    common::*,
    scheduler_managed_jobs_support::{CONFIG, NATIVE},
};
use agf_core::{error::DomainResult, ids::Id};
use std::sync::Mutex;
pub(super) const ACCESS_KEY: &str = "agf-owned-scheduler-key-no-cloud";
pub(super) const SECRET: &str = "agf-owned-scheduler-signing-secret-no-cloud";
pub(crate) const JOB: &str = "9007199254741001";
struct State {
    fixture: Value,
    reads: usize,
    writes: usize,
    lose_response: bool,
}
pub(crate) struct Engine {
    server: Server,
    state: Arc<Mutex<State>>,
}
impl Engine {
    pub(crate) async fn new(lose_response: bool) -> DomainResult<Self> {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../agf-alicloud/src/schedulerx3/native_observation/owned_fixture.json"
        ))?;
        let state = Arc::new(Mutex::new(State { fixture, reads: 0, writes: 0, lose_response }));
        let shared = state.clone();
        let server = Server::start(move |request| {
            let host = request.headers.get("host").ok_or_else(|| wire::fixture_error("host absent"))?;
            signature::verify_signature(request, &format!("http://{host}"))?;
            let action = request.headers.get("x-acs-action").ok_or_else(|| wire::fixture_error("action absent"))?;
            let input = if request.method == "GET" { signature::query(request)? } else { signature::form(request)? };
            if input.get("ClusterId").map(String::as_str) != Some("cluster-agf-demo")
                || input.get("AppName").map(String::as_str) != Some("app-agf-demo")
            {
                return Err(wire::fixture_error("foreign identity"));
            }
            let mut state = shared.lock().map_err(|_| wire::fixture_error("state mutex failed"))?;
            match action.as_str() {
                "GetApp" if request.method == "GET" && input.len() == 2 => {
                    state.reads += 1;
                    Ok(Reply::json(&state.fixture["GetApp"]))
                }
                "ListJobs"
                    if request.method == "GET"
                        && input.len() == 4
                        && input.get("PageNum").map(String::as_str) == Some("1")
                        && input.get("PageSize").map(String::as_str) == Some("100") =>
                {
                    state.reads += 1;
                    Ok(Reply::json(&state.fixture["ListJobs"]))
                }
                "UpdateJob"
                    if request.method == "POST"
                        && input.len() == 4
                        && input.get("JobId").map(String::as_str) == Some(JOB)
                        && input.get("TimeExpression").map(String::as_str) == Some("0 0/7 * * * ?") =>
                {
                    assert_eq!(state.fixture["ListJobs"]["Data"]["Records"][0]["Status"], 0);
                    state.writes += 1;
                    state.fixture["ListJobs"]["Data"]["Records"][0]["TimeExpression"] = json!("0 0/7 * * * ?");
                    if state.lose_response {
                        Ok(Reply::disconnected())
                    } else {
                        Ok(Reply::json(&json!({"Code":200,"Success":true,"RequestId":"owned-one-update-ack"})))
                    }
                }
                _ => Err(wire::fixture_error("unexpected action, method or business fields")),
            }
        })
        .await?;
        Ok(Self { server, state })
    }
    pub(crate) fn writes(&self) -> DomainResult<usize> {
        Ok(self.state.lock().map_err(|_| super::error())?.writes)
    }
    pub(crate) fn reads(&self) -> DomainResult<usize> {
        Ok(self.state.lock().map_err(|_| super::error())?.reads)
    }
    pub(crate) async fn verify(&self) -> DomainResult<()> {
        self.server.settled(self.reads()? + self.writes()?).await?;
        Ok(())
    }
}
pub(crate) fn attach(mut h: Harness, engine: &Engine) -> DomainResult<Harness> {
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    let address = engine.server.origin.trim_start_matches("http://").parse().map_err(|_| super::error())?;
    h.state.scheduler_native_observation =
        Arc::new(agf_api::scheduler_native_observation::Registry::literal_loopback_for_test(h.tenant, address)?);
    h.app = build_router(h.state.clone());
    Ok(h)
}
pub(crate) async fn configure(h: &Harness, engine: &Engine, version: u64, enabled: bool) -> DomainResult<()> {
    let saved = h
        .request(
            "PUT",
            CONFIG,
            Some(&h.admin),
            Some(json!({"expected_version":version,"enabled":enabled,"mock":false,
        "settings":{"region_id":"cn-hangzhou","cluster_id":"cluster-agf-demo","app_name":"app-agf-demo",
            "account_id":"owned-managed-scheduler-account","endpoint":engine.server.origin},
        "secrets":{"access_key_id":ACCESS_KEY,"access_key_secret":SECRET}})),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "owned source status");
    assert_eq!(saved.json()["version"], version + 1);
    Ok(())
}
pub(crate) async fn observe(h: &Harness) -> DomainResult<Value> {
    let reply = h
        .post(
            &format!("{NATIVE}/observe"),
            json!({"request_id":Id::new(),"configuration_version":1,
        "initialize_mock_fixture":false,"confirm_live":false}),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "owned loopback observation status");
    Ok(reply.json())
}
