//! Every count is an actual signed HTTP request to this task's ephemeral literal-loopback server.
use super::{
    signature,
    wire::{self, Gate, Release, Reply, Server},
    *,
};
use std::sync::Mutex;
use tokio::{
    task::JoinHandle,
    time::{Duration, timeout},
};
pub(super) const ACCESS_KEY: &str = "agf-owned-scheduler-key-no-cloud";
pub(super) const SECRET: &str = "agf-owned-scheduler-signing-secret-no-cloud";
struct State {
    reads: usize,
    total: usize,
    large: bool,
    hold: Option<(String, usize, Arc<Gate>)>,
}
pub(crate) struct Engine {
    pub(crate) server: Server,
    state: Arc<Mutex<State>>,
}
impl Engine {
    pub(crate) async fn new(total: usize, large: bool) -> DomainResult<Self> {
        assert!(total <= 2000);
        let state = Arc::new(Mutex::new(State { reads: 0, total, large, hold: None }));
        let provider = state.clone();
        let server = Server::start(move |request| {
            let host = request.headers.get("host").ok_or_else(|| wire::fixture_error("host absent"))?;
            signature::verify_signature(request, &format!("http://{host}"))?;
            let input = signature::query(request)?;
            if input.get("ClusterId").map(String::as_str) != Some("cluster-agf-demo")
                || input.get("AppName").map(String::as_str) != Some("app-agf-demo")
            {
                return Err(wire::fixture_error("foreign RPC identity"));
            }
            let action = request.headers.get("x-acs-action").ok_or_else(|| wire::fixture_error("action absent"))?;
            let mut state = provider.lock().map_err(|_| wire::fixture_error("provider mutex poisoned"))?;
            state.reads += 1;
            let body = response(&state, action, &input)?;
            let reply = Reply::json(&body);
            Ok(match &state.hold {
                Some((held, nth, gate)) if held == action && *nth == state.reads => reply.held(gate),
                _ => reply,
            })
        })
        .await?;
        Ok(Self { server, state })
    }
    pub(crate) fn hold(&self, action: &str, nth: usize) -> DomainResult<(Arc<Gate>, Release)> {
        let gate = Arc::new(Gate::default());
        self.state.lock().map_err(|_| wire::fixture_error("provider mutex poisoned"))?.hold =
            Some((action.into(), nth, gate.clone()));
        let release = gate.release_on_drop();
        Ok((gate, release))
    }
    pub(crate) async fn count(&self, expected: usize) -> DomainResult<()> {
        self.server.settled(expected).await?;
        assert_eq!(self.server.requests()?.len(), expected);
        Ok(())
    }
    pub(crate) fn received(&self) -> DomainResult<usize> {
        Ok(self.server.requests()?.len())
    }
}
fn response(state: &State, action: &str, input: &BTreeMap<String, String>) -> DomainResult<Value> {
    let required: &[&str] = match action {
        "GetApp" => &["AppName", "ClusterId"],
        "ListJobs" => &["AppName", "ClusterId", "PageNum", "PageSize"],
        _ => return Err(wire::fixture_error("unexpected RPC action")),
    };
    if input.len() != required.len() || required.iter().any(|key| !input.contains_key(*key)) {
        return Err(wire::fixture_error("unexpected RPC business fields"));
    }
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../agf-alicloud/src/schedulerx3/native_observation/owned_fixture.json"
    ))?;
    if action == "GetApp" {
        return Ok(fixture["GetApp"].clone());
    }
    if input.get("PageSize").map(String::as_str) != Some("100") {
        return Err(wire::fixture_error("page size differs"));
    }
    let page = input
        .get("PageNum")
        .and_then(|p| p.parse::<usize>().ok())
        .filter(|p| *p > 0 && *p <= state.total.div_ceil(100).max(1))
        .ok_or_else(|| wire::fixture_error("page number differs"))?;
    let start = (page - 1) * 100;
    let count = state.total.saturating_sub(start).min(100);
    let records = (start + 1..=start + count)
        .map(|index| {
            let mut job = fixture["ListJobs"]["Data"]["Records"][0].clone();
            job["JobId"] = json!((9_007_199_254_741_000_i64 + index as i64).to_string());
            job["Name"] = json!(if state.large { "x".repeat(260) } else { format!("owned-scheduler-job-{index}") });
            job["Status"] = json!(1);
            job
        })
        .collect::<Vec<_>>();
    Ok(
        json!({"Code":200,"Success":true,"RequestId":format!("owned-page-{page}"),"Data":{"PageNumber":page,"PageSize":100,"Total":state.total,"Records":records}}),
    )
}
pub(crate) fn attach(mut h: Harness, engine: &Engine) -> DomainResult<Harness> {
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    let address = engine
        .server
        .origin
        .trim_start_matches("http://")
        .parse()
        .map_err(|_| wire::fixture_error("literal socket invalid"))?;
    h.state.scheduler_native_observation =
        Arc::new(agf_api::scheduler_native_observation::Registry::literal_loopback_for_test(h.tenant, address)?);
    let tenant = h.tenant;
    for_tenant(h, tenant)
}
pub(crate) async fn configure(h: &Harness, engine: &Engine, version: u64, enabled: bool) -> DomainResult<()> {
    let mut configured = settings();
    configured["endpoint"] = json!(engine.server.origin);
    let reply = h
        .request(
            "PUT",
            CONFIG,
            Some(&h.admin),
            Some(json!({"expected_version":version,"enabled":enabled,"mock":false,"settings":configured,
        "secrets":{"access_key_id":ACCESS_KEY,"access_key_secret":SECRET}})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "owned live configuration status");
    assert_eq!(reply.json()["version"], version + 1);
    Ok(())
}
pub(crate) struct Pending(JoinHandle<Resp>);
impl Pending {
    pub(crate) fn start(h: &Harness, method: &str, path: String, token: String, input: Option<Value>) -> Self {
        let h = h.clone();
        let method = method.to_owned();
        Self(tokio::spawn(async move { h.request(&method, &path, Some(&token), input).await }))
    }
    pub(crate) async fn finish(&mut self) -> DomainResult<Resp> {
        self.finish_within(Duration::from_secs(15)).await
    }
    pub(crate) async fn finish_within(&mut self, budget: Duration) -> DomainResult<Resp> {
        timeout(budget, &mut self.0)
            .await
            .map_err(|_| wire::fixture_error("API task timeout"))?
            .map_err(|_| wire::fixture_error("API task failed"))
    }
    pub(crate) async fn cancel(&mut self) -> DomainResult<()> {
        self.0.abort();
        match (&mut self.0).await {
            Err(error) if error.is_cancelled() => Ok(()),
            _ => Err(wire::fixture_error("API task was not cancelled")),
        }
    }
    pub(crate) fn is_finished(&self) -> bool {
        self.0.is_finished()
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub(crate) fn start(h: &Harness, id: Id, token: String) -> Pending {
    Pending::start(h, "POST", format!("{BASE}/observe"), token, Some(observe(id, false)))
}
