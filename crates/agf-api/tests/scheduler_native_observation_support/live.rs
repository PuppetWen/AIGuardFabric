//! Literal-loopback HTTP traverses the real source, auth, shared runtime entry and ACS3 signer.
use super::{
    signature,
    wire::{self, Gate, Release, Reply, Server},
    *,
};
use agf_core::error::{DomainError, DomainResult};
use std::sync::Mutex;
use tokio::{
    task::JoinHandle,
    time::{Duration, timeout},
};

pub(super) const ACCESS_KEY: &str = "agf-owned-scheduler-key-no-cloud";
pub(super) const SECRET: &str = "agf-owned-scheduler-signing-secret-no-cloud";
#[derive(Clone, Copy)]
enum Profile {
    Complete,
    Empty,
    MissingTotal,
    Duplicate,
    Error,
}
struct Provider {
    profile: Profile,
    reads: usize,
    hold: Option<(String, usize, Arc<Gate>)>,
}
struct Engine {
    server: Server,
    state: Arc<Mutex<Provider>>,
}
impl Engine {
    async fn new(profile: Profile) -> DomainResult<Self> {
        let state = Arc::new(Mutex::new(Provider { profile, reads: 0, hold: None }));
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
            let mut provider = provider.lock().map_err(|_| wire::fixture_error("provider mutex poisoned"))?;
            provider.reads += 1;
            let body = response(provider.profile, action, &input)?;
            let reply = Reply::json(&body);
            Ok(match &provider.hold {
                Some((held, nth, gate)) if held == action && *nth == provider.reads => reply.held(gate),
                _ => reply,
            })
        })
        .await?;
        Ok(Self { server, state })
    }
    fn hold(&self, action: &str, nth: usize) -> DomainResult<(Arc<Gate>, Release)> {
        let gate = Arc::new(Gate::default());
        self.state.lock().map_err(|_| wire::fixture_error("provider mutex poisoned"))?.hold =
            Some((action.into(), nth, gate.clone()));
        let release = gate.release_on_drop();
        Ok((gate, release))
    }
    async fn count(&self, expected: usize) -> DomainResult<()> {
        self.server.settled(expected).await?;
        assert_eq!(self.server.requests()?.len(), expected);
        Ok(())
    }
}
fn response(profile: Profile, action: &str, input: &BTreeMap<String, String>) -> DomainResult<Value> {
    let required: &[&str] = if action == "GetApp" {
        &["AppName", "ClusterId"]
    } else if action == "ListJobs" {
        &["AppName", "ClusterId", "PageNum", "PageSize"]
    } else {
        return Err(wire::fixture_error("unexpected RPC action"));
    };
    if input.len() != required.len() || required.iter().any(|field| !input.contains_key(*field)) {
        return Err(wire::fixture_error("unexpected RPC business fields"));
    }
    if matches!(profile, Profile::Error) {
        return Ok(json!({"Code":500,"Success":false,"RequestId":"owned-failed",
            "Message":"owned-provider-secret-diagnostic"}));
    }
    let mut fixture: Value = serde_json::from_str(include_str!(
        "../../../agf-alicloud/src/schedulerx3/native_observation/owned_fixture.json"
    ))?;
    if action == "GetApp" {
        return Ok(fixture["GetApp"].take());
    }
    if input.get("PageSize").map(String::as_str) != Some("100") {
        return Err(wire::fixture_error("wrong page size"));
    }
    let (page, start, count) = match input.get("PageNum").map(String::as_str) {
        Some("1") => (1, 1, if matches!(profile, Profile::Empty) { 0 } else { 100 }),
        Some("2") => (2, 101, 1),
        _ => return Err(wire::fixture_error("wrong page number")),
    };
    let records: Vec<_> = (start..start + count)
        .map(|index| {
            let mut job = fixture["ListJobs"]["Data"]["Records"][0].clone();
            let index = if matches!(profile, Profile::Duplicate) && page == 2 { 1 } else { index };
            job["JobId"] = json!(format!("{}", 9_007_199_254_741_000_i64 + index));
            job["Name"] = json!(format!("owned-loopback-job-{index}"));
            job["Status"] = json!(1);
            job
        })
        .collect();
    let mut body = json!({"Code":200,"Success":true,"RequestId":format!("owned-page-{page}"),
        "Data":{"PageNumber":page,"PageSize":100,"Total":if matches!(profile,Profile::Empty){0}else{101},
            "Records":records}});
    if matches!(profile, Profile::MissingTotal) {
        body["Data"].as_object_mut().ok_or_else(|| wire::fixture_error("page data absent"))?.remove("Total");
    }
    Ok(body)
}
async fn fixture(engine: &Engine) -> DomainResult<Harness> {
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    let address = engine
        .server
        .origin
        .trim_start_matches("http://")
        .parse()
        .map_err(|_| wire::fixture_error("invalid owned socket address"))?;
    h.state.scheduler_native_observation =
        Arc::new(agf_api::scheduler_native_observation::Registry::literal_loopback_for_test(h.tenant, address)?);
    h.app = build_router(h.state.clone());
    configure_live(&h, engine, 0, true).await?;
    Ok(h)
}
async fn configure_live(h: &Harness, engine: &Engine, version: u64, enabled: bool) -> DomainResult<()> {
    let mut configured = settings();
    configured["endpoint"] = json!(engine.server.origin);
    let reply = h
        .request(
            "PUT",
            CONFIG,
            Some(&h.admin),
            Some(json!({"expected_version":version,
        "enabled":enabled,"mock":false,"settings":configured,
        "secrets":{"access_key_id":ACCESS_KEY,"access_key_secret":SECRET}})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "owned live source status");
    assert_eq!(reply.json()["version"], version + 1);
    Ok(())
}
struct Pending(JoinHandle<Resp>);
impl Pending {
    async fn finish(&mut self) -> DomainResult<Resp> {
        timeout(Duration::from_secs(8), &mut self.0)
            .await
            .map_err(|_| wire::fixture_error("API request did not terminate"))?
            .map_err(|_| wire::fixture_error("API request task failed"))
    }
    async fn cancel(&mut self) -> DomainResult<()> {
        self.0.abort();
        match (&mut self.0).await {
            Err(error) if error.is_cancelled() => Ok(()),
            _ => Err(wire::fixture_error("API request was not cancelled")),
        }
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn spawn(h: &Harness, path: String, token: String, input: Value) -> Pending {
    let h = h.clone();
    Pending(tokio::spawn(async move { h.request("POST", &path, Some(&token), Some(input)).await }))
}
async fn claimed(h: &Harness, id: Id) -> DomainResult<()> {
    timeout(Duration::from_secs(5), async {
        loop {
            if records(h, "scheduler-native-fact")
                .await?
                .iter()
                .any(|row| row["request_id"] == json!(id) && row["status"] == "reading")
            {
                return Ok::<_, DomainError>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| wire::fixture_error("native request did not reach its permanent claim"))?
}

#[tokio::test]
async fn unchanged_live_source_passes_canonical_guard_and_actual_v3_paging_without_generic_getapp_leak()
-> DomainResult<()> {
    let engine = Engine::new(Profile::Complete).await?;
    let h = fixture(&engine).await?;
    let before = snapshot(&h).await?;
    let view = read(&h, BASE).await?;
    assert_eq!(view["sourceTarget"]["transportMode"], "loopback_test");
    assert_eq!(view["sourceTarget"]["mocked"], false);
    assert_eq!(snapshot(&h).await?, before);
    engine.count(0).await?;
    let id = Id::new();
    let input = observe_input(id, 1, false);
    let observed = post(&h, &format!("{BASE}/observe"), input.clone()).await?;
    assert_eq!(observed["status"], "observed");
    assert_eq!(observed["total"], 101);
    assert_eq!(observed["observation"]["jobs"].as_array().map(Vec::len), Some(100));
    assert_eq!(observed["observation"]["pagination"]["pages"].as_array().map(Vec::len), Some(2));
    assert_safe(&observed);
    assert_read_audit(&h, id, AuditOutcome::Success).await?;
    engine.count(3).await?;
    let before = snapshot(&h).await?;
    let second = read(&h, &format!("{}?page=2", receipt(id))).await?;
    assert_eq!(second["observation"]["jobs"].as_array().map(Vec::len), Some(1));
    assert_eq!(post(&h, &format!("{BASE}/observe"), input).await?, observed);
    let blocked = h
        .post(
            &format!("{CONFIG}/operations"),
            json!({"request_id":Id::new(),
        "configuration_version":1,"confirm_live":true,"action":"GetApp","parameters":{}}),
        )
        .await;
    assert_eq!(blocked.status, StatusCode::PRECONDITION_FAILED);
    assert_safe(&blocked.json());
    assert_eq!(snapshot(&h).await?, before);
    assert!(agf_api::integration_receipts::history(&h.state, h.tenant, NAME).await?.is_empty());
    engine.count(3).await?;
    Ok(())
}

#[tokio::test]
async fn incomplete_or_duplicate_real_pages_publish_no_snapshot_and_do_not_retry_uuid() -> DomainResult<()> {
    for (profile, count) in [(Profile::MissingTotal, 2), (Profile::Duplicate, 3)] {
        let engine = Engine::new(profile).await?;
        let h = fixture(&engine).await?;
        let id = Id::new();
        let input = observe_input(id, 1, false);
        let reply = h.post(&format!("{BASE}/observe"), input.clone()).await;
        assert!(!reply.status.is_success(), "invalid complete pagination must reject");
        assert_safe(&reply.json());
        assert!(records(&h, "scheduler-native-observation").await?.is_empty());
        assert!(read(&h, BASE).await?["latestObservation"].is_null());
        assert_read_audit(&h, id, AuditOutcome::Failure).await?;
        engine.count(count).await?;
        let failed = read(&h, &receipt(id)).await?;
        assert_eq!(failed["total"], Value::Null);
        assert_eq!(failed["listingComplete"], false);
        let before = snapshot(&h).await?;
        assert_eq!(post(&h, &format!("{BASE}/observe"), input).await?, failed);
        assert_eq!(snapshot(&h).await?, before);
        engine.count(count).await?;
    }
    Ok(())
}

#[tokio::test]
async fn actual_provider_error_is_sanitized_and_valid_empty_is_an_observed_zero() -> DomainResult<()> {
    let engine = Engine::new(Profile::Error).await?;
    let h = fixture(&engine).await?;
    let id = Id::new();
    let reply = h.post(&format!("{BASE}/observe"), observe_input(id, 1, false)).await;
    assert!(!reply.status.is_success());
    assert_safe(&reply.json());
    assert!(!reply.text.contains(SECRET));
    let failed = read(&h, &receipt(id)).await?;
    assert_eq!(failed["total"], Value::Null);
    assert_safe(&failed);
    assert_read_audit(&h, id, AuditOutcome::Failure).await?;
    engine.count(1).await?;
    let empty = Engine::new(Profile::Empty).await?;
    let h = fixture(&empty).await?;
    let value = post(&h, &format!("{BASE}/observe"), observe_input(Id::new(), 1, false)).await?;
    assert_eq!(value["status"], "observed");
    assert_eq!(value["total"], 0);
    assert_eq!(value["observation"]["jobs"], json!([]));
    assert_eq!(value["listingComplete"], true);
    assert_eq!(value["strongSnapshot"], false);
    empty.count(2).await?;
    Ok(())
}

#[tokio::test]
async fn same_service_queue_rechecks_source_version_and_revoked_current_identity_before_getapp() -> DomainResult<()> {
    for revoke in [false, true] {
        let engine = Engine::new(Profile::Empty).await?;
        let h = fixture(&engine).await?;
        let (gate, _release) = engine.hold("ListJobs", 1)?;
        let mut blocker = spawn(
            &h,
            format!("{CONFIG}/operations"),
            h.admin.clone(),
            json!({
            "request_id":Id::new(),"configuration_version":1,"confirm_live":true,
            "action":"ListJobs","parameters":{"PageNum":1,"PageSize":100}}),
        );
        gate.wait_entered().await?;
        let (token, key_id) = key(&h, &["alicloud:read"]).await?;
        let id = Id::new();
        let mut pending = spawn(&h, format!("{BASE}/observe"), token, observe_input(id, 1, false));
        claimed(&h, id).await?;
        assert_eq!(engine.server.requests()?.len(), 1);
        if revoke {
            h.state.store.api_key_revoke_durable(h.tenant, key_id).await?;
        } else {
            configure_live(&h, &engine, 1, true).await?;
        }
        gate.release();
        let result = pending.finish().await?;
        assert_eq!(result.status, if revoke { StatusCode::FORBIDDEN } else { StatusCode::CONFLICT });
        assert_safe(&result.json());
        blocker.finish().await?;
        engine.count(1).await?;
        assert!(
            engine
                .server
                .requests()?
                .iter()
                .all(|request| request.headers.get("x-acs-action").map(String::as_str) == Some("ListJobs"))
        );
        assert!(records(&h, "scheduler-native-observation").await?.is_empty());
        assert!(read(&h, BASE).await?["latestObservation"].is_null());
        assert!(
            audits(&h, id, "scheduler-native-observation")
                .await?
                .iter()
                .all(|entry| entry.outcome != AuditOutcome::Success)
        );
        let before = snapshot(&h).await?;
        read(&h, &receipt(id)).await?;
        assert_eq!(snapshot(&h).await?, before);
        engine.count(1).await?;
    }
    Ok(())
}

#[tokio::test]
async fn configured_loopback_without_server_capability_cannot_send_or_seed() -> DomainResult<()> {
    let engine = Engine::new(Profile::Empty).await?;
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    configure_live(&h, &engine, 0, true).await?;
    let before = snapshot(&h).await?;
    let value = read(&h, BASE).await?;
    assert_eq!(value["configured"], true);
    assert_eq!(value["canObserve"], false);
    assert_eq!(value["sourceTarget"], Value::Null);
    for initialize in [false, true] {
        let reply = h.post(&format!("{BASE}/observe"), observe_input(Id::new(), 1, initialize)).await;
        assert_eq!(reply.status, StatusCode::PRECONDITION_FAILED);
        assert_eq!(snapshot(&h).await?, before);
    }
    engine.count(0).await?;
    Ok(())
}

#[tokio::test]
async fn cancelled_api_read_finishes_only_the_local_claim_without_dispatching_another_cloud_read() -> DomainResult<()> {
    let engine = Engine::new(Profile::Empty).await?;
    let h = fixture(&engine).await?;
    let id = Id::new();
    let (gate, _release) = engine.hold("GetApp", 1)?;
    let input = observe_input(id, 1, false);
    let mut pending = spawn(&h, format!("{BASE}/observe"), h.admin.clone(), input.clone());
    gate.wait_entered().await?;
    pending.cancel().await?;
    gate.release();
    timeout(Duration::from_secs(3), async {
        loop {
            if records(&h, "scheduler-native-fact")
                .await?
                .iter()
                .any(|row| row["request_id"] == json!(id) && row["status"] == "failed")
            {
                return Ok::<_, DomainError>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| wire::fixture_error("cancelled local claim did not finish"))??;
    assert_read_audit(&h, id, AuditOutcome::Failure).await?;
    engine.count(1).await?;
    let failed = read(&h, &receipt(id)).await?;
    assert_eq!(failed["observation"], Value::Null);
    assert_eq!(failed["total"], Value::Null);
    let before = snapshot(&h).await?;
    assert_eq!(post(&h, &format!("{BASE}/observe"), input).await?, failed);
    assert_eq!(snapshot(&h).await?, before);
    engine.count(1).await?;
    Ok(())
}
