use super::{
    Case, error, queue,
    wire::{self, Gate, Release, Reply, Server},
};
use crate::common::*;
use agf_core::error::DomainResult;
use std::sync::Mutex;
#[derive(Clone, Copy)]
pub(crate) enum Mode {
    Accepted,
    Lost,
    Rejected,
}
pub(crate) struct Engine {
    server: Server,
    mode: Arc<Mutex<Mode>>,
    hold: Arc<Mutex<Option<(usize, Arc<Gate>)>>>,
    pub(crate) address: std::net::SocketAddr,
}
impl Engine {
    pub(crate) async fn start() -> DomainResult<Self> {
        let mode = Arc::new(Mutex::new(Mode::Accepted));
        let hold = Arc::new(Mutex::new(None::<(usize, Arc<Gate>)>));
        let current = mode.clone();
        let gate = hold.clone();
        let count = Arc::new(Mutex::new(0_usize));
        let server = Server::start(move |request| {
            let host = request.headers.get("host").ok_or_else(|| error("host absent"))?;
            wire::verify_signature(request, &format!("http://{host}"))?;
            let query = url::Url::parse(&format!("http://{host}{}", request.target))?
                .query_pairs()
                .into_owned()
                .collect::<BTreeMap<_, _>>();
            if request.method != "POST"
                || !request.body.is_empty()
                || query.get("EventInfo.1.GroupId").map(String::as_str) != Some("7")
                || query.get("EventInfo.1.EventName").map(String::as_str) != Some("owned-queue-event")
                || query.get("EventInfo.1.Content").map(String::as_str) != Some("owned-private-CMS-payload")
                || request.headers.get("x-acs-action").map(String::as_str) != Some("PutCustomEvent")
            {
                return Err(error("unexpected typed CMS request"));
            }
            let mut count = count.lock().map_err(|_| error("counter poisoned"))?;
            *count += 1;
            let current_mode = *current.lock().map_err(|_| error("mode poisoned"))?;
            let reply = match current_mode {
                Mode::Accepted => {
                    Reply::json(200, &json!({"Code":"200","Message":"success","RequestId":"owned-cms-accepted"}))
                }
                Mode::Lost => Reply::truncated(),
                Mode::Rejected => Reply::json(403, &json!({"Code":"Forbidden","RequestId":"owned-cms-rejected"})),
            };
            let held = gate.lock().map_err(|_| error("gate poisoned"))?;
            Ok(if let Some((_, held)) = held.as_ref().filter(|(nth, _)| *nth == *count) {
                reply.held(held)
            } else {
                reply
            })
        })
        .await?;
        let address = server.origin.trim_start_matches("http://").parse().map_err(|_| error("socket invalid"))?;
        Ok(Self { server, mode, hold, address })
    }
    pub(crate) fn mode(&self, value: Mode) -> DomainResult<()> {
        *self.mode.lock().map_err(|_| error("mode poisoned"))? = value;
        Ok(())
    }
    pub(crate) fn count(&self) -> DomainResult<usize> {
        self.server.healthy()?;
        self.server.count("POST")
    }
    pub(crate) fn hold(&self, nth: usize) -> DomainResult<(Arc<Gate>, Release)> {
        let gate = Arc::new(Gate::default());
        let release = gate.release_on_drop();
        *self.hold.lock().map_err(|_| error("gate poisoned"))? = Some((nth, gate.clone()));
        Ok((gate, release))
    }
}
pub(crate) fn route(mut h: Harness, engine: &Engine) -> DomainResult<Harness> {
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.state.cms_queue = Arc::new(agf_api::cms_queue::Registry::literal_loopback_for_test(h.tenant, engine.address)?);
    let tenant = h.tenant;
    h.app = build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
        request.headers_mut().insert("x-agf-tenant", tenant.to_string().parse().expect("synthetic tenant header"));
        async move { request }
    }));
    Ok(h)
}
pub(crate) async fn configure(h: &Harness, engine: &Engine, version: u64, enabled: bool) -> DomainResult<()> {
    let reply = h
        .request(
            "PUT",
            queue::CONFIG,
            Some(&h.admin),
            Some(json!({"expected_version":version,"enabled":enabled,"mock":false,
        "settings":{"region_id":"cn-hangzhou","group_id":"7","endpoint":format!("http://{}",engine.address)},
        "secrets":{"access_key_id":wire::ACCESS_KEY,"access_key_secret":wire::SECRET}})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "normal HTTP CMS source");
    Ok(())
}
pub(crate) async fn fixture(case: &Case) -> DomainResult<(Harness, Engine)> {
    let engine = Engine::start().await?;
    let h = route(case.inner.h.clone(), &engine)?;
    configure(&h, &engine, 0, true).await?;
    Ok((h, engine))
}
