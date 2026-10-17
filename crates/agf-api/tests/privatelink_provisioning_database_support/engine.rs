use super::{
    error, p,
    wire::{self, Gate, Release, Reply, Server},
};
use crate::common::*;
use agf_core::{error::DomainResult, ids::Id};
use std::sync::Mutex;
#[derive(Clone, Copy)]
pub(crate) enum Mode {
    Acknowledged,
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
        let mode = Arc::new(Mutex::new(Mode::Acknowledged));
        let hold = Arc::new(Mutex::new(None::<(usize, Arc<Gate>)>));
        let m = mode.clone();
        let g = hold.clone();
        let count = Arc::new(Mutex::new(0_usize));
        let server=Server::start(move|r|{let host=r.headers.get("host").ok_or_else(||error("host missing"))?;wire::verify_signature(r,&format!("http://{host}"))?;let q=url::Url::parse(&format!("http://{host}{}",r.target))?.query_pairs().into_owned().collect::<BTreeMap<_,_>>();let action=r.headers.get("x-acs-action").map(String::as_str).ok_or_else(||error("action missing"))?;let method=match action{"CreateVpcEndpoint"|"EnableVpcEndpointConnection"=>"POST","GetVpcEndpointAttribute"|"ListVpcEndpointZones"|"ListVpcEndpointSecurityGroups"=>"GET",_=>return Err(error("unexpected action"))};if r.method!=method||!r.body.is_empty()||q.get("RegionId").map(String::as_str)!=Some("cn-hangzhou"){return Err(error("typed method/scope differs"))}
if method=="GET"&&(q.get("EndpointId").map(String::as_str)!=Some("ep-owned-live")||(action!="GetVpcEndpointAttribute"&&q.get("MaxResults").map(String::as_str)!=Some("50"))||q.contains_key("NextToken")){return Err(error("typed read resource differs"))}let mut n=count.lock().map_err(|_|error("counter poisoned"))?;*n+=1;let ack=Id::new();let reply=match action{
"CreateVpcEndpoint"|"EnableVpcEndpointConnection"=>{let token=q.get("ClientToken").ok_or_else(||error("original UUID absent"))?;if Id::parse(token)?.is_nil()||q.get("ServiceId").map(String::as_str)!=Some("epsrv-agf-demo"){return Err(error("intent identity differs"))}
if action=="CreateVpcEndpoint"&&(q.get("VpcId").map(String::as_str)!=Some("vpc-agf-demo")||q.get("DryRun").map(String::as_str)!=Some("false")){return Err(error("create resources differ"))}let current_mode=*m.lock().map_err(|_|error("mode poisoned"))?;match current_mode{Mode::Acknowledged=>Reply::json(200,&json!({"RequestId":ack,"EndpointId":"ep-owned-live"})),Mode::Lost=>Reply::truncated(),Mode::Rejected=>Reply::json(403,&json!({"RequestId":ack,"Code":"Forbidden"}))}},
"GetVpcEndpointAttribute"=>Reply::json(200,&json!({"RequestId":ack,"EndpointId":"ep-owned-live","RegionId":"cn-hangzhou","ServiceRegionId":"cn-hangzhou","ServiceId":"epsrv-agf-demo","VpcId":"vpc-agf-demo","EndpointStatus":"Active","ConnectionStatus":"Connected"})),
"ListVpcEndpointZones"=>Reply::json(200,&json!({"RequestId":ack,"TotalCount":1,"MaxResults":50,"Zones":[{"ZoneId":"cn-hangzhou-a","VSwitchId":"vsw-agf-demo"}]})),
"ListVpcEndpointSecurityGroups"=>Reply::json(200,&json!({"RequestId":ack,"TotalCount":1,"MaxResults":50,"SecurityGroups":[{"SecurityGroupId":"sg-agf-demo"}]})),_=>return Err(error("unexpected action"))};let gate=g.lock().map_err(|_|error("gate poisoned"))?;Ok(if let Some((_,held))=gate.as_ref().filter(|(nth,_)|*nth==*n){reply.held(held)}else{reply})}).await?;
        let address = server.origin.trim_start_matches("http://").parse().map_err(|_| error("socket invalid"))?;
        Ok(Self { server, mode, hold, address })
    }
    pub(crate) fn mode(&self, m: Mode) -> DomainResult<()> {
        *self.mode.lock().map_err(|_| error("mode poisoned"))? = m;
        Ok(())
    }
    pub(crate) fn writes(&self) -> DomainResult<usize> {
        self.server.healthy()?;
        self.server.count("POST")
    }
    pub(crate) fn count(&self) -> DomainResult<usize> {
        self.server.healthy()?;
        Ok(self.server.requests()?.len())
    }
    pub(crate) fn hold(&self, nth: usize) -> DomainResult<(Arc<Gate>, Release)> {
        let g = Arc::new(Gate::default());
        let release = g.release_on_drop();
        *self.hold.lock().map_err(|_| error("gate poisoned"))? = Some((nth, g.clone()));
        Ok((g, release))
    }
}
pub(crate) fn route(mut h: Harness, e: &Engine) -> DomainResult<Harness> {
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.state.privatelink_provisioning =
        Arc::new(agf_api::privatelink_provisioning::Registry::literal_loopback_for_test(h.tenant, e.address)?);
    let tenant = h.tenant;
    h.app = build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut r: Request<Body>| {
        r.headers_mut().insert("x-agf-tenant", tenant.to_string().parse().expect("synthetic tenant"));
        async move { r }
    }));
    Ok(h)
}
pub(crate) async fn configure(h: &Harness, e: &Engine, version: u64, enabled: bool, label: &str) -> DomainResult<()> {
    let r=h.request("PUT",p::CONFIG,Some(&h.admin),Some(json!({"expected_version":version,"enabled":enabled,"mock":false,"settings":{"region_id":"cn-hangzhou","account_id":label,"endpoint":format!("http://{}",e.address)},"secrets":{"access_key_id":wire::ACCESS_KEY,"access_key_secret":wire::SECRET}}))).await;
    assert_eq!(r.status, StatusCode::OK, "normal stored source");
    Ok(())
}
