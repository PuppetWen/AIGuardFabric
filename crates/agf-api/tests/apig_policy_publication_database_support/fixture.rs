//! Real API configuration and signed source records; provider effects use the owned encrypted Mock bridge.
use crate::common::*;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
    policy::Policy,
};

use super::wire::{self, Gate, Release, Reply, Server, fixture_error, verify_signature};
use std::sync::Mutex;

pub(crate) const BASE: &str = "/api/v1/alicloud/apig/policy-publication";
pub(crate) const CONFIG: &str = "/api/v1/alicloud/connections/alicloud-apig";
pub(crate) const PRIVATE_REASON: &str = "owned-apig-source-description-never-a-receipt";

pub(crate) struct Fixture {
    pub(crate) h: Harness,
    pub(crate) quota: Value,
    pub(crate) policy: Value,
}

pub(crate) fn settings() -> Value {
    json!({"region_id":"cn-hangzhou","account_id":"owned-apig-publication-account",
        "policy_http_api_id":"api-agf-demo","policy_gateway_id":"gw-agf-demo",
        "policy_environment_id":"env-agf-demo","policy_id":"policy-agf-demo",
        "policy_attachment_id":"attachment-agf-demo","policy_dialect":"apig-2024-03-27-ai-token-rate-limit",
        "managed_policy_confirmed":true})
}

pub(crate) fn number(value: &Value, field: &str) -> DomainResult<u64> {
    value[field].as_u64().ok_or_else(|| DomainError::Internal(format!("missing public numeric field {field}")))
}
pub(crate) fn identifier(value: &Value, field: &str) -> DomainResult<Id> {
    serde_json::from_value(value[field].clone()).map_err(Into::into)
}
pub(crate) fn text(value: &Value, field: &str) -> DomainResult<String> {
    value[field]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| DomainError::Internal(format!("missing public text field {field}")))
}
pub(crate) async fn read(h: &Harness, path: &str) -> DomainResult<Value> {
    let response = h.get(path).await;
    assert_eq!(response.status, StatusCode::OK, "GET {path}: {}", response.text);
    serde_json::from_slice(&response.bytes).map_err(Into::into)
}
pub(crate) async fn post(h: &Harness, path: &str, input: Value) -> DomainResult<Value> {
    let response = h.post(path, input).await;
    assert_eq!(response.status, StatusCode::OK, "POST {path}: {}", response.text);
    serde_json::from_slice(&response.bytes).map_err(Into::into)
}
pub(crate) async fn configure(h: &Harness, version: u64, enabled: bool, settings: Value) -> DomainResult<Value> {
    let response = h
        .request(
            "PUT",
            CONFIG,
            Some(&h.admin),
            Some(json!({
                "expected_version":version,"enabled":enabled,"mock":true,"settings":settings,"secrets":{}
            })),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "configuration: {}", response.text);
    let saved = response.json();
    assert_eq!(saved["name"], "alicloud-apig");
    assert_eq!(saved["version"], version + 1);
    let actual = agf_api::cloud_store::load(&h.state, h.tenant, "alicloud-apig")
        .await?
        .ok_or_else(|| DomainError::Internal("missing HTTP-saved APIG source".into()))?;
    assert_eq!(actual.version, version + 1);
    assert!(
        h.state.configurations.get::<Value>(h.tenant, agf_api::integration_store::KIND, actual.id).await?.is_none()
    );
    Ok(saved)
}
pub(crate) fn quota_body(name: &str, version: u64, limit: u64) -> Value {
    json!({"name":name,"expected_version":version,"scope":"tenant","dimension":"tokens",
        "window":"minute","limit":limit,"soft_threshold":0,"action":"deny","enabled":true})
}
pub(crate) async fn save_quota(h: &Harness, body: Value) -> DomainResult<Value> {
    Ok(post(h, "/api/v1/quotas", body).await?["quota"].clone())
}
pub(crate) fn policy_body(name: &str, quota: Id, version: u64) -> Value {
    json!({"expected_version":version,"name":name,"description":PRIVATE_REASON,"language":"structured",
        "source":"","structured":{},"action":"quota","priority":1,"intercept_points":["ai-gateway"],
        "enabled":true,"dry_run":false,"quota_id":quota})
}
pub(crate) fn assert_policy(h: &Harness, value: &Value) -> DomainResult<()> {
    let policy: Policy = serde_json::from_value(value.clone())?;
    assert_eq!(policy.tenant_id, h.tenant);
    assert_eq!(policy.content_hash, policy.compute_hash());
    agf_api::policy_store::signer(&h.state)?.verify(&policy)
}
pub(crate) async fn create_policy(h: &Harness, body: Value) -> DomainResult<Value> {
    let response = h.post("/api/v1/policies", body).await;
    assert_eq!(response.status, StatusCode::CREATED, "policy creation: {}", response.text);
    let policy = response.json()["policy"].clone();
    assert_policy(h, &policy)?;
    Ok(policy)
}

impl Fixture {
    pub(crate) async fn with_harness(h: Harness) -> DomainResult<Self> {
        configure(&h, 0, true, settings()).await?;
        let quota = save_quota(&h, quota_body(&format!("owned-apig-quota-{}", Id::new()), 0, 1250)).await?;
        assert_eq!(quota["version"], 1);
        let policy =
            create_policy(&h, policy_body(&format!("owned-apig-policy-{}", Id::new()), identifier(&quota, "id")?, 0))
                .await?;
        Ok(Self { h, quota, policy })
    }
    pub(crate) async fn state(&self) -> DomainResult<Value> {
        read(&self.h, BASE).await
    }
    pub(crate) async fn observe(&self, initialize: bool) -> DomainResult<Value> {
        let state = self.state().await?;
        post(
            &self.h,
            &format!("{BASE}/observe"),
            observe_input(Id::new(), number(&state["binding"], "configurationVersion")?, initialize),
        )
        .await
    }
    pub(crate) async fn prepare(&self, observed: &Value) -> DomainResult<Value> {
        self.prepare_change(observed, selection(&self.policy)?).await
    }
    pub(crate) async fn prepare_change(&self, observed: &Value, change: Value) -> DomainResult<Value> {
        let state = self.state().await?;
        post(&self.h, &format!("{BASE}/previews"), preview_input(observed, change, number(&state, "stateVersion")?)?)
            .await
    }
    pub(crate) async fn ready(&self) -> DomainResult<Value> {
        let mocked = self.state().await?["binding"]["mocked"] == true;
        self.prepare(&self.observe(mocked).await?).await
    }
    pub(crate) async fn apply(&self, preview: &Value, request: Id) -> DomainResult<Value> {
        post(&self.h, &format!("{BASE}/operations"), apply_input(preview, request)?).await
    }
}
pub(crate) fn observe_input(request: Id, version: u64, initialize: bool) -> Value {
    json!({"request_id":request,"configuration_version":version,"confirm_live":false,"initialize_mock_fixture":initialize})
}
pub(crate) fn selection(policy: &Value) -> DomainResult<Value> {
    Ok(
        json!({"action":"publish","policies":[{"policy_id":identifier(policy,"id")?,"version":number(policy,"version")?}]}),
    )
}
pub(crate) fn preview_input(observed: &Value, change: Value, version: u64) -> DomainResult<Value> {
    Ok(json!({"request_id":Id::new(),"configuration_version":number(&observed["target"],"configurationVersion")?,
        "observation_id":identifier(observed,"id")?,"expected_state_version":version,"change":change}))
}
pub(crate) fn apply_input(preview: &Value, request: Id) -> DomainResult<Value> {
    Ok(
        json!({"request_id":request,"preview_id":identifier(preview,"id")?,"expected_state_version":number(preview,"stateVersion")?,
        "confirm_apply":true,"confirm_scope_difference":true,"confirm_shared_policy_impact":true,"confirm_no_cloud_cas":true,
        "confirm_live":false,"confirm_unknown_overlap":false}),
    )
}
pub(crate) fn receipt_path(request: Id) -> String {
    format!("{BASE}/operations/{request}")
}
pub(crate) fn assert_verified(value: &Value) {
    assert_eq!(value["status"], "verified");
    assert_eq!(value["cloudWrite"]["status"], "accepted");
    assert_eq!(value["readback"]["status"], "matched");
    assert_eq!(value["localPublication"]["status"], "published");
    assert_eq!(value["completionState"], "complete");
    assert_eq!(value["consumerApplied"], Value::Null);
    assert_eq!(value["target"]["mocked"], true);
    assert_eq!(value["target"]["transportMode"], "mock");
    assert_private(value);
}
pub(crate) fn assert_private(value: &Value) {
    assert!(!value.to_string().contains(PRIVATE_REASON));
    match value {
        Value::Object(fields) => {
            for (field, value) in fields {
                if field == "source" {
                    assert!(
                        value.is_null()
                            || value.as_object().is_some_and(|fields| fields.keys().all(|key| matches!(
                                key.as_str(),
                                "policyId"
                                    | "policyVersion"
                                    | "quotaId"
                                    | "quotaVersion"
                                    | "quotaFingerprint"
                                    | "managedLimit"
                                    | "limit"
                            ))),
                        "raw policy source must not be exposed"
                    );
                }
                assert!(
                    !matches!(
                        field.as_str(),
                        "config"
                            | "body"
                            | "baseline"
                            | "desired"
                            | "content"
                            | "signature"
                            | "private"
                            | "completion"
                            | "secrets"
                            | "ciphertext_b64"
                            | "nonce_b64"
                            | "aad"
                            | "headers"
                            | "raw_body"
                    ),
                    "private field exposed: {field}"
                );
                assert_private(value);
            }
        }
        Value::Array(items) => {
            for value in items {
                assert_private(value);
            }
        }
        _ => {}
    }
}
pub(crate) fn for_tenant(mut h: Harness, tenant: TenantId) -> DomainResult<Harness> {
    let value = tenant
        .to_string()
        .parse::<axum::http::HeaderValue>()
        .map_err(|_| DomainError::Internal("invalid owned tenant header".into()))?;
    h.tenant = tenant;
    h.app = build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
        request.headers_mut().insert("x-agf-tenant", value.clone());
        async move { request }
    }));
    Ok(h)
}

#[derive(Clone, Copy)]
pub(crate) enum Outcome {
    Normal,
    Lost,
    Error,
    False,
}
struct State {
    responses: Value,
    outcome: Outcome,
    held: Option<(String, usize, Arc<Gate>)>,
    gets: usize,
    puts: usize,
}
pub(crate) struct Engine {
    server: Server,
    state: Arc<Mutex<State>>,
    pub(crate) address: std::net::SocketAddr,
}
impl Engine {
    pub(crate) async fn start() -> DomainResult<Self> {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../../tests/fixtures/alicloud/apig-policy-driver.json"))?;
        let state = Arc::new(Mutex::new(State {
            responses: fixture["responses"].clone(),
            outcome: Outcome::Normal,
            held: None,
            gets: 0,
            puts: 0,
        }));
        let current = state.clone();
        let server = Server::start(move |request| {
            let host = request.headers.get("host").ok_or_else(|| fixture_error("missing host"))?;
            if !host.starts_with("127.0.0.1:") {
                return Err(fixture_error("foreign host"));
            }
            verify_signature(request, &format!("http://{host}"))?;
            let action = request.headers.get("x-acs-action").ok_or_else(|| fixture_error("missing action"))?;
            let mut state = current.lock().map_err(|_| fixture_error("state lock poisoned"))?;
            let reply = if request.method == "GET" {
                state.gets += 1;
                let expected = match action.as_str() {
                    "GetHttpApi" => "/v1/http-apis/api-agf-demo?expandPolicyConfigs=false",
                    "GetPolicy" => "/v2/policies/policy-agf-demo",
                    "GetPolicyAttachment" => "/v1/policy-attachments/attachment-agf-demo",
                    _ => return Err(fixture_error("foreign GET action")),
                };
                if request.target != expected || !request.body.is_empty() {
                    return Err(fixture_error("foreign GET identity"));
                }
                Reply::json(200, &state.responses[action])
            } else if request.method == "PUT"
                && request.target == "/v2/policies/policy-agf-demo"
                && action == "UpdatePolicy"
            {
                state.puts += 1;
                let body: Value = serde_json::from_str(&request.body)?;
                let fields = body.as_object().ok_or_else(|| fixture_error("PUT body is not an object"))?;
                if fields.keys().any(|key| !matches!(key.as_str(), "name" | "description" | "config")) {
                    return Err(fixture_error("unexpected PUT field"));
                }
                let config =
                    body["config"].as_str().ok_or_else(|| fixture_error("config is not a plain JSON string"))?;
                let _: Value = serde_json::from_str(config)?;
                match state.outcome {
                    Outcome::Error => {
                        Reply::json(503, &json!({"code":"ownedUnavailable","requestId":"owned-unavailable"}))
                    }
                    Outcome::False => Reply::json(200, &json!({"code":"false","requestId":"owned-false"})),
                    Outcome::Normal | Outcome::Lost => {
                        state.responses["GetPolicy"]["data"]["config"] = body["config"].clone();
                        state.responses["GetPolicy"]["data"]["name"] = body["name"].clone();
                        if let Some(description) = body.get("description") {
                            state.responses["GetPolicy"]["data"]["description"] = description.clone();
                        }
                        if matches!(state.outcome, Outcome::Lost) {
                            Reply::truncated()
                        } else {
                            Reply::json(200, &json!({"code":"Ok","requestId":"owned-accepted-put"}))
                        }
                    }
                }
            } else {
                return Err(fixture_error("unexpected HTTP method"));
            };
            let count = if request.method == "GET" { state.gets } else { state.puts };
            Ok(match &state.held {
                Some((method, nth, gate)) if *method == request.method && *nth == count => reply.held(gate),
                _ => reply,
            })
        })
        .await?;
        let address =
            server.origin.trim_start_matches("http://").parse().map_err(|_| fixture_error("socket address invalid"))?;
        Ok(Self { server, state, address })
    }
    pub(crate) fn reply(&self, outcome: Outcome) -> DomainResult<()> {
        self.state.lock().map_err(|_| fixture_error("state lock poisoned"))?.outcome = outcome;
        Ok(())
    }
    pub(crate) fn counts(&self) -> DomainResult<(usize, usize)> {
        self.server.healthy()?;
        Ok((self.server.count("GET")?, self.server.count("PUT")?))
    }
    pub(crate) fn config(&self) -> DomainResult<Value> {
        let state = self.state.lock().map_err(|_| fixture_error("state lock poisoned"))?;
        serde_json::from_str(
            state.responses["GetPolicy"]["data"]["config"].as_str().ok_or_else(|| fixture_error("config missing"))?,
        )
        .map_err(Into::into)
    }
    pub(crate) fn hold(&self, method: &str, nth: usize) -> DomainResult<(Arc<Gate>, Release)> {
        assert!(matches!(method, "GET" | "PUT") && nth > 0);
        let gate = Arc::new(Gate::default());
        self.state.lock().map_err(|_| fixture_error("state lock poisoned"))?.held =
            Some((method.into(), nth, gate.clone()));
        let release = gate.release_on_drop();
        Ok((gate, release))
    }
}
pub(crate) fn route(mut h: Harness, address: std::net::SocketAddr) -> DomainResult<Harness> {
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.state.apig_policy_publication =
        Arc::new(agf_api::apig_policy_publication::Registry::literal_loopback_for_test(h.tenant, address)?);
    let tenant = h.tenant;
    super::for_tenant(h, tenant)
}
pub(crate) async fn loopback(h: Harness, engine: &Engine) -> DomainResult<super::Fixture> {
    let f = super::Fixture::with_harness(route(h, engine.address)?).await?;
    let mut settings = super::settings();
    settings["endpoint"] = json!(format!("http://{}", engine.address));
    configure_live(&f.h, 1, true, settings).await?;
    assert_eq!(engine.counts()?, (0, 0));
    Ok(f)
}
pub(crate) async fn configure_live(h: &Harness, version: u64, enabled: bool, settings: Value) -> DomainResult<()> {
    let response = h
        .request(
            "PUT",
            super::CONFIG,
            Some(&h.admin),
            Some(json!({"expected_version":version,"enabled":enabled,"mock":false,
        "settings":settings,"secrets":{"access_key_id":wire::ACCESS_KEY,"access_key_secret":wire::SECRET}})),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.json()["version"], version + 1);
    Ok(())
}
