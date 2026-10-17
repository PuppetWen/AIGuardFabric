//! HTTP-facing workflow setup with an explicit per-tenant literal-loopback transport registry.
use crate::common::*;
use agf_core::{
    audit::AuditLog,
    error::{DomainError, DomainResult},
    ids::Id,
};

#[path = "transport_wire.rs"]
mod wire;
pub(crate) use wire::{Engine, INITIAL, Pending, Reply};
pub(crate) const BASE: &str = "/api/v1/alicloud/mse/config-publication";
pub(crate) const CONFIG: &str = "/api/v1/alicloud/connections/alicloud-mse";
pub(crate) const FACT: &str = "mse-config-publication-fact";
pub(crate) const PENDING: &str = "mse-config-publication-pending";
pub(crate) const DETAIL: &str = "mse-config-publication-detail";
pub(crate) const MAIN: &str = "mse-config-publication-state";

pub(crate) fn number(value: &Value, field: &str) -> DomainResult<u64> {
    value[field].as_u64().ok_or_else(|| DomainError::Internal(format!("missing numeric DTO {field}")))
}
pub(crate) fn id(value: &Value, field: &str) -> DomainResult<Id> {
    Ok(serde_json::from_value(value[field].clone())?)
}
pub(crate) async fn read(h: &Harness, path: &str) -> DomainResult<Value> {
    let response = h.get(path).await;
    assert_eq!(response.status, StatusCode::OK, "GET {path}: {}", response.text);
    Ok(serde_json::from_slice(&response.bytes)?)
}
pub(crate) async fn post(h: &Harness, path: &str, body: Value) -> DomainResult<Value> {
    let response = h.post(path, body).await;
    assert_eq!(response.status, StatusCode::OK, "POST {path}: {}", response.text);
    Ok(serde_json::from_slice(&response.bytes)?)
}
pub(crate) fn route(mut h: Harness, address: std::net::SocketAddr) -> DomainResult<Harness> {
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.state.mse_config_publication =
        Arc::new(agf_api::mse_config_publication::Registry::literal_loopback_for_test(h.tenant, address)?);
    let header: axum::http::HeaderValue =
        h.tenant.to_string().parse().map_err(|_| DomainError::Internal("owned tenant header invalid".into()))?;
    h.app = build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
        request.headers_mut().insert("x-agf-tenant", header.clone());
        async move { request }
    }));
    Ok(h)
}
pub(crate) fn settings(address: std::net::SocketAddr) -> Value {
    json!({"engine_origin":format!("http://{address}"),"region_id":"cn-hangzhou","instance_id":"owned-loopback-instance",
        "namespace_id":"","config_group":"AGF","config_data_id":"agf-policies.json","config_dialect":"nacos-http-v2-cas",
        "managed_upsert_confirmed":true,"account_id":"owned-loopback-account","credential_source":"access-key"})
}
pub(crate) async fn configure(
    h: &Harness,
    address: std::net::SocketAddr,
    version: u64,
    enabled: bool,
) -> DomainResult<()> {
    let response = h
        .request(
            "PUT",
            CONFIG,
            Some(&h.admin),
            Some(json!({"expected_version":version,"enabled":enabled,
        "mock":false,"settings":settings(address),"secrets":{"access_key_id":wire::ACCESS,
        "access_key_secret":"owned-loopback-synthetic-secret-not-a-real-credential"}})),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "configuration: {}", response.text);
    assert_eq!(response.json()["version"], version + 1);
    Ok(())
}
pub(crate) async fn create_policy(h: &Harness) -> DomainResult<Value> {
    let response = h
        .post(
            "/api/v1/policies",
            json!({"name":format!("owned-loopback-{}",Id::new()),"language":"cel",
        "source":"{\"action\":\"allow\",\"reason\":\"owned private policy\"}","action":"allow","enabled":true,
        "priority":1,"intercept_points":["ai-gateway","mcp-proxy"]}),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "policy creation: {}", response.text);
    let policy = response.json()["policy"].clone();
    let typed: agf_core::policy::Policy = serde_json::from_value(policy.clone())?;
    assert_eq!(typed.content_hash, typed.compute_hash());
    agf_api::policy_store::signer(&h.state)?.verify(&typed)?;
    Ok(policy)
}
pub(crate) fn observe_input() -> Value {
    json!({"request_id":Id::new(),"configuration_version":1,"confirm_live":false})
}
pub(crate) fn apply_input(preview: &Value, request: Id) -> DomainResult<Value> {
    Ok(
        json!({"request_id":request,"preview_id":id(preview,"id")?,"expected_state_version":number(preview,"stateVersion")?,
        "confirm_apply":true,"confirm_upsert":true,"confirm_live":false,"confirm_unknown_overlap":false}),
    )
}
pub(crate) fn receipt(request: Id) -> String {
    format!("{BASE}/operations/{request}")
}

pub(crate) struct Fixture {
    pub(crate) h: Harness,
    pub(crate) policy: Value,
    pub(crate) engine: Engine,
}
impl Fixture {
    pub(crate) async fn attach(h: Harness) -> DomainResult<Self> {
        let engine = Engine::start().await?;
        let h = route(h, engine.address)?;
        configure(&h, engine.address, 0, true).await?;
        let policy = create_policy(&h).await?;
        assert_eq!(engine.counts().await, (0, 0));
        Ok(Self { h, policy, engine })
    }
    pub(crate) async fn observe(&self) -> DomainResult<Value> {
        post(&self.h, &format!("{BASE}/observe"), observe_input()).await
    }
    pub(crate) async fn ready(&self) -> DomainResult<Value> {
        let before = self.engine.counts().await;
        let observation = self.observe().await?;
        let state = read(&self.h, BASE).await?;
        let preview = post(
            &self.h,
            &format!("{BASE}/previews"),
            json!({"request_id":Id::new(),"configuration_version":1,
            "observation_id":id(&observation,"id")?,"expected_state_version":number(&state,"stateVersion")?,
            "change":{"action":"publish","policies":[{"policy_id":id(&self.policy,"id")?,"version":1}]}}),
        )
        .await?;
        assert_eq!(self.engine.counts().await, (before.0 + 1, before.1));
        Ok(preview)
    }
    pub(crate) async fn apply(&self, preview: &Value, request: Id) -> DomainResult<Value> {
        post(&self.h, &format!("{BASE}/operations"), apply_input(preview, request)?).await
    }
}
pub(crate) fn verified(value: &Value) {
    assert_eq!(value["status"], "verified");
    assert_eq!(value["cloudWrite"]["status"], "accepted");
    assert_eq!(value["readback"]["status"], "matched");
    assert_eq!(value["localPublication"]["status"], "published");
    assert_eq!(value["completionState"], "complete");
    assert_eq!(value["consumerApplied"], Value::Null);
    assert_eq!(value["target"]["mocked"], false);
    assert_eq!(value["target"]["transportMode"], "loopback-test");
}
pub(crate) async fn audits(h: &Harness, request: Id, kind: &str) -> DomainResult<Vec<AuditLog>> {
    let id = request.to_string();
    Ok(h.state
        .store
        .audit_chain_durable(h.tenant, 0, i64::MAX)
        .await?
        .into_iter()
        .filter(|row| row.target.kind == kind && row.target.id.as_deref() == Some(id.as_str()))
        .collect())
}
pub(crate) async fn snapshot(h: &Harness) -> DomainResult<Value> {
    let mut rows = BTreeMap::new();
    for kind in [
        MAIN,
        FACT,
        DETAIL,
        PENDING,
        "mse-config-publication-preview",
        "mse-config-publication-mock",
        "signed-policy-registry",
        "cloud-integration",
    ] {
        let mut values = h.state.configurations.list::<Value>(h.tenant, kind).await?;
        values.sort_by_key(Value::to_string);
        rows.insert(kind, values);
    }
    Ok(json!({"rows":rows,"audit":h.state.store.audit_chain_durable(h.tenant,0,i64::MAX).await?}))
}
pub(crate) async fn wait_pending(h: &Harness) -> DomainResult<()> {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if !h.state.configurations.list::<Value>(h.tenant, PENDING).await?.is_empty() {
                return Ok::<_, DomainError>(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| DomainError::Internal("cancelled cloud call did not stage its local receipt".into()))?
}
