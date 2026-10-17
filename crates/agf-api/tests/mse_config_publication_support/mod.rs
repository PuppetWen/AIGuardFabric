//! Owned Mock fixtures configure real API records; no provider, process environment or shared edits.
use crate::common::*;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
    policy::Policy,
};

mod boundaries;
mod lifecycle;
mod records;
pub(crate) use records::{assert_bundle, configurations, provider, provider_at, snapshot, workflow_audits};

pub(crate) const BASE: &str = "/api/v1/alicloud/mse/config-publication";
pub(crate) const CONFIG: &str = "/api/v1/alicloud/connections/alicloud-mse";
pub(crate) const PRIVATE_REASON: &str = "owned-mse-policy-source-never-a-public-receipt";

pub(crate) struct Fixture {
    pub(crate) h: Harness,
    pub(crate) policy: Value,
}

pub(crate) fn settings() -> Value {
    json!({"engine_origin":"https://mse-agf-demo.invalid","region_id":"cn-hangzhou",
        "instance_id":"inst-demo","namespace_id":"","config_group":"AGF",
        "config_data_id":"agf-policies.json","config_dialect":"nacos-http-v2-cas",
        "managed_upsert_confirmed":true,"account_id":"owned-mse-publication-account"})
}

pub(crate) fn number(value: &Value, field: &str) -> DomainResult<u64> {
    value[field].as_u64().ok_or_else(|| DomainError::Internal(format!("missing numeric public field {field}")))
}

pub(crate) fn identifier(value: &Value, field: &str) -> DomainResult<Id> {
    Ok(serde_json::from_value(value[field].clone())?)
}

pub(crate) fn text(value: &Value, field: &str) -> DomainResult<String> {
    value[field]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| DomainError::Internal(format!("missing textual public field {field}")))
}

pub(crate) async fn read(h: &Harness, path: &str) -> DomainResult<Value> {
    let response = h.get(path).await;
    assert_eq!(response.status, StatusCode::OK, "public GET {path}: {}", response.text);
    Ok(serde_json::from_slice(&response.bytes)?)
}

pub(crate) async fn post(h: &Harness, path: &str, input: Value) -> DomainResult<Value> {
    let response = h.post(path, input).await;
    assert_eq!(response.status, StatusCode::OK, "public POST {path}: {}", response.text);
    Ok(serde_json::from_slice(&response.bytes)?)
}

pub(crate) async fn configure(
    h: &Harness,
    version: u64,
    enabled: bool,
    mocked: bool,
    settings: Value,
) -> DomainResult<Value> {
    let response = h
        .request(
            "PUT",
            CONFIG,
            Some(&h.admin),
            Some(json!({
                "expected_version":version,"enabled":enabled,"mock":mocked,"settings":settings,
            })),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "cloud configuration: {}", response.text);
    let saved = response.json();
    assert_eq!(saved["name"], "alicloud-mse");
    assert_eq!(saved["version"], version + 1);
    let row = agf_api::cloud_store::load(&h.state, h.tenant, "alicloud-mse")
        .await?
        .ok_or_else(|| DomainError::Internal("API did not persist the cloud configuration".into()))?;
    assert_eq!(row.name, "alicloud-mse");
    assert_eq!(row.version, version + 1);
    assert!(h.state.configurations.get::<Value>(h.tenant, agf_api::integration_store::KIND, row.id).await?.is_none());
    Ok(saved)
}

pub(crate) fn policy_body(name: &str, action: &str, version: u64) -> Value {
    json!({"expected_version":version,"name":name,"language":"cel",
        "source":json!({"action":action,"reason":PRIVATE_REASON}).to_string(),
        "action":action,"enabled":true,"priority":1,"intercept_points":["ai-gateway","mcp-proxy"]})
}

pub(crate) fn assert_policy(h: &Harness, value: &Value) -> DomainResult<()> {
    let policy: Policy = serde_json::from_value(value.clone())?;
    assert_eq!(policy.tenant_id, h.tenant);
    assert_eq!(policy.content_hash, policy.compute_hash());
    agf_api::policy_store::signer(&h.state)?.verify(&policy)?;
    Ok(())
}

pub(crate) async fn create_policy(h: &Harness, action: &str) -> DomainResult<Value> {
    let name = format!("owned-mse-{}", Id::new());
    let response = h.post("/api/v1/policies", policy_body(&name, action, 0)).await;
    assert_eq!(response.status, StatusCode::CREATED, "policy creation: {}", response.text);
    let policy = response.json()["policy"].clone();
    assert_eq!(policy["version"], 1);
    assert_policy(h, &policy)?;
    Ok(policy)
}

pub(crate) async fn update_policy(f: &Fixture, action: &str) -> DomainResult<Value> {
    let id = identifier(&f.policy, "id")?;
    let response =
        f.h.request(
            "PUT",
            &format!("/api/v1/policies/{id}"),
            Some(&f.h.admin),
            Some(policy_body(&text(&f.policy, "name")?, action, number(&f.policy, "version")?)),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "policy update: {}", response.text);
    let policy = response.json()["policy"].clone();
    assert_policy(&f.h, &policy)?;
    Ok(policy)
}

impl Fixture {
    pub(crate) async fn new() -> DomainResult<Self> {
        Self::with_harness(setup().await).await
    }
    pub(crate) async fn with_harness(h: Harness) -> DomainResult<Self> {
        configure(&h, 0, true, true, settings()).await?;
        let policy = create_policy(&h, "allow").await?;
        Ok(Self { h, policy })
    }
    pub(crate) async fn state(&self) -> DomainResult<Value> {
        read(&self.h, BASE).await
    }
    pub(crate) async fn observe(&self) -> DomainResult<Value> {
        let state = self.state().await?;
        post(
            &self.h,
            &format!("{BASE}/observe"),
            observe_input(Id::new(), number(&state["binding"], "configurationVersion")?),
        )
        .await
    }
    pub(crate) async fn prepare(&self, observation: &Value) -> DomainResult<Value> {
        let state = self.state().await?;
        self.prepare_change(
            observation,
            json!({"action":"publish","policies":[{
                "policy_id":identifier(&self.policy,"id")?,"version":number(&self.policy,"version")?
            }]}),
            number(&state, "stateVersion")?,
        )
        .await
    }
    pub(crate) async fn prepare_change(
        &self,
        observation: &Value,
        change: Value,
        state_version: u64,
    ) -> DomainResult<Value> {
        post(&self.h, &format!("{BASE}/previews"), preview_input(observation, change, state_version)?).await
    }
    pub(crate) async fn ready(&self) -> DomainResult<Value> {
        self.prepare(&self.observe().await?).await
    }
    pub(crate) async fn apply(&self, preview: &Value, request: Id) -> DomainResult<Value> {
        post(&self.h, &format!("{BASE}/operations"), apply_input(preview, request)?).await
    }
}

pub(crate) fn observe_input(request: Id, version: u64) -> Value {
    json!({"request_id":request,"configuration_version":version,"confirm_live":false})
}

pub(crate) fn preview_input(observation: &Value, change: Value, state_version: u64) -> DomainResult<Value> {
    Ok(json!({"request_id":Id::new(),
        "configuration_version":number(&observation["target"],"configurationVersion")?,
        "observation_id":identifier(observation,"id")?,"expected_state_version":state_version,"change":change}))
}

pub(crate) fn selection(policy: &Value) -> DomainResult<Value> {
    Ok(
        json!({"action":"publish","policies":[{"policy_id":identifier(policy,"id")?,"version":number(policy,"version")?}]}),
    )
}

pub(crate) fn apply_input(preview: &Value, request: Id) -> DomainResult<Value> {
    Ok(json!({"request_id":request,"preview_id":identifier(preview,"id")?,
        "expected_state_version":number(preview,"stateVersion")?,"confirm_apply":true,
        "confirm_upsert":true,"confirm_live":false,"confirm_unknown_overlap":false}))
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
    assert!(!value.to_string().contains(PRIVATE_REASON));
}

pub(crate) fn assert_private(value: &Value) {
    assert!(!value.to_string().contains(PRIVATE_REASON));
    match value {
        Value::Object(fields) => {
            for (field, value) in fields {
                assert!(
                    !matches!(
                        field.as_str(),
                        "content"
                            | "baseline"
                            | "desired"
                            | "private"
                            | "completion"
                            | "signature"
                            | "source"
                            | "secrets"
                            | "ciphertext_b64"
                            | "nonce_b64"
                            | "aad"
                            | "headers"
                            | "raw_body"
                    ),
                    "private content field exposed: {field}"
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

pub(crate) async fn key(h: &Harness, scopes: &[&str]) -> DomainResult<String> {
    let response =
        h.post("/api/v1/settings/api-keys", json!({"name":format!("owned-mse-{}",Id::new()),"scopes":scopes})).await;
    // Never echo an issuance response, which contains the fresh plaintext collector key.
    assert_eq!(response.status, StatusCode::CREATED);
    text(&response.json(), "plaintext")
}

pub(crate) fn for_tenant(mut h: Harness, tenant: TenantId) -> DomainResult<Harness> {
    let value: axum::http::HeaderValue = tenant
        .to_string()
        .parse()
        .map_err(|_| DomainError::Internal("owned tenant header could not be constructed".into()))?;
    h.tenant = tenant;
    h.app = build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
        request.headers_mut().insert("x-agf-tenant", value.clone());
        async move { request }
    }));
    Ok(h)
}

pub(crate) fn effective_live(mut h: Harness) -> DomainResult<Harness> {
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    let tenant = h.tenant;
    for_tenant(h, tenant)
}
