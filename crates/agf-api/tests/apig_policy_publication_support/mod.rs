//! Real API configuration and signed source records; provider effects use the owned encrypted Mock bridge.
use crate::common::*;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
    policy::Policy,
};

mod boundaries;
mod lifecycle;
mod records;
pub(crate) use records::{assert_package, configurations, external_edit, provider, snapshot, workflow_audits};

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
    pub(crate) async fn new() -> DomainResult<Self> {
        Self::with_harness(setup().await).await
    }
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
        self.prepare(&self.observe(true).await?).await
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
pub(crate) async fn key(h: &Harness, scopes: &[&str]) -> DomainResult<String> {
    let response =
        h.post("/api/v1/settings/api-keys", json!({"name":format!("owned-apig-{}",Id::new()),"scopes":scopes})).await;
    assert_eq!(response.status, StatusCode::CREATED);
    text(&response.json(), "plaintext")
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
