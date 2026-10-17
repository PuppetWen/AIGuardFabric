//! API requests own the configuration and authentication; GET snapshots never initialize fixtures.
use crate::common::*;
use agf_core::{
    audit::{AuditAction, AuditLog, AuditOutcome},
    error::{DomainError, DomainResult},
    ids::Id,
};

mod live;
mod signature;
mod wire;

pub(crate) const NAME: &str = "alicloud-schedulerx3";
pub(crate) const BASE: &str = "/api/v1/alicloud/schedulerx3/native";
pub(crate) const CONFIG: &str = "/api/v1/alicloud/connections/alicloud-schedulerx3";
pub(crate) const KINDS: [&str; 7] = [
    "scheduler-native-state",
    "scheduler-native-fact",
    "scheduler-native-observation",
    "scheduler-native-bindings",
    "scheduler-native-driver-mock",
    "cloud-integration",
    "integration-operation",
];

pub(crate) fn number(value: &Value, field: &str) -> DomainResult<u64> {
    value[field].as_u64().ok_or_else(|| DomainError::Internal(format!("missing public numeric {field}")))
}
pub(crate) fn text(value: &Value, field: &str) -> DomainResult<String> {
    value[field]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| DomainError::Internal(format!("missing public text {field}")))
}
pub(crate) fn identifier(value: &Value, field: &str) -> DomainResult<Id> {
    serde_json::from_value(value[field].clone()).map_err(Into::into)
}
pub(crate) async fn read(h: &Harness, path: &str) -> DomainResult<Value> {
    let reply = h.get(path).await;
    assert_eq!(reply.status, StatusCode::OK, "owned GET status");
    serde_json::from_slice(&reply.bytes).map_err(Into::into)
}
pub(crate) async fn post(h: &Harness, path: &str, input: Value) -> DomainResult<Value> {
    let reply = h.post(path, input).await;
    assert_eq!(reply.status, StatusCode::OK, "owned POST status");
    serde_json::from_slice(&reply.bytes).map_err(Into::into)
}
pub(crate) async fn put(h: &Harness, input: Value) -> DomainResult<Value> {
    let reply = h.request("PUT", &format!("{BASE}/bindings"), Some(&h.admin), Some(input)).await;
    assert_eq!(reply.status, StatusCode::OK, "owned binding status");
    serde_json::from_slice(&reply.bytes).map_err(Into::into)
}
pub(crate) fn settings() -> Value {
    json!({"region_id":"cn-hangzhou","cluster_id":"cluster-agf-demo","app_name":"app-agf-demo",
        "account_id":"owned-scheduler-api-account"})
}
pub(crate) async fn configure(h: &Harness, version: u64, enabled: bool, settings: Value) -> DomainResult<()> {
    let reply = h
        .request(
            "PUT",
            CONFIG,
            Some(&h.admin),
            Some(json!({
                "expected_version":version,"enabled":enabled,"mock":true,"settings":settings,"secrets":{}
            })),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "owned source status");
    assert_eq!(reply.json()["version"], version + 1);
    let saved = agf_api::cloud_store::load(&h.state, h.tenant, NAME)
        .await?
        .ok_or_else(|| DomainError::Internal("HTTP source was not saved".into()))?;
    assert_eq!(saved.version, version + 1);
    Ok(())
}
pub(crate) fn observe_input(id: Id, version: u64, initialize: bool) -> Value {
    json!({"request_id":id,"configuration_version":version,"confirm_live":false,
        "initialize_mock_fixture":initialize})
}
pub(crate) fn receipt(id: Id) -> String {
    format!("{BASE}/observations/{id}")
}
pub(crate) async fn observed(h: &Harness) -> DomainResult<Value> {
    post(h, &format!("{BASE}/observe"), observe_input(Id::new(), 1, true)).await
}
pub(crate) async fn mock_harness() -> DomainResult<Harness> {
    let h = setup().await;
    configure(&h, 0, true, settings()).await?;
    Ok(h)
}
pub(crate) fn replace(id: Id, version: u64, observation: Id, kinds: &[(&str, &str)]) -> Value {
    json!({"action":"replace","request_id":id,"expected_version":version,"configuration_version":1,
        "observation_id":observation,"bindings":kinds.iter().map(|(kind,job)|
            json!({"kind":kind,"job_id":job})).collect::<Vec<_>>(),"confirm_local_only":true})
}
pub(crate) fn disable(id: Id, version: u64) -> Value {
    json!({"action":"disable","request_id":id,"expected_version":version})
}
pub(crate) async fn snapshot(h: &Harness) -> DomainResult<Value> {
    let mut values = BTreeMap::new();
    for kind in KINDS {
        values.insert(kind, h.state.configurations.list::<Value>(h.tenant, kind).await?);
    }
    Ok(json!({"configurations":values,"audit":h.state.store.audit_chain_durable(h.tenant,0,i64::MAX).await?}))
}
pub(crate) async fn records(h: &Harness, kind: &str) -> DomainResult<Vec<Value>> {
    h.state.configurations.list(h.tenant, kind).await
}
pub(crate) async fn audits(h: &Harness, id: Id, kind: &str) -> DomainResult<Vec<AuditLog>> {
    let id = id.to_string();
    Ok(h.state
        .store
        .audit_chain_durable(h.tenant, 0, i64::MAX)
        .await?
        .into_iter()
        .filter(|entry| entry.target.kind == kind && entry.target.id.as_deref() == Some(id.as_str()))
        .collect())
}
pub(crate) async fn assert_read_audit(h: &Harness, id: Id, outcome: AuditOutcome) -> DomainResult<()> {
    let entries = audits(h, id, "scheduler-native-observation").await?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].action, AuditAction::Read);
    assert_eq!(entries[0].outcome, outcome);
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    Ok(())
}
pub(crate) fn assert_safe(value: &Value) {
    for secret in [
        "SYNTHETIC-APP-TOKEN-DO-NOT-EXPOSE",
        "SYNTHETIC-CALLBACK-TOKEN",
        "SYNTHETIC-SCRIPT-BODY",
        "opaque-http-handler",
        "owned-provider-secret-diagnostic",
    ] {
        assert!(!value.to_string().contains(secret), "opaque provider value exposed");
    }
    match value {
        Value::Object(fields) => {
            for (key, child) in fields {
                assert!(
                    !matches!(
                        key.as_str(),
                        "AccessToken"
                            | "Parameters"
                            | "JobHandler"
                            | "Xattrs"
                            | "Script"
                            | "private"
                            | "secret"
                            | "ciphertext_b64"
                            | "nonce_b64"
                            | "aad"
                            | "headers"
                            | "raw_body"
                    ),
                    "private carrier key exposed"
                );
                assert_safe(child);
            }
        }
        Value::Array(children) => {
            for child in children {
                assert_safe(child);
            }
        }
        _ => {}
    }
}
pub(crate) async fn key(h: &Harness, scopes: &[&str]) -> DomainResult<(String, Id)> {
    let response = h
        .post(
            "/api/v1/settings/api-keys",
            json!({
        "name":format!("owned-scheduler-{}",Id::new()),"scopes":scopes}),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED);
    let value = response.json();
    Ok((text(&value, "plaintext")?, identifier(&value["api_key"], "id")?))
}
pub(crate) fn for_tenant(mut h: Harness, tenant: TenantId) -> DomainResult<Harness> {
    let header = tenant
        .to_string()
        .parse::<axum::http::HeaderValue>()
        .map_err(|_| DomainError::Internal("owned tenant header invalid".into()))?;
    h.tenant = tenant;
    h.app = build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
        request.headers_mut().insert("x-agf-tenant", header.clone());
        async move { request }
    }));
    Ok(h)
}
