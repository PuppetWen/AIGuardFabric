//! Independent policy fixtures inspect the authoritative signed registry, not its projection.
#![allow(dead_code)]
use crate::common::*;
use agf_core::{audit::AuditLog, ids::Id};

pub(crate) mod loopback;

pub(crate) const POLICIES: &str = "/api/v1/policies";
pub(crate) const KIND: &str = "signed-policy-registry";

pub(crate) fn body(name: &str, action: &str, version: Option<u64>) -> Value {
    let mut value = json!({"name":name,"language":"cel",
        "source":json!({"action":action,"reason":"owned policy publication"}).to_string(),
        "action":action,"enabled":true,"priority":1,"intercept_points":["ai-gateway","mcp-proxy"]});
    if let Some(version) = version {
        value["expected_version"] = json!(version);
    }
    value
}

pub(crate) fn id(policy: &Value) -> Id {
    serde_json::from_value(policy["id"].clone()).unwrap()
}
pub(crate) fn path(id: Id) -> String {
    format!("{POLICIES}/{id}")
}
pub(crate) fn restore_path(id: Id, version: u64) -> String {
    format!("{POLICIES}/{id}/versions/{version}/restore")
}

pub(crate) async fn create(h: &Harness, name: &str, action: &str) -> Value {
    let response = h.post(POLICIES, body(name, action, Some(0))).await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
    let value = response.json()["policy"].clone();
    assert_eq!(value["version"], 1);
    assert_signed(h, &value);
    value
}

pub(crate) async fn update(h: &Harness, policy: &Value, action: &str) -> Resp {
    h.request(
        "PUT",
        &path(id(policy)),
        Some(&h.admin),
        Some(body(policy["name"].as_str().unwrap(), action, policy["version"].as_u64())),
    )
    .await
}

pub(crate) async fn restore(h: &Harness, policy: &Value, version: u64) -> Resp {
    h.post(&restore_path(id(policy), version), json!({"version":version,"expected_version":policy["version"]})).await
}

pub(crate) fn assert_signed(h: &Harness, value: &Value) {
    let policy: agf_core::policy::Policy = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(policy.tenant_id, h.tenant);
    assert_eq!(policy.content_hash, policy.compute_hash());
    agf_api::policy_store::signer(&h.state).unwrap().verify(&policy).unwrap();
}

pub(crate) async fn registry(h: &Harness) -> Value {
    h.state
        .configurations
        .get::<Value>(h.tenant, KIND, agf_api::model_routes::tenant_record_id(h.tenant))
        .await
        .unwrap()
        .unwrap()
}

pub(crate) async fn replace_registry(h: &Harness, value: &Value) {
    h.state.configurations.put(h.tenant, KIND, agf_api::model_routes::tenant_record_id(h.tenant), value).await.unwrap();
}

pub(crate) async fn history(h: &Harness, policy: Id) -> Value {
    let response = h.get(&format!("{}/versions", path(policy))).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    response.json()
}

pub(crate) async fn policy_audits(h: &Harness) -> Vec<AuditLog> {
    h.state
        .store
        .audit_chain_durable(h.tenant, 0, i64::MAX)
        .await
        .unwrap()
        .into_iter()
        .filter(|entry| entry.target.kind == "policy")
        .collect()
}

pub(crate) async fn successes(h: &Harness, policy: Id, action: &str) -> usize {
    policy_audits(h)
        .await
        .into_iter()
        .filter(|entry| {
            entry.target.id.as_deref() == Some(policy.to_string().as_str())
                && entry.action.as_str() == action
                && entry.outcome == agf_core::audit::AuditOutcome::Success
        })
        .count()
}

pub(crate) async fn intact_chain(h: &Harness) {
    assert!(h.state.store.audit_verify_durable(h.tenant).await.unwrap().passed);
}

pub(crate) fn live(mut h: Harness) -> Harness {
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    let tenant = h.tenant;
    h.app = build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
        request.headers_mut().insert("x-agf-tenant", tenant.to_string().parse().unwrap());
        async move { request }
    }));
    h
}
