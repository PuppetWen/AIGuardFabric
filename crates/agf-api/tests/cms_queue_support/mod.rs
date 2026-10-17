//! Shared by the router, OpenAPI and owned SQL binaries, each using a different helper subset.
#![allow(dead_code)]
use crate::common::*;
use agf_core::{
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::Id,
};
use secrecy::ExposeSecret;
pub(crate) const BASE: &str = "/api/v1/alicloud/cms/queue";
pub(crate) const CONFIG: &str = "/api/v1/alicloud/connections/alicloud-cms";
pub(crate) const KINDS: [&str; 8] = [
    "cms-queue-state",
    "cms-queue-item",
    "cms-queue-body",
    "cms-queue-attempt",
    "cms-queue-request",
    "cms-queue-pending",
    "cms-queue-mock",
    "cloud-integration",
];
pub(crate) fn number(value: &Value, key: &str) -> DomainResult<u64> {
    value[key].as_u64().ok_or_else(|| error("numeric DTO missing"))
}
pub(crate) fn id(value: &Value, key: &str) -> DomainResult<Id> {
    serde_json::from_value(value[key].clone()).map_err(Into::into)
}
pub(crate) fn error(message: &str) -> DomainError {
    DomainError::Internal(format!("owned CMS test: {message}"))
}
pub(crate) async fn get(h: &Harness, path: &str) -> DomainResult<Value> {
    let reply = h.get(path).await;
    assert_eq!(reply.status, StatusCode::OK, "CMS GET status");
    serde_json::from_slice(&reply.bytes).map_err(Into::into)
}
pub(crate) async fn post(h: &Harness, path: &str, body: Value) -> DomainResult<Value> {
    let reply = h.post(path, body).await;
    assert_eq!(reply.status, StatusCode::OK, "CMS POST status");
    serde_json::from_slice(&reply.bytes).map_err(Into::into)
}
pub(crate) async fn configure(h: &Harness, version: u64, enabled: bool) -> DomainResult<()> {
    let reply = h
        .request(
            "PUT",
            CONFIG,
            Some(&h.admin),
            Some(json!({"expected_version":version,"enabled":enabled,"mock":true,
        "settings":{"region_id":"cn-hangzhou","group_id":"agf-cms-demo"},"secrets":{}})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json()["version"], version + 1);
    Ok(())
}
pub(crate) fn payload() -> Value {
    json!({"kind":"event","name":"owned-queue-event","content":"owned-private-CMS-payload","at":agf_core::time::Timestamp::now()})
}
pub(crate) async fn enqueue(h: &Harness, request: Id, count: usize, seed: bool) -> DomainResult<Value> {
    let state = get(h, BASE).await?;
    post(h,&format!("{BASE}/enqueue"),json!({"request_id":request,"configuration_version":number(&state["source"],"configurationVersion")?,
        "expected_generation":number(&state,"generation")?,"items":(0..count).map(|_|payload()).collect::<Vec<_>>(),"initialize_mock_fixture":seed})).await
}
pub(crate) async fn send_input(h: &Harness, item: Id, request: Id) -> DomainResult<Value> {
    Ok(
        json!({"request_id":request,"expected_generation":number(&get(h,BASE).await?,"generation")?,"item_ids":[item],"confirm_live":false}),
    )
}
pub(crate) async fn snapshot(h: &Harness) -> DomainResult<Value> {
    let mut rows = BTreeMap::new();
    for kind in KINDS {
        rows.insert(kind, h.state.configurations.list::<Value>(h.tenant, kind).await?);
    }
    Ok(json!({"rows":rows,"audit":h.state.store.audit_chain_durable(h.tenant,0,i64::MAX).await?}))
}
pub(crate) fn clear(h: &Harness, envelope: &Value) -> DomainResult<Value> {
    let secret: SecretMaterial = serde_json::from_value(envelope["secret"].clone())?;
    let clear = agf_api::model_gateway::cipher(&h.state)?.decrypt(&secret)?;
    serde_json::from_str(clear.expose_secret()).map_err(Into::into)
}
pub(crate) async fn accepted(h: &Harness) -> DomainResult<(Id, Id, Value)> {
    let queued = enqueue(h, Id::new(), 1, true).await?;
    let item = serde_json::from_value(queued["itemIds"][0].clone())?;
    let request = Id::new();
    let body = send_input(h, item, request).await?;
    let receipt = post(h, &format!("{BASE}/send"), body).await?;
    assert_eq!(receipt["originalAttempts"][0]["outcome"]["delivery"], "accepted");
    assert_eq!(receipt["originalAttempts"][0]["providerWriteAttempted"], false);
    assert!(!receipt.to_string().contains("owned-private-CMS-payload"));
    Ok((item, request, receipt))
}
pub(crate) async fn key(h: &Harness, scopes: &[&str]) -> DomainResult<String> {
    let reply = h.post("/api/v1/settings/api-keys", json!({"name":"owned-cms-queue-key","scopes":scopes})).await;
    assert_eq!(reply.status, StatusCode::CREATED);
    reply.json()["plaintext"].as_str().map(str::to_owned).ok_or_else(|| error("synthetic Key missing"))
}
