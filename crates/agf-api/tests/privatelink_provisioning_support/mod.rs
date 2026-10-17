//! Shared by provisioning, OpenAPI, managed admission and SQL binaries with different helper subsets.
#![allow(dead_code)]
use crate::common::*;
use agf_core::{
    credential::SecretMaterial,
    error::{DomainError, DomainResult},
    ids::Id,
};
use secrecy::ExposeSecret;
pub(crate) const BASE: &str = "/api/v1/alicloud/privatelink/provisioning";
pub(crate) const CONFIG: &str = "/api/v1/alicloud/connections/alicloud-privatelink";
pub(crate) const KINDS: [&str; 6] = [
    "privatelink-provisioning-state",
    "privatelink-provisioning-fact",
    "privatelink-provisioning-body",
    "privatelink-provisioning-pending",
    "privatelink-provisioning-mock",
    "cloud-integration",
];
pub(crate) fn error(s: &str) -> DomainError {
    DomainError::Internal(format!("owned PrivateLink test: {s}"))
}
pub(crate) fn n(v: &Value, k: &str) -> DomainResult<u64> {
    v[k].as_u64().ok_or_else(|| error("missing safe number"))
}
pub(crate) fn id(v: &Value, k: &str) -> DomainResult<Id> {
    serde_json::from_value(v[k].clone()).map_err(Into::into)
}
pub(crate) async fn get(h: &Harness, path: &str) -> DomainResult<Value> {
    let r = h.get(path).await;
    assert_eq!(r.status, StatusCode::OK, "safe GET status");
    serde_json::from_slice(&r.bytes).map_err(Into::into)
}
pub(crate) async fn post(h: &Harness, path: &str, body: Value) -> DomainResult<Value> {
    let r = h.post(path, body).await;
    assert_eq!(r.status, StatusCode::OK, "safe POST status");
    serde_json::from_slice(&r.bytes).map_err(Into::into)
}
pub(crate) async fn configure(h: &Harness, version: u64, enabled: bool, account: &str) -> DomainResult<()> {
    let r=h.request("PUT",CONFIG,Some(&h.admin),Some(json!({"expected_version":version,"enabled":enabled,"mock":true,"settings":{"region_id":"cn-hangzhou","endpoint_id":"ep-agf-demo","account_id":account},"secrets":{}}))).await;
    assert_eq!(r.status, StatusCode::OK);
    Ok(())
}
pub(crate) fn target() -> Value {
    json!({"region_id":"cn-hangzhou","service_region_id":"cn-hangzhou","service_id":"epsrv-agf-demo","vpc_id":"vpc-agf-demo","name":"AgfDemoEndpoint","zones":[{"zone_id":"cn-hangzhou-a","vswitch_id":"vsw-agf-demo"}],"security_group_ids":["sg-agf-demo"]})
}
pub(crate) async fn preview_body(h: &Harness, request: Id, selection: Value) -> DomainResult<Value> {
    let s = get(h, BASE).await?;
    Ok(
        json!({"request_id":request,"configuration_version":n(&s["source"],"configurationVersion")?,"expected_generation":n(&s,"generation")?,"selection":selection}),
    )
}
pub(crate) async fn preview(h: &Harness, selection: Value) -> DomainResult<Value> {
    post(h, &format!("{BASE}/preview"), preview_body(h, Id::new(), selection).await?).await
}
pub(crate) async fn apply_body(h: &Harness, preview: Id, request: Id, seed: bool) -> DomainResult<Value> {
    Ok(
        json!({"request_id":request,"preview_id":preview,"expected_generation":n(&get(h,BASE).await?,"generation")?,"confirm_resources_and_cost":true,"confirm_current_role":true,"confirm_no_connectivity_proof":true,"confirm_live":true,"initialize_mock_fixture":seed}),
    )
}
pub(crate) async fn created(h: &Harness, seed: bool) -> DomainResult<(Id, Value, Value)> {
    let p = preview(h, json!({"action":"create","target":target()})).await?;
    let request = Id::new();
    let input = apply_body(h, id(&p, "requestId")?, request, seed).await?;
    let r = post(h, &format!("{BASE}/apply"), input.clone()).await?;
    assert_eq!(r["result"]["delivery"], "acknowledged");
    Ok((request, input, r))
}
pub(crate) async fn observe(h: &Harness, original: Id) -> DomainResult<Value> {
    let s = get(h, BASE).await?;
    post(h,&format!("{BASE}/observe"),json!({"request_id":Id::new(),"configuration_version":n(&s["source"],"configurationVersion")?,"original_create_request_id":original,"confirm_live":true})).await
}
pub(crate) async fn imported(h: &Harness) -> DomainResult<Value> {
    let version = n(&get(h, BASE).await?["source"], "configurationVersion")?;
    let r = h
        .post(
            "/api/v1/alicloud/privatelink/inventory/sync",
            json!({"request_id":Id::new(),"configuration_version":version,"confirm_live":false}),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let state = get(h, BASE).await?;
    let scope = id(&state["inventorySelection"], "scopeId")?;
    post(
        h,
        &format!("{BASE}/observe"),
        json!({"request_id":Id::new(),"configuration_version":version,"inventory_scope_id":scope}),
    )
    .await
}
pub(crate) async fn snapshot(h: &Harness) -> DomainResult<Value> {
    let mut rows = BTreeMap::new();
    for kind in KINDS {
        rows.insert(kind, h.state.configurations.list::<Value>(h.tenant, kind).await?);
    }
    Ok(json!({"rows":rows,"audit":h.state.store.audit_chain_durable(h.tenant,0,i64::MAX).await?}))
}
pub(crate) fn clear(h: &Harness, row: &Value) -> DomainResult<Value> {
    let secret: SecretMaterial = serde_json::from_value(row["secret"].clone())?;
    let decoded = agf_api::model_gateway::cipher(&h.state)?.decrypt(&secret)?;
    let payload: Value = serde_json::from_str(decoded.expose_secret())?;
    Ok(payload["value"].clone())
}
pub(crate) async fn mock_counts(h: &Harness) -> DomainResult<(u64, u64)> {
    let rows = h.state.configurations.list::<Value>(h.tenant, "privatelink-provisioning-mock").await?;
    assert_eq!(rows.len(), 1);
    let row = clear(h, &rows[0])?;
    Ok((n(&row, "writes")?, n(&row, "reads")?))
}
pub(crate) async fn chain(h: &Harness) -> DomainResult<()> {
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    Ok(())
}
