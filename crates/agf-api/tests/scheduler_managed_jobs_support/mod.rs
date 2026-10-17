//! Small route fixture without importing another target's tests or provider.
use crate::common::*;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use sha2::{Digest, Sha256};
pub(crate) const BASE: &str = "/api/v1/alicloud/schedulerx3/native/jobs";
pub(crate) const NATIVE: &str = "/api/v1/alicloud/schedulerx3/native";
pub(crate) const CONFIG: &str = "/api/v1/alicloud/connections/alicloud-schedulerx3";
pub(crate) fn id(value: &Value, key: &str) -> DomainResult<Id> {
    serde_json::from_value(value[key].clone()).map_err(Into::into)
}
pub(crate) fn number(value: &Value, key: &str) -> DomainResult<u64> {
    value[key].as_u64().ok_or_else(|| DomainError::Internal("owned DTO number absent".into()))
}
pub(crate) async fn get(h: &Harness, path: &str) -> DomainResult<Value> {
    let reply = h.get(path).await;
    assert_eq!(reply.status, StatusCode::OK, "owned GET status");
    Ok(reply.json())
}
pub(crate) async fn post(h: &Harness, path: &str, body: Value) -> DomainResult<Value> {
    let reply = h.post(path, body).await;
    assert_eq!(reply.status, StatusCode::OK, "owned POST status");
    Ok(reply.json())
}
pub(crate) async fn config(h: &Harness, version: u64, enabled: bool) -> DomainResult<()> {
    let reply = h
        .request(
            "PUT",
            CONFIG,
            Some(&h.admin),
            Some(json!({"expected_version":version,"enabled":enabled,"mock":true,
        "settings":{"region_id":"cn-hangzhou","cluster_id":"cluster-agf-demo","app_name":"app-agf-demo",
            "account_id":"owned-managed-scheduler-account"},"secrets":{}})),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "owned source save status");
    assert_eq!(reply.json()["version"], version + 1);
    Ok(())
}
pub(crate) async fn observe(h: &Harness) -> DomainResult<Value> {
    post(
        h,
        &format!("{NATIVE}/observe"),
        json!({"request_id":Id::new(),"configuration_version":1,
        "initialize_mock_fixture":true,"confirm_live":false}),
    )
    .await
}
pub(crate) fn create(kind: &str) -> Value {
    json!({"action":"create_disabled","declaration":{"kind":kind,"name":format!("owned-{kind}"),"total":1,
        "schedule":{"time_type":1,"time_expression":"0 0/5 * * * ?","timezone":"UTC","calendar":"",
            "max_attempt":0,"attempt_interval":0}}})
}
pub(crate) async fn input(
    h: &Harness,
    observed: &Value,
    change: Value,
    job: Option<&str>,
    request: Id,
) -> DomainResult<Value> {
    let state = get(h, BASE).await?;
    let mut input = json!({"request_id":request,"configuration_version":1,"expected_binding_version":number(&state,"bindingVersion")?,
        "observation_id":id(observed,"requestId")?,"change":change});
    if let Some(job) = job {
        input["selection"] = json!({"kind":"report","app_id":observed["appId"],"job_id":job,
        "observation_fingerprint":observed["fingerprint"]});
    }
    Ok(input)
}
pub(crate) async fn preview(h: &Harness, observed: &Value, change: Value, job: Option<&str>) -> DomainResult<Value> {
    post(h, &format!("{BASE}/previews"), input(h, observed, change, job, Id::new()).await?).await
}
pub(crate) fn apply_input(preview: &Value) -> Value {
    json!({"preview_id":preview["id"],"preview_fingerprint":preview["fingerprint"],
        "confirm_no_cloud_cas":true,"confirm_callback_unknown":true,"confirm_live":false,"confirm_unknown_overlap":false})
}
pub(crate) fn receipt(id: Id) -> String {
    format!("{BASE}/operations/{id}")
}
pub(crate) async fn apply(h: &Harness, preview: &Value, id: Id) -> DomainResult<Value> {
    let reply = h.request("PUT", &receipt(id), Some(&h.admin), Some(apply_input(preview))).await;
    assert_eq!(reply.status, StatusCode::OK, "owned single apply status: {}", reply.text);
    Ok(reply.json())
}
pub(crate) async fn digest(h: &Harness) -> DomainResult<String> {
    let mut records = BTreeMap::new();
    for kind in [
        "cloud-integration",
        "scheduler-native-state",
        "scheduler-native-fact",
        "scheduler-native-observation",
        "scheduler-native-bindings",
        "scheduler-native-driver-mock",
        "scheduler-managed-job-state",
        "scheduler-managed-job-preview",
        "scheduler-managed-job-operation",
        "scheduler-managed-job-request",
        "scheduler-managed-job-pending",
        "integration-operation",
    ] {
        records.insert(kind, h.state.configurations.list::<Value>(h.tenant, kind).await?);
    }
    let value = json!({"records":records,"audit":h.state.store.audit_chain_durable(h.tenant,0,i64::MAX).await?});
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&value)?)))
}
pub(crate) async fn terminal_count(h: &Harness, id: Id) -> DomainResult<usize> {
    Ok(h.state
        .store
        .audit_chain_durable(h.tenant, 0, i64::MAX)
        .await?
        .iter()
        .filter(|a| {
            a.target.kind == "scheduler-managed-job"
                && a.target.id.as_deref() == Some(id.to_string().as_str())
                && a.action == agf_core::audit::AuditAction::Execute
        })
        .count())
}
pub(crate) fn safe(value: &Value) {
    let serialized = value.to_string();
    for forbidden in [
        "SYNTHETIC-APP-TOKEN-DO-NOT-EXPOSE",
        "SYNTHETIC-CALLBACK-TOKEN",
        "opaque-http-handler",
        "SYNTHETIC-SCRIPT-BODY",
        "ciphertext_b64",
        "nonce_b64",
        "AccessToken",
        "JobHandler",
        "Parameters",
    ] {
        assert!(!serialized.contains(forbidden), "opaque provider/private material appeared");
    }
}
