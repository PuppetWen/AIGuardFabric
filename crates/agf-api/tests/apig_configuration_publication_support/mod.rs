//! Public HTTP fixture. Only an explicitly initialized encrypted synthetic provider is used.
//! Three distinct targets reuse different subsets; behavioral assertions remain in those targets.
#![allow(dead_code)]
use crate::common::*;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};

pub(crate) const BASE: &str = "/api/v1/alicloud/apig/configuration-publication";
pub(crate) const CONFIG: &str = "/api/v1/alicloud/connections/alicloud-apig";
pub(crate) const MAIN: &str = "apig-configuration-publication-state";
pub(crate) const FACT: &str = "apig-configuration-publication-fact";
pub(crate) const PENDING: &str = "apig-configuration-publication-pending";
pub(crate) const MOCK: &str = "apig-configuration-driver-mock";

pub(crate) fn settings(kind: &str) -> Value {
    json!({"region_id":"cn-hangzhou","account_id":"owned-configuration-account",
        "configuration_kind":kind,"configuration_http_api_id":"api-owned",
        "configuration_gateway_id":"gw-owned","configuration_environment_id":"env-owned",
        "configuration_attachment_id":"pa-owned","configuration_plugin_id":"pl-owned",
        "configuration_class_id":"cls-owned","configuration_class_version":"1.0.0",
        "managed_configuration_confirmed":true})
}
pub(crate) async fn configure(h: &Harness, version: u64, enabled: bool, settings: Value) -> DomainResult<Value> {
    let r = h
        .request(
            "PUT",
            CONFIG,
            Some(&h.admin),
            Some(json!({"expected_version":version,
        "enabled":enabled,"mock":true,"settings":settings,"secrets":{}})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    Ok(r.json())
}
pub(crate) async fn get(h: &Harness, path: &str) -> DomainResult<Value> {
    let r = h.get(path).await;
    assert_eq!(r.status, StatusCode::OK, "{path}: {}", r.text);
    Ok(r.json())
}
pub(crate) async fn post(h: &Harness, path: &str, body: Value) -> DomainResult<Value> {
    let r = h.post(path, body).await;
    assert_eq!(r.status, StatusCode::OK, "{path}: {}", r.text);
    Ok(r.json())
}
pub(crate) fn num(v: &Value, k: &str) -> DomainResult<u64> {
    v[k].as_u64().ok_or_else(|| DomainError::Internal(format!("missing safe number {k}")))
}
pub(crate) fn id(v: &Value, k: &str) -> DomainResult<Id> {
    Ok(serde_json::from_value(v[k].clone())?)
}
pub(crate) fn receipt(id: Id) -> String {
    format!("{BASE}/operations/{id}")
}
pub(crate) fn change(kind: &str) -> Value {
    if kind == "content" {
        json!({"action":"content","settings":{"enabled":true,"checkRequest":true,"checkResponse":true,"denyCode":451}})
    } else {
        json!({"action":"models","services":[
        {"serviceId":"svc-one","version":"r1","expectedModelName":"observed-one","modelName":"observed-one","weight":25},
        {"serviceId":"svc-two","version":"r2","expectedModelName":"observed-two","modelName":"observed-two","weight":75}]})
    }
}
pub(crate) async fn observe(h: &Harness, initialize: bool) -> DomainResult<Value> {
    let s = get(h, BASE).await?;
    post(
        h,
        &format!("{BASE}/observe"),
        json!({"request_id":Id::new(),"configuration_version":num(&s["binding"],"configurationVersion")?,
        "confirm_live":false,"initialize_mock_fixture":initialize}),
    )
    .await
}
pub(crate) async fn preview(h: &Harness, o: &Value, change: Value) -> DomainResult<Value> {
    let s = get(h, BASE).await?;
    post(
        h,
        &format!("{BASE}/previews"),
        json!({"request_id":Id::new(),"configuration_version":num(&o["target"],"configurationVersion")?,
        "observation_id":id(o,"id")?,"expected_state_version":num(&s,"stateVersion")?,"change":change}),
    )
    .await
}
pub(crate) fn apply_body(p: &Value, request: Id) -> DomainResult<Value> {
    Ok(json!({"request_id":request,"preview_id":id(p,"id")?,"expected_state_version":num(p,"stateVersion")?,
        "confirm_apply":true,"confirm_preserved_private_configuration":true,"confirm_streaming_or_shared_impact":true,
        "confirm_no_cloud_cas":true,"confirm_live":false,"confirm_unknown_overlap":false}))
}
pub(crate) async fn apply(h: &Harness, p: &Value, request: Id) -> DomainResult<Value> {
    post(h, &format!("{BASE}/operations"), apply_body(p, request)?).await
}
pub(crate) async fn ready(h: &Harness, kind: &str) -> DomainResult<Value> {
    preview(h, &observe(h, true).await?, change(kind)).await
}
pub(crate) async fn archive(h: &Harness, request: Id) -> DomainResult<Value> {
    post(
        h,
        &format!("{BASE}/operations/archive"),
        json!({"expected_generation":num(&get(h,BASE).await?,"generation")?,"request_ids":[request]}),
    )
    .await
}
pub(crate) fn safe(v: &Value) {
    let text = v.to_string();
    for secret in [
        "synthetic-content-key",
        "synthetic-content-secret",
        "synthetic-auth-marker",
        "preserve-secret-condition",
        "synthetic-backend-secret",
        "leave-other-env-alone",
    ] {
        assert!(!text.contains(secret));
    }
    match v {
        Value::Object(o) => {
            for (k, v) in o {
                assert!(
                    ![
                        "raw",
                        "headers",
                        "pluginConfig",
                        "deployConfigs",
                        "authConfig",
                        "body",
                        "secrets",
                        "ciphertext_b64",
                        "nonce_b64",
                        "aad"
                    ]
                    .contains(&k.as_str())
                );
                safe(v);
            }
        }
        Value::Array(a) => {
            for v in a {
                safe(v);
            }
        }
        _ => {}
    }
}
pub(crate) fn verified(v: &Value) {
    assert_eq!(v["status"], "verified");
    assert_eq!(v["cloudWrite"]["status"], "accepted");
    assert_eq!(v["readback"]["status"], "matched");
    assert_eq!(v["localPublication"]["status"], "published");
    assert_eq!(v["configurationObserved"], true);
    assert_eq!(v["deploymentVerified"], Value::Null);
    assert_eq!(v["consumerApplied"], Value::Null);
    safe(v);
}
pub(crate) async fn snapshot(h: &Harness) -> DomainResult<Value> {
    let mut rows = BTreeMap::new();
    for kind in [
        MAIN,
        FACT,
        PENDING,
        MOCK,
        "apig-configuration-publication-detail",
        "apig-configuration-publication-preview",
        "cloud-integration",
        "integration-operation",
    ] {
        let mut values = h.state.configurations.list::<Value>(h.tenant, kind).await?;
        values.sort_by_key(Value::to_string);
        rows.insert(kind, values);
    }
    Ok(json!({"rows":rows,"audit":h.state.store.audit_chain_durable(h.tenant,0,i64::MAX).await?}))
}
pub(crate) async fn terminal_count(h: &Harness, request: Id) -> DomainResult<usize> {
    Ok(h.state
        .store
        .audit_chain_durable(h.tenant, 0, i64::MAX)
        .await?
        .iter()
        .filter(|a| {
            a.target.kind == "apig-configuration-publication"
                && a.target.id.as_deref() == Some(request.to_string().as_str())
                && a.action == agf_core::audit::AuditAction::Execute
        })
        .count())
}
