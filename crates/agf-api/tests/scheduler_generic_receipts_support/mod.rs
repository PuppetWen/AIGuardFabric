//! Synthetic receipts and owned loopback configuration; no provider or filesystem secrets.
use crate::common::*;
use crate::integration_completion_support::{PENDING, RUNS, completion_audit, rows};
use agf_api::{cloud_runtime, integration_receipts::Run};
use agf_core::ids::{Id, deterministic_id};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};

pub(crate) const NAME: &str = "alicloud-schedulerx3";
pub(crate) const PATH: &str = "/api/v1/alicloud/connections/alicloud-schedulerx3";
pub(crate) const PRIVATE: &str = "OWNED-SCHEDULER-CALLBACK-TOKEN";
pub(crate) const OMITTED: &str = "Scheduler response details were omitted; inspect safe status and request identifiers";
pub(crate) const CARRIERS: &[&str] = &[
    "Parameters",
    "JobHandler",
    "Script",
    "XAttrs",
    "xattrs",
    "INSTANCE_PARAMETERS",
    "Result",
    "WorkAddr",
    "Executor",
    "ServerIp",
    "NoticeConfig",
    "NoticeContacts",
    "Label",
    "CleanMode",
    "Description",
    "AccessToken",
    "SecurityToken",
    "Authorization",
    "Headers",
    "Raw",
    "Payload",
];

pub(crate) fn request(action: &str) -> Value {
    let parameters = if action == "GetJobExecution" {
        json!({"ClusterId":"owned-cluster","AppName":"owned-app","JobExecutionId":"9007199254741002"})
    } else {
        json!({"ClusterId":"owned-cluster","AppName":"owned-app","PageNum":1,"PageSize":20})
    };
    json!({"request_id":Id::new(),"configuration_version":1,"action":action,
        "parameters":parameters,"confirm_live":true})
}

pub(crate) fn provider(action: &str) -> Value {
    let mut row = json!({
        "JobId":74,"JobExecutionId":"9007199254741002","Name":"owned job","JobName":"owned job",
        "AppName":"owned-app","Status":4,"TimeExpression":"0 0 12 * * ?",
        "ScheduleTime":"2026-10-01 00:00:00","Duration":10,
        "jobs":[{"Parameters":{"headers":{"Authorization":PRIVATE}},"Name":"owned child"}]
    });
    for carrier in CARRIERS {
        row[*carrier] = json!({"credential":PRIVATE,"nested":[{"token":PRIVATE}]});
    }
    row[PRIVATE] = json!(PRIVATE);
    let data =
        if action == "GetJobExecution" { row } else { json!({"Records":[row],"Total":1,"PageNumber":1,"PageSize":20}) };
    json!({"Code":200,"Success":true,"Message":PRIVATE,"RequestId":"owned-provider-request","Data":data})
}

pub(crate) fn result_row<'a>(result: &'a Value, action: &str) -> &'a Value {
    if action == "GetJobExecution" { &result["Data"] } else { &result["Data"]["Records"][0] }
}

pub(crate) fn assert_opaque(value: &Value, present: bool) {
    let fields = value.as_object().expect("carrier must be metadata, never raw content");
    assert_eq!(fields.len(), 3);
    assert_eq!(fields["opaque"], true);
    assert_eq!(fields["present"], present);
    if present {
        let digest = fields["sha256"].as_str().unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    } else {
        assert!(fields["sha256"].is_null());
    }
}

pub(crate) fn assert_safe(value: &Value) {
    let text = serde_json::to_string(value).unwrap();
    assert!(!text.contains(PRIVATE), "opaque carrier or field name escaped the safe projection");
    for forbidden in ["ciphertext_b64", "nonce_b64", "request_hash", "OWNED-SOURCE-SECRET"] {
        assert!(!text.contains(forbidden));
    }
}

pub(crate) fn assert_projected(value: &Value, action: &str) {
    assert_safe(value);
    let response = &value["receipt"]["response"];
    assert_eq!(response["Code"], 200);
    assert_eq!(response["Success"], true);
    assert_eq!(response["Message"], OMITTED);
    assert_eq!(response["RequestId"], "owned-provider-request");
    let row = result_row(response, action);
    assert_eq!(row["JobId"], 74);
    assert_eq!(row["JobExecutionId"], "9007199254741002");
    assert_eq!(row["Name"], "owned job");
    assert_eq!(row["TimeExpression"], "0 0 12 * * ?");
    for carrier in CARRIERS {
        assert_opaque(&row[*carrier], true);
    }
    assert_opaque(&row["jobs"][0]["Parameters"], true);
    assert!(row.get(PRIVATE).is_none());
    if action != "GetJobExecution" {
        assert_eq!(response["Data"]["Total"], 1);
        assert_eq!(response["Data"]["PageNumber"], 1);
        assert_eq!(response["Data"]["PageSize"], 20);
    }
}

pub(crate) async fn configure(h: &Harness, endpoint: &str, mocked: bool) {
    let reply = h.request("PUT", PATH, Some(&h.admin), Some(json!({
        "expected_version":0,"enabled":true,"mock":mocked,
        "settings":{"endpoint":endpoint,"region_id":"cn-hangzhou","cluster_id":"owned-cluster","app_name":"owned-app"},
        "secrets":{"access_key_id":"OWNED-SOURCE-ID","access_key_secret":"OWNED-SOURCE-SECRET"}
    }))).await;
    assert_eq!(reply.status, StatusCode::OK);
}

pub(crate) fn claim(h: &Harness, adapter: &str, action: &str, body: &Value) -> Run {
    let request: cloud_runtime::Request = serde_json::from_value(body.clone()).unwrap();
    Run {
        id: deterministic_id("agf.integration.run", &format!("{}:{adapter}:{}", h.tenant, request.request_id)),
        request_id: request.request_id,
        adapter: adapter.into(),
        operation: action.into(),
        configuration_version: request.configuration_version,
        request_hash: format!("{:x}", Sha256::digest(serde_json::to_vec(&request).unwrap())),
        actor: "owned-original-scheduler-actor".into(),
        started_at: Timestamp::now(),
        finished_at: None,
        status: "started".into(),
        mocked: false,
        result: None,
    }
}

pub(crate) async fn seed(
    h: &Harness,
    adapter: &str,
    action: &str,
    status: &str,
    receipt: Value,
    pending: bool,
) -> (Run, Value) {
    let body = request(action);
    let initial = claim(h, adapter, action, &body);
    let mut terminal = initial.clone();
    terminal.status = status.into();
    terminal.finished_at = Some(Timestamp::now());
    terminal.result =
        Some(agf_api::model_gateway::encrypt(&h.state, h.tenant, initial.id, receipt.to_string()).unwrap());
    if pending {
        let audit = completion_audit(h, &terminal);
        h.state.configurations.put(h.tenant, RUNS, initial.id, &initial).await.unwrap();
        h.state
            .configurations
            .put(h.tenant, PENDING, initial.id, &json!({"run":terminal,"audit":audit}))
            .await
            .unwrap();
    } else {
        h.state.configurations.put(h.tenant, RUNS, initial.id, &terminal).await.unwrap();
    }
    (terminal, body)
}

pub(crate) fn receipt_path(id: Id) -> String {
    format!("{PATH}/operations/{id}")
}

pub(crate) async fn decrypted(h: &Harness, id: Id) -> Value {
    let run = h.state.configurations.get::<Run>(h.tenant, RUNS, id).await.unwrap().unwrap();
    let text = agf_api::model_gateway::cipher(&h.state).unwrap().decrypt(run.result.as_ref().unwrap()).unwrap();
    serde_json::from_str(text.expose_secret()).unwrap()
}

pub(crate) async fn snapshot(h: &Harness) -> String {
    let audit = h.state.store.audit_chain_durable(h.tenant, 0, i64::MAX).await.unwrap();
    let state = json!({"runs":rows(h,RUNS).await,"pending":rows(h,PENDING).await,
        "connections":rows(h,"cloud-integration").await,"audit":audit});
    format!("{:x}", Sha256::digest(serde_json::to_vec(&state).unwrap()))
}
