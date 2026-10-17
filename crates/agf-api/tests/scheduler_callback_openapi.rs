//! Public service contract and actual fail-closed authentication/body boundaries.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::ids::Id;
use common::*;

const ROOT: &str = "/api/v1/alicloud/schedulerx3/native/callback-executions";

fn refs(document: &Value, value: &Value) {
    match value {
        Value::Object(fields) => {
            if let Some(reference) = fields.get("$ref").and_then(Value::as_str) {
                assert!(
                    document.pointer(reference.strip_prefix('#').unwrap()).is_some(),
                    "unresolved contract reference"
                );
            }
            fields.values().for_each(|value| refs(document, value));
        }
        Value::Array(items) => items.iter().for_each(|value| refs(document, value)),
        _ => {}
    }
}

#[tokio::test]
async fn five_service_operations_document_current_task_grants_and_distinct_unique_start_permission() {
    let h = setup().await;
    let document = h.get("/api/v1/openapi.json").await.json();
    let routes =
        document["paths"].as_object().unwrap().iter().filter(|(path, _)| path.starts_with(ROOT)).collect::<Vec<_>>();
    assert_eq!(routes.len(), 5);
    let mut operations = 0;
    for (_, item) in routes {
        for method in ["get", "post"] {
            let Some(operation) = item.get(method) else { continue };
            operations += 1;
            assert_eq!(operation["security"], json!([{"apiKey":[]}]));
            assert_eq!(operation["x-required-permissions"], json!(["alicloud:read"]));
            assert_eq!(
                operation["x-task-permissions"],
                json!({
                    "asset-inventory":["assets:read"],"log-pull":["sources:read","sources:write"],
                    "redteam-cruise":["redteam:read","redteam:execute"],
                    "rule-hot-reload":["policies:write"],"report":["reports:write"],"archive":["reports:write"]
                })
            );
            assert!(
                operation["parameters"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|field| field["name"] == "X-AGF-Tenant" && field["required"] == true)
            );
            refs(&document, operation);
        }
    }
    assert_eq!(operations, 5);
    let schemas = &document["components"]["schemas"];
    for name in [
        "SchedulerCallbackAdmissionInput",
        "SchedulerCallbackStartInput",
        "SchedulerCallbackCompleteInput",
        "SchedulerCallbackArtifactDigest",
        "SchedulerCallbackOutcome",
        "SchedulerCallbackExecution",
    ] {
        let schema = &schemas[name];
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["required"].as_array().unwrap().len(), schema["properties"].as_object().unwrap().len());
        refs(&document, schema);
    }
    let execution = &schemas["SchedulerCallbackExecution"]["properties"];
    assert_eq!(execution["mayConfirmStart"]["type"], "boolean");
    assert_eq!(execution["mayExecute"]["type"], "boolean");
    assert!(execution.get("startedAt").is_some() && execution.get("executionLeaseExpiresAt").is_some());
    for private in ["note", "path", "token", "callbackToken", "authenticated", "raw", "headers", "ownerKeyId"] {
        assert!(execution.get(private).is_none());
        assert!(schemas["SchedulerCallbackOutcome"]["properties"].get(private).is_none());
    }
    assert_eq!(schemas["SchedulerCallbackOutcome"]["properties"]["artifacts"]["maxItems"], 64);
}

fn admission() -> Value {
    json!({"request_id":Id::new(),"kind":"asset-inventory","app_id":"123","job_id":"42",
        "job_execution_id":"original-42","partition_index":0,"partition_total":1,
        "binding_version":1,"configuration_version":1,"source_fingerprint":"a".repeat(64)})
}

#[tokio::test]
async fn user_jwt_and_memory_mode_cannot_claim_execute_or_initialize_a_cloud_task() {
    let h = setup().await;
    assert_eq!(h.request("POST", ROOT, None, Some(admission())).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(h.request("POST", ROOT, Some(&h.admin), Some(admission())).await.status, StatusCode::FORBIDDEN);
    let created = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":"owned callback contract",
        "scopes":["alicloud:read","assets:read"]}),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let value = created.json();
    let key = value["plaintext"].as_str().unwrap();
    assert_eq!(h.request("POST", ROOT, Some(key), Some(admission())).await.status, StatusCode::PRECONDITION_FAILED);
    let id = Id::new();
    for (method, path, body) in [
        ("GET", format!("{ROOT}/{id}"), None),
        ("GET", format!("{ROOT}/requests/{id}"), None),
        ("POST", format!("{ROOT}/{id}/validate"), Some(json!({"claim_id":Id::new()}))),
        (
            "POST",
            format!("{ROOT}/{id}/complete"),
            Some(json!({"claim_id":Id::new(),
            "outcome":{"ok":true,"skipped":false,"degraded":false,"artifacts":[]}})),
        ),
    ] {
        assert_eq!(h.request(method, &path, Some(key), body).await.status, StatusCode::PRECONDITION_FAILED);
    }
    for kind in [
        "scheduler-native-callback-execution",
        "scheduler-native-callback-batch",
        "scheduler-native-callback-progress",
        "scheduler-native-callback-pending",
        "scheduler-native-callback-request",
    ] {
        assert!(h.state.configurations.list::<Value>(h.tenant, kind).await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn private_flags_unknown_fields_and_oversized_bodies_are_rejected_before_service_admission() {
    let h = setup().await;
    for field in ["authenticated", "callback_token", "owner_key_id", "job_handler", "parameters"] {
        let mut body = admission();
        body[field] = json!(true);
        assert_eq!(h.request("POST", ROOT, Some(&h.admin), Some(body)).await.status, StatusCode::BAD_REQUEST);
    }
    let mut body = admission();
    body["job_execution_id"] = json!("x".repeat(70_000));
    assert_eq!(h.request("POST", ROOT, Some(&h.admin), Some(body)).await.status, StatusCode::PAYLOAD_TOO_LARGE);
}
