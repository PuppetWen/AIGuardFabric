//! The public OpenAPI must match real local responses and distinguish provider evidence from deployment.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::ids::Id;
use common::*;

const ROOT: &str = "/api/v1/alicloud/schedulerx3/native";

fn type_matches(kind: &str, value: &Value) -> bool {
    match kind {
        "null" => value.is_null(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "integer" => value.is_i64() || value.is_u64(),
        _ => panic!("unsupported OpenAPI type {kind}"),
    }
}

fn assert_shape(document: &Value, rule: &Value, value: &Value) {
    if let Some(reference) = rule["$ref"].as_str() {
        return assert_shape(document, document.pointer(reference.strip_prefix('#').unwrap()).unwrap(), value);
    }
    if let Some(alternatives) = rule["oneOf"].as_array() {
        let selected = alternatives
            .iter()
            .find(|rule| if value.is_null() { rule["type"] == "null" } else { rule["type"] != "null" })
            .unwrap();
        return assert_shape(document, selected, value);
    }
    if let Some(constant) = rule.get("const") {
        assert_eq!(constant, value);
    }
    if let Some(choices) = rule["enum"].as_array() {
        assert!(choices.contains(value), "undocumented value {value}");
    }
    if let Some(kind) = rule["type"].as_str() {
        assert!(type_matches(kind, value), "type {kind} differs for {value}");
    } else if let Some(kinds) = rule["type"].as_array() {
        assert!(kinds.iter().any(|kind| type_matches(kind.as_str().unwrap(), value)), "nullable type differs");
    }
    if let Some(fields) = value.as_object() {
        if let Some(required) = rule["required"].as_array() {
            for key in required {
                assert!(fields.contains_key(key.as_str().unwrap()), "missing {key}");
            }
        }
        for (key, field) in fields {
            if let Some(property) = rule["properties"].get(key) {
                assert_shape(document, property, field);
            } else {
                assert_ne!(rule["additionalProperties"], false, "undocumented response field {key}");
            }
        }
    }
    if let Some(items) = value.as_array() {
        if let Some(max) = rule["maxItems"].as_u64() {
            assert!(items.len() as u64 <= max);
        }
        for item in items {
            assert_shape(document, &rule["items"], item);
        }
    }
}
fn assert_refs(document: &Value, value: &Value) {
    match value {
        Value::Object(fields) => {
            if let Some(reference) = fields.get("$ref").and_then(Value::as_str) {
                assert!(document.pointer(reference.strip_prefix('#').unwrap()).is_some(), "missing {reference}");
            }
            for child in fields.values() {
                assert_refs(document, child);
            }
        }
        Value::Array(values) => {
            for child in values {
                assert_refs(document, child);
            }
        }
        _ => {}
    }
}
fn schema<'a>(document: &'a Value, name: &str) -> &'a Value {
    &document["components"]["schemas"][name]
}

#[tokio::test]
async fn five_observation_operations_have_current_grants_resolvable_refs_and_strict_tagged_inputs() {
    let h = setup().await;
    let document = h.get("/api/v1/openapi.json").await.json();
    let paths = document["paths"].as_object().unwrap();
    // 同一 native 前缀还有任务管理及 callback 端点；它们有各自不同的权限合同。
    let observation_paths = ["", "/observe", "/observations/{id}", "/bindings", "/observations/archive"]
        .map(|suffix| format!("{ROOT}{suffix}"));
    let routes = paths.iter().filter(|(path, _)| observation_paths.contains(path)).collect::<Vec<_>>();
    assert_eq!(routes.len(), 5);
    let mut count = 0;
    for (_, item) in routes {
        for method in ["get", "post", "put"] {
            let Some(operation) = item.get(method) else { continue };
            count += 1;
            assert_eq!(operation["x-required-permissions"][0], "alicloud:read");
            assert_refs(&document, operation);
            assert!(operation["security"].as_array().unwrap().len() >= 2);
            assert!(operation["responses"].get("501").is_none());
        }
    }
    assert_eq!(count, 5);
    let observe = &document["paths"][format!("{ROOT}/observe")]["post"];
    assert_eq!(observe["x-required-permissions"], json!(["alicloud:read"]));
    assert_eq!(
        observe["x-conditional-permissions"]["initialize_mock_fixture=true"],
        json!(["alicloud:read", "alicloud:write"])
    );
    let union = schema(&document, "SchedulerNativeBindingInput")["oneOf"].as_array().unwrap();
    assert_eq!(union.len(), 2);
    assert!(union.iter().all(|row| row["additionalProperties"] == false));
    assert_eq!(union[0]["properties"]["action"]["const"], "replace");
    assert_eq!(union[1]["properties"]["action"]["const"], "disable");
    assert!(union[1]["properties"].get("configuration_version").is_none());
}

#[tokio::test]
async fn actual_unknown_observed_paged_and_archived_dtos_conform_to_the_public_schemas() {
    let h = setup().await;
    let document = h.get("/api/v1/openapi.json").await.json();
    let unknown = h.get(ROOT).await;
    assert_eq!(unknown.status, StatusCode::OK, "{}", unknown.text);
    assert!(unknown.json()["latestObservation"].is_null());
    assert_shape(&document, schema(&document, "SchedulerNativeState"), &unknown.json());
    let saved = h
        .request(
            "PUT",
            "/api/v1/alicloud/connections/alicloud-schedulerx3",
            Some(&h.admin),
            Some(json!({
                "expected_version":0,"enabled":true,"mock":true,
                "settings":{"region_id":"cn-hangzhou","cluster_id":"cluster-agf-demo","app_name":"app-agf-demo"}
            })),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let id = Id::new();
    let observed = h
        .post(
            &format!("{ROOT}/observe"),
            json!({
                "request_id":id,"configuration_version":1,"initialize_mock_fixture":true
            }),
        )
        .await;
    assert_eq!(observed.status, StatusCode::OK, "{}", observed.text);
    assert_shape(&document, schema(&document, "SchedulerNativeReceipt"), &observed.json());
    assert_eq!(observed.json()["total"], 6);
    let page = h.get(&format!("{ROOT}/observations/{id}?page=2&page_size=2")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text);
    assert_shape(&document, schema(&document, "SchedulerNativeReceipt"), &page.json());
    assert_eq!(page.json()["observation"]["jobs"].as_array().unwrap().len(), 2);
    let adopted = h
        .request(
            "PUT",
            &format!("{ROOT}/bindings"),
            Some(&h.admin),
            Some(json!({
                "action":"replace","request_id":Id::new(),"expected_version":0,"configuration_version":1,
                "observation_id":id,"bindings":[{"kind":"report","job_id":"9007199254741002"}],"confirm_local_only":true
            })),
        )
        .await;
    assert_eq!(adopted.status, StatusCode::OK, "{}", adopted.text);
    assert_shape(&document, schema(&document, "SchedulerNativeBinding"), &adopted.json());
    assert_eq!(adopted.json()["items"][0]["eligibility"], "eligible");
    let state = h.get(ROOT).await.json();
    assert_shape(&document, schema(&document, "SchedulerNativeState"), &state);
    let archived = h
        .post(
            &format!("{ROOT}/observations/archive"),
            json!({
                "expected_generation":state["generation"],"request_ids":[id]
            }),
        )
        .await;
    assert_eq!(archived.status, StatusCode::OK, "{}", archived.text);
    assert_shape(&document, schema(&document, "SchedulerNativeArchiveResult"), &archived.json());
    let old = h.get(&format!("{ROOT}/observations/{id}")).await;
    assert_eq!(old.status, StatusCode::OK, "{}", old.text);
    assert_eq!(old.json()["status"], "archived");
    assert!(old.json()["observation"].is_null());
    assert_shape(&document, schema(&document, "SchedulerNativeReceipt"), &old.json());
    let retained = h.get(ROOT).await.json();
    assert_shape(&document, schema(&document, "SchedulerNativeState"), &retained);
    assert_eq!(
        retained["bindings"]["items"],
        adopted.json()["items"],
        "body archive retains authenticated adoption and qualification"
    );
    assert_eq!(retained["bindings"]["current"], true);
}
