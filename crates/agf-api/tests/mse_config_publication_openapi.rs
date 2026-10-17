//! Public workflow documentation must resolve and describe actual pure local response shapes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;

const ROOT: &str = "/api/v1/alicloud/mse/config-publication";
const RECEIPT: &str = "/api/v1/alicloud/mse/config-publication/operations/{request_id}";

async fn document(h: &Harness) -> Value {
    let response = h.get("/api/v1/openapi.json").await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    response.json()
}
fn schema<'a>(document: &'a Value, name: &str) -> &'a Value {
    document.pointer(&format!("/components/schemas/{name}")).unwrap()
}
fn check_references(document: &Value, value: &Value) {
    match value {
        Value::Object(fields) => {
            if let Some(reference) = fields.get("$ref").and_then(Value::as_str) {
                assert!(document.pointer(reference.strip_prefix('#').unwrap()).is_some(), "missing {reference}");
            }
            for value in fields.values() {
                check_references(document, value);
            }
        }
        Value::Array(values) => {
            for value in values {
                check_references(document, value);
            }
        }
        _ => {}
    }
}
fn type_matches(kind: &str, value: &Value) -> bool {
    match kind {
        "null" => value.is_null(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "integer" => value.is_i64() || value.is_u64(),
        _ => panic!("unsupported kind {kind}"),
    }
}
fn matches(document: &Value, rule: &Value, value: &Value) -> bool {
    if let Some(reference) = rule["$ref"].as_str() {
        return matches(document, document.pointer(reference.strip_prefix('#').unwrap()).unwrap(), value);
    }
    if let Some(alternatives) = rule["oneOf"].as_array() {
        return alternatives.iter().filter(|rule| matches(document, rule, value)).count() == 1;
    }
    if rule.get("const").is_some_and(|constant| constant != value) {
        return false;
    }
    if rule["enum"].as_array().is_some_and(|choices| !choices.contains(value)) {
        return false;
    }
    if let Some(kind) = rule["type"].as_str() {
        if !type_matches(kind, value) {
            return false;
        }
    } else if let Some(kinds) = rule["type"].as_array() {
        if !kinds.iter().any(|kind| type_matches(kind.as_str().unwrap(), value)) {
            return false;
        }
    }
    if let Some(number) = value.as_f64() {
        if rule["minimum"].as_f64().is_some_and(|min| number < min)
            || rule["maximum"].as_f64().is_some_and(|max| number > max)
        {
            return false;
        }
    }
    if let Some(fields) = value.as_object() {
        if rule["required"]
            .as_array()
            .is_some_and(|keys| keys.iter().any(|key| !fields.contains_key(key.as_str().unwrap())))
        {
            return false;
        }
        for (key, value) in fields {
            if let Some(field) = rule["properties"].get(key) {
                if !matches(document, field, value) {
                    return false;
                }
            } else if rule["additionalProperties"] == false {
                return false;
            }
        }
    }
    if let Some(values) = value.as_array() {
        if rule["maxItems"].as_u64().is_some_and(|max| values.len() as u64 > max)
            || rule["minItems"].as_u64().is_some_and(|min| (values.len() as u64) < min)
        {
            return false;
        }
        if values.iter().any(|value| !matches(document, &rule["items"], value)) {
            return false;
        }
    }
    true
}

#[tokio::test]
async fn all_eight_operations_have_separate_read_write_grants_strict_inputs_and_valid_references() {
    let h = setup().await;
    let document = document(&h).await;
    let paths = document["paths"].as_object().unwrap();
    let entries = paths.iter().filter(|(path, _)| path.starts_with(ROOT)).collect::<Vec<_>>();
    assert_eq!(entries.len(), 8);
    let mut operations = 0;
    for (path, item) in entries {
        for method in ["get", "post"] {
            let Some(operation) = item.get(method) else {
                continue;
            };
            operations += 1;
            let read = method == "get" || path.ends_with("/observe");
            assert_eq!(
                operation["x-required-permissions"],
                if read {
                    json!(["alicloud:read", "policies:read"])
                } else {
                    json!(["alicloud:read", "alicloud:write", "policies:read"])
                }
            );
            assert!(operation["responses"]["501"].is_null());
            check_references(&document, operation);
            if method == "post" {
                let input = &operation["requestBody"]["content"]["application/json"]["schema"];
                assert_eq!(input["additionalProperties"], false);
                for forbidden in ["engine_origin", "url", "credentials", "content", "grant"] {
                    assert!(input["properties"].get(forbidden).is_none());
                }
            }
        }
    }
    assert_eq!(operations, 8);
    assert_eq!(document["paths"][RECEIPT]["get"]["parameters"][0]["name"], "request_id");
    let input = schema(&document, "MseConfigPolicyRevisionInput");
    let output = schema(&document, "MseConfigPolicyRevision");
    let id = agf_core::ids::Id::new();
    assert!(matches(&document, input, &json!({"policy_id":id,"version":1})));
    assert!(!matches(&document, input, &json!({"policyId":id,"version":1})));
    assert!(matches(&document, output, &json!({"policyId":id,"version":1})));
    assert!(matches(&document, input, &json!({"policy_id":id,"version":u32::MAX})));
    assert!(matches(&document, output, &json!({"policyId":id,"version":u32::MAX})));
    for version in [-1_i64, 0, i64::from(u32::MAX) + 1] {
        assert!(!matches(&document, input, &json!({"policy_id":id,"version":version})));
        assert!(!matches(&document, output, &json!({"policyId":id,"version":version})));
    }
    assert_eq!(schema(&document, "MseConfigOperation")["properties"]["consumerApplied"]["type"], "null");
    for name in
        document["components"]["schemas"].as_object().unwrap().keys().filter(|name| name.starts_with("MseConfig"))
    {
        check_references(&document, schema(&document, name));
    }
}

#[tokio::test]
async fn actual_unconfigured_get_matches_documented_null_binding_without_initializing_business_records() {
    let h = setup().await;
    let document = document(&h).await;
    for _ in 0..2 {
        let response = h.request("GET", ROOT, Some(&h.admin), None).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text);
        let data = response.json();
        assert!(matches(&document, schema(&document, "MseConfigPublicationState"), &data), "{data}");
        assert_eq!(data["configured"], false);
        assert!(data["binding"].is_null());
        assert_eq!(data["stateVersion"], 0);
        assert_eq!(data["generation"], 0);
    }
    for kind in [
        "cloud-integration",
        "mse-config-publication-state",
        "mse-config-publication-mock",
        "mse-config-publication-fact",
        "mse-config-publication-preview",
    ] {
        assert!(
            h.state.configurations.list::<Value>(h.tenant, kind).await.unwrap().is_empty(),
            "GET initialized {kind}"
        );
    }
}
