//! Only the emitted structural subset is checked here; no fabricated provider responses.
use crate::common::*;
use agf_core::error::DomainResult;

pub(crate) const APIG: &str = "/api/v1/alicloud/apig/configuration-publication";
pub(crate) const JOBS: &str = "/api/v1/alicloud/schedulerx3/native/jobs";

pub(crate) fn matches(document: &Value, rule: &Value, value: &Value) -> bool {
    if let Some(reference) = rule["$ref"].as_str() {
        return reference
            .strip_prefix('#')
            .and_then(|p| document.pointer(p))
            .is_some_and(|r| matches(document, r, value));
    }
    if let Some(alternatives) = rule["oneOf"].as_array() {
        return alternatives.iter().filter(|rule| matches(document, rule, value)).count() == 1;
    }
    if rule.get("const").is_some_and(|v| v != value) || rule["enum"].as_array().is_some_and(|v| !v.contains(value)) {
        return false;
    }
    if let Some(kind) = rule["type"].as_str() {
        let valid = match kind {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "integer" => value.is_i64() || value.is_u64(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            _ => false,
        };
        if !valid {
            return false;
        }
    }
    if let Some(fields) = value.as_object() {
        if rule["required"]
            .as_array()
            .is_some_and(|required| required.iter().any(|key| key.as_str().is_none_or(|k| !fields.contains_key(k))))
        {
            return false;
        }
        if fields.iter().any(|(key, value)| match rule["properties"].get(key) {
            Some(field) => !matches(document, field, value),
            None => rule["additionalProperties"] == false,
        }) {
            return false;
        }
    }
    if let Some(values) = value.as_array() {
        let length = u64::try_from(values.len()).unwrap_or(u64::MAX);
        if rule["minItems"].as_u64().is_some_and(|n| length < n)
            || rule["maxItems"].as_u64().is_some_and(|n| length > n)
            || (rule["uniqueItems"] == true && values.iter().enumerate().any(|(i, v)| values[..i].contains(v)))
        {
            return false;
        }
        if rule.get("items").is_some_and(|r| values.iter().any(|v| !matches(document, r, v))) {
            return false;
        }
    }
    true
}
pub(crate) fn shape(document: &Value, name: &str, value: &Value) {
    assert!(
        matches(document, &document["components"]["schemas"][name], value),
        "safe DTO differs from documented structure"
    );
}
pub(crate) fn references(document: &Value, value: &Value) {
    match value {
        Value::Object(fields) => {
            if let Some(reference) = fields.get("$ref").and_then(Value::as_str) {
                assert!(
                    reference.strip_prefix('#').and_then(|p| document.pointer(p)).is_some(),
                    "local schema reference missing: {reference}"
                );
            }
            for value in fields.values() {
                references(document, value);
            }
        }
        Value::Array(values) => {
            for value in values {
                references(document, value);
            }
        }
        _ => {}
    }
}
pub(crate) async fn ok(h: &Harness, method: &str, path: &str, input: Option<Value>) -> Value {
    let result = h.request(method, path, Some(&h.admin), input).await;
    assert_eq!(result.status, StatusCode::OK, "owned request status");
    result.json()
}
pub(crate) async fn snapshot(h: &Harness) -> DomainResult<Value> {
    let mut rows = BTreeMap::new();
    for kind in [
        "cloud-integration",
        "apig-configuration-publication-state",
        "apig-configuration-publication-fact",
        "apig-configuration-publication-preview",
        "apig-configuration-publication-detail",
        "apig-configuration-publication-pending",
        "apig-configuration-driver-mock",
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
    ] {
        rows.insert(kind, h.state.configurations.list::<Value>(h.tenant, kind).await?);
    }
    Ok(json!({"records":rows,"audits":h.state.store.audit_chain_durable(h.tenant,0,i64::MAX).await?}))
}
