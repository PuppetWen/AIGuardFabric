//! Contract checks resolve references and compare documented fields with actual native workflow DTOs.
mod common;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::Id,
};
use common::*;

const ROOT: &str = "/api/v1/alicloud/apig/policy-publication";
const RECEIPT: &str = "/api/v1/alicloud/apig/policy-publication/operations/{request_id}";

async fn response(
    h: &Harness,
    method: &str,
    path: &str,
    input: Option<Value>,
    status: StatusCode,
) -> DomainResult<Value> {
    let result = h.request(method, path, Some(&h.admin), input).await;
    assert_eq!(result.status, status, "{method} {path}: {}", result.text);
    serde_json::from_slice(&result.bytes).map_err(Into::into)
}
async fn document(h: &Harness) -> DomainResult<Value> {
    response(h, "GET", "/api/v1/openapi.json", None, StatusCode::OK).await
}
fn schema<'a>(document: &'a Value, name: &str) -> DomainResult<&'a Value> {
    document
        .pointer(&format!("/components/schemas/{name}"))
        .ok_or_else(|| DomainError::Internal(format!("missing documented schema {name}")))
}
fn check_references(document: &Value, value: &Value) -> DomainResult<()> {
    match value {
        Value::Object(fields) => {
            if let Some(reference) = fields.get("$ref").and_then(Value::as_str) {
                let pointer = reference
                    .strip_prefix('#')
                    .ok_or_else(|| DomainError::Internal("nonlocal schema reference".into()))?;
                assert!(document.pointer(pointer).is_some(), "missing {reference}");
            }
            for value in fields.values() {
                check_references(document, value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                check_references(document, value)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn type_matches(kind: &str, value: &Value) -> bool {
    match kind {
        "null" => value.is_null(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "integer" => value.is_i64() || value.is_u64(),
        _ => false,
    }
}
// Only the schema subset emitted here is checked; formats/patterns are separately documented.
fn matches(document: &Value, rule: &Value, value: &Value) -> bool {
    if let Some(reference) = rule["$ref"].as_str() {
        return reference
            .strip_prefix('#')
            .and_then(|pointer| document.pointer(pointer))
            .is_some_and(|resolved| matches(document, resolved, value));
    }
    if let Some(alternatives) = rule["oneOf"].as_array() {
        return alternatives.iter().filter(|rule| matches(document, rule, value)).count() == 1;
    }
    if rule.get("const").is_some_and(|constant| constant != value)
        || rule["enum"].as_array().is_some_and(|choices| !choices.contains(value))
    {
        return false;
    }
    if let Some(kind) = rule["type"].as_str() {
        if !type_matches(kind, value) {
            return false;
        }
    } else if let Some(kinds) = rule["type"].as_array() {
        if !kinds.iter().any(|kind| kind.as_str().is_some_and(|kind| type_matches(kind, value))) {
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
            .is_some_and(|keys| keys.iter().any(|key| key.as_str().is_none_or(|key| !fields.contains_key(key))))
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
        if rule["uniqueItems"] == true && values.iter().enumerate().any(|(i, value)| values[..i].contains(value)) {
            return false;
        }
    }
    true
}
fn check_shape(document: &Value, name: &str, value: &Value) -> DomainResult<()> {
    assert!(matches(document, schema(document, name)?, value), "{name} rejected actual DTO: {value}");
    Ok(())
}

#[tokio::test]
async fn eight_routes_document_real_permissions_strict_confirmations_and_unknown_boundaries() -> DomainResult<()> {
    let h = setup().await;
    let document = document(&h).await?;
    let paths = document["paths"].as_object().ok_or_else(|| DomainError::Internal("missing paths".into()))?;
    let entries = paths.iter().filter(|(path, _)| path.starts_with(ROOT)).collect::<Vec<_>>();
    assert_eq!(entries.len(), 8);
    let mut ids = std::collections::BTreeSet::new();
    for (path, item) in entries {
        for method in ["get", "post"] {
            let Some(operation) = item.get(method) else {
                continue;
            };
            let read = method == "get" || path.ends_with("/observe");
            assert_eq!(
                operation["x-required-permissions"],
                if read {
                    json!(["alicloud:read", "policies:read"])
                } else {
                    json!(["alicloud:read", "alicloud:write", "policies:read"])
                }
            );
            let id =
                operation["operationId"].as_str().ok_or_else(|| DomainError::Internal("missing operationId".into()))?;
            assert!(ids.insert(id));
            assert!(operation["responses"]["501"].is_null());
            check_references(&document, operation)?;
            if method == "post" {
                let input = &operation["requestBody"]["content"]["application/json"]["schema"];
                assert_eq!(input["additionalProperties"], false);
                for forbidden in ["endpoint", "url", "credentials", "config", "content", "grant"] {
                    assert!(input["properties"].get(forbidden).is_none());
                }
            }
        }
    }
    assert_eq!(ids.len(), 8);
    let apply = &document["paths"][format!("{ROOT}/operations")]["post"]["requestBody"]["content"]["application/json"]
        ["schema"];
    for confirmation in
        ["confirm_apply", "confirm_scope_difference", "confirm_shared_policy_impact", "confirm_no_cloud_cas"]
    {
        assert!(apply["required"].as_array().is_some_and(|keys| keys.contains(&json!(confirmation))));
    }
    assert_eq!(
        document["paths"][format!("{ROOT}/observe")]["post"]["x-conditional-permissions"][0]["required"],
        json!(["alicloud:write"])
    );
    assert_eq!(
        document["paths"][format!("{RECEIPT}/observe")]["post"]["requestBody"]["content"]["application/json"]["schema"]
            ["properties"]["initialize_mock_fixture"]["const"],
        false
    );
    assert_eq!(document["paths"][ROOT]["get"]["parameters"].as_array().map(Vec::len), Some(3));
    let revision = schema(&document, "ApigPolicyRevisionInput")?;
    for version in [1_u64, u64::from(u32::MAX)] {
        assert!(matches(&document, revision, &json!({"policy_id":Id::new(),"version":version})));
    }
    for version in [0_u64, u64::from(u32::MAX) + 1] {
        assert!(!matches(&document, revision, &json!({"policy_id":Id::new(),"version":version})));
    }
    assert!(!matches(&document, revision, &json!({"policyId":Id::new(),"version":1})));
    assert_eq!(
        schema(&document, "ApigPolicyOperation")?["properties"]["cloudWrite"]["properties"]["status"]["enum"],
        json!(["not_attempted", "attempting", "accepted", "unknown"])
    );
    assert_eq!(schema(&document, "ApigPolicyPreview")?["properties"]["casSemantics"]["const"], "none");
    for name in paths.keys().filter(|path| path.starts_with(ROOT)) {
        check_references(&document, &document["paths"][name])?;
    }
    let schemas =
        document["components"]["schemas"].as_object().ok_or_else(|| DomainError::Internal("missing schemas".into()))?;
    for (name, rule) in schemas {
        if name.starts_with("ApigPolicy") {
            check_references(&document, rule)?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn unconfigured_get_is_documented_unknown_and_does_not_initialize_any_provider_or_workflow() -> DomainResult<()> {
    let h = setup().await;
    let document = document(&h).await?;
    let before = serde_json::to_value(h.state.store.audit_chain_durable(h.tenant, 0, i64::MAX).await?)?;
    for _ in 0..2 {
        let value = response(&h, "GET", ROOT, None, StatusCode::OK).await?;
        check_shape(&document, "ApigPolicyPublicationState", &value)?;
        assert_eq!(value["configured"], false);
        for field in ["binding", "enabled", "consumerApplied", "sharedPolicyImpact"] {
            assert!(value[field].is_null());
        }
        assert_eq!(value["stateVersion"], 0);
        assert_eq!(value["noCloudCas"], true);
    }
    for kind in [
        "cloud-integration",
        "apig-policy-driver-mock",
        "apig-policy-publication-state",
        "apig-policy-publication-fact",
        "apig-policy-publication-detail",
        "apig-policy-publication-preview",
        "apig-policy-publication-pending",
    ] {
        assert!(h.state.configurations.list::<Value>(h.tenant, kind).await?.is_empty(), "GET initialized {kind}");
    }
    assert_eq!(serde_json::to_value(h.state.store.audit_chain_durable(h.tenant, 0, i64::MAX).await?)?, before);
    Ok(())
}

#[tokio::test]
async fn actual_mock_observation_preview_receipt_history_and_archive_match_safe_documented_shapes() -> DomainResult<()>
{
    let h = setup().await;
    let document = document(&h).await?;
    response(&h, "PUT", "/api/v1/alicloud/connections/alicloud-apig", Some(json!({
        "expected_version":0,"enabled":true,"mock":true,"secrets":{},"settings":{
            "region_id":"cn-hangzhou","account_id":"owned-openapi-apig-account",
            "policy_http_api_id":"api-agf-demo","policy_gateway_id":"gw-agf-demo","policy_environment_id":"env-agf-demo",
            "policy_id":"policy-agf-demo","policy_attachment_id":"attachment-agf-demo",
            "policy_dialect":"apig-2024-03-27-ai-token-rate-limit","managed_policy_confirmed":true}})), StatusCode::OK).await?;
    let quota = response(
        &h,
        "POST",
        "/api/v1/quotas",
        Some(json!({"name":format!("owned-apig-contract-quota-{}",Id::new()),
        "expected_version":0,"scope":"tenant","dimension":"tokens","window":"minute","limit":1250,
        "soft_threshold":0,"action":"deny","enabled":true})),
        StatusCode::OK,
    )
    .await?["quota"]
        .clone();
    let policy = response(
        &h,
        "POST",
        "/api/v1/policies",
        Some(json!({"name":format!("owned-apig-contract-policy-{}",Id::new()),
        "expected_version":0,"language":"structured","source":"","structured":{},"action":"quota",
        "intercept_points":["ai-gateway"],"enabled":true,"dry_run":false,"quota_id":quota["id"]})),
        StatusCode::CREATED,
    )
    .await?["policy"]
        .clone();
    let observation = response(
        &h,
        "POST",
        &format!("{ROOT}/observe"),
        Some(json!({"request_id":Id::new(),
        "configuration_version":1,"initialize_mock_fixture":true})),
        StatusCode::OK,
    )
    .await?;
    check_shape(&document, "ApigPolicyObservation", &observation)?;
    let state = response(&h, "GET", ROOT, None, StatusCode::OK).await?;
    check_shape(&document, "ApigPolicyPublicationState", &state)?;
    let preview = response(
        &h,
        "POST",
        &format!("{ROOT}/previews"),
        Some(json!({"request_id":Id::new(),
        "configuration_version":1,"observation_id":observation["id"],"expected_state_version":state["stateVersion"],
        "change":{"action":"publish","policies":[{"policy_id":policy["id"],"version":policy["version"]}]}})),
        StatusCode::OK,
    )
    .await?;
    check_shape(&document, "ApigPolicyPreview", &preview)?;
    let request = Id::new();
    let operation = response(
        &h,
        "POST",
        &format!("{ROOT}/operations"),
        Some(json!({"request_id":request,
        "preview_id":preview["id"],"expected_state_version":preview["stateVersion"],"confirm_apply":true,
        "confirm_scope_difference":true,"confirm_shared_policy_impact":true,"confirm_no_cloud_cas":true})),
        StatusCode::OK,
    )
    .await?;
    check_shape(&document, "ApigPolicyOperation", &operation)?;
    assert_eq!(operation["status"], "verified");
    assert!(operation["consumerApplied"].is_null());
    let state = response(&h, "GET", ROOT, None, StatusCode::OK).await?;
    check_shape(&document, "ApigPolicyPublicationState", &state)?;
    assert_eq!(state["history"].as_array().map(Vec::len), Some(1));
    let archive = response(
        &h,
        "POST",
        &format!("{ROOT}/operations/archive"),
        Some(json!({
        "expected_generation":state["generation"],"request_ids":[request]})),
        StatusCode::OK,
    )
    .await?;
    check_shape(&document, "ApigPolicyArchiveResult", &archive)?;
    let receipt = response(&h, "GET", &format!("{ROOT}/operations/{request}"), None, StatusCode::OK).await?;
    check_shape(&document, "ApigPolicyOperation", &receipt)?;
    assert_eq!(receipt["status"], "archived");
    assert_eq!(receipt["originalStatus"], "verified");
    Ok(())
}
