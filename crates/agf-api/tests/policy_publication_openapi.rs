//! Published policy documentation is checked against actual HTTP request and signed response shapes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{ids::Id, policy::Policy};
use common::*;

const ROOT: &str = "/api/v1/policies";
const CURRENT: &str = "/api/v1/policies/{id}";
const HISTORY: &str = "/api/v1/policies/{id}/versions";
const RESTORE: &str = "/api/v1/policies/{id}/versions/{version}/restore";

async fn spec(h: &Harness) -> Value {
    let response = h.get("/api/v1/openapi.json").await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    response.json()
}
fn schema<'a>(document: &'a Value, name: &str) -> &'a Value {
    document.pointer(&format!("/components/schemas/{name}")).unwrap()
}
fn type_matches(kind: &str, value: &Value) -> bool {
    match kind {
        "null" => value.is_null(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "integer" => value.is_i64() || value.is_u64(),
        _ => panic!("unsupported contract type {kind}"),
    }
}
// This narrow contract checker only interprets the keywords present in this owned helper.
// It catches accidental DTO fields, wrong optionality/enums and generated schema drift.
fn matches(document: &Value, rule: &Value, value: &Value) -> bool {
    if let Some(reference) = rule["$ref"].as_str() {
        return matches(document, document.pointer(reference.strip_prefix('#').unwrap()).unwrap(), value);
    }
    if let Some(alternatives) = rule["anyOf"].as_array() {
        return alternatives.iter().any(|rule| matches(document, rule, value));
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
    if let Some(choices) = rule["enum"].as_array() {
        if !choices.contains(value) {
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
    if let Some(text) = value.as_str() {
        if rule["minLength"].as_u64().is_some_and(|min| (text.chars().count() as u64) < min)
            || rule["maxLength"].as_u64().is_some_and(|max| (text.chars().count() as u64) > max)
        {
            return false;
        }
        if rule["format"] == "uuid" && Id::parse(text).is_err() {
            return false;
        }
        if rule["format"] == "date-time" && Timestamp::parse_rfc3339(text).is_err() {
            return false;
        }
        if let Some(pattern) = rule["pattern"].as_str() {
            if !regex::Regex::new(pattern).unwrap().is_match(text) {
                return false;
            }
        }
    }
    if let Some(fields) = value.as_object() {
        if let Some(required) = rule["required"].as_array() {
            if required.iter().any(|name| !fields.contains_key(name.as_str().unwrap())) {
                return false;
            }
        }
        for (name, item) in fields {
            if let Some(child) = rule["properties"].get(name) {
                if !matches(document, child, item) {
                    return false;
                }
            } else if rule["additionalProperties"] == false {
                return false;
            }
        }
    }
    if let Some(items) = value.as_array() {
        if rule["maxItems"].as_u64().is_some_and(|max| (items.len() as u64) > max) {
            return false;
        }
        if rule["uniqueItems"] == true && items.iter().enumerate().any(|(i, item)| items[..i].contains(item)) {
            return false;
        }
        if let Some(child) = rule.get("items") {
            if items.iter().any(|item| !matches(document, child, item)) {
                return false;
            }
        }
    }
    true
}
fn assert_response(document: &Value, path: &str, method: &str, response: &Resp) {
    let code = response.status.as_u16().to_string();
    let rule = &document["paths"][path][method]["responses"][&code]["content"]["application/json"]["schema"];
    assert!(rule.is_object(), "no documented success schema for {method} {path} {code}");
    assert!(matches(document, rule, &response.json()), "response differs from documented {method} {path}");
}
fn assert_signed(h: &Harness, value: &Value) {
    let policy: Policy = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(policy.tenant_id, h.tenant);
    assert_eq!(policy.content_hash, policy.compute_hash());
    agf_api::policy_store::signer(&h.state).unwrap().verify(&policy).unwrap();
}

#[tokio::test]
async fn all_seven_publication_operations_are_unique_versioned_and_have_their_real_permissions() {
    let h = setup().await;
    let document = spec(&h).await;
    let specs = agf_api::routes::platform::endpoint_specs();
    use utoipa::openapi::path::HttpMethod::{Delete, Get, Post, Put};
    for (path, method, http, permission, success) in [
        (ROOT, "get", Get, "policies:read", "200"),
        (ROOT, "post", Post, "policies:write", "201"),
        (CURRENT, "get", Get, "policies:read", "200"),
        (CURRENT, "put", Put, "policies:write", "200"),
        (CURRENT, "delete", Delete, "policies:delete", "200"),
        (HISTORY, "get", Get, "policies:read", "200"),
        (RESTORE, "post", Post, "policies:write", "200"),
    ] {
        assert_eq!(
            specs.iter().filter(|entry| entry.path == path && entry.method == http).count(),
            1,
            "{method} {path}"
        );
        let operation = &document["paths"][path][method];
        assert!(operation["operationId"].is_string());
        assert_eq!(operation["x-required-permissions"], json!([permission]));
        assert_eq!(operation["security"], json!([{"bearerAuth":[]},{"apiKey":[]}]));
        assert!(operation["responses"][success]["content"]["application/json"]["schema"].is_object());
        for code in ["400", "401", "403", "500"] {
            assert!(operation["responses"][code].is_object());
        }
        if path != ROOT {
            assert!(operation["responses"]["404"].is_object());
        }
        if method != "get" {
            assert!(operation["responses"]["409"].is_object());
            assert!(operation["x-runtime-boundary"].as_str().unwrap().contains("does not publish to cloud"));
        }
    }
    assert!(document["paths"][ROOT]["post"]["responses"].get("200").is_none());
    let delete = &document["paths"][CURRENT]["delete"]["parameters"];
    assert_eq!(delete.as_array().unwrap().len(), 2);
    assert_eq!(delete[1]["name"], "expected_version");
    assert_eq!(delete[1]["required"], true);
    assert_eq!(delete[1]["schema"]["minimum"], 1);
    assert_eq!(document["paths"][RESTORE]["post"]["parameters"][1]["name"], "version");
    assert_eq!(schema(&document, "RestoreSignedPolicy")["additionalProperties"], false);
    assert_eq!(schema(&document, "UpdateSignedPolicy")["required"], json!(["name", "expected_version"]));
    assert_eq!(schema(&document, "SignedPolicyHistory")["properties"]["versions"]["maxItems"], 101);
}

#[tokio::test]
async fn real_crud_and_deleted_history_restore_responses_fit_the_documented_signed_dtos() {
    let h = setup().await;
    let document = spec(&h).await;
    let body = json!({"name":"owned-openapi-policy","language":"structured","enabled":true,
        "structured":{"command_deny":["owned-contract-deny"],"require_approval":false},
        "action":"circuit-break","intercept_points":["ai-gateway","mcp-proxy"],"expected_version":0});
    assert!(matches(&document, schema(&document, "CreateSignedPolicy"), &body));
    let created = h.post(ROOT, body.clone()).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    assert_response(&document, ROOT, "post", &created);
    let policy = created.json()["policy"].clone();
    assert_signed(&h, &policy);
    assert_eq!(policy["action"], "circuitbreak", "raw enum serde spelling must be documented accurately");
    let path = format!("{ROOT}/{}", policy["id"].as_str().unwrap());
    let listed = h.get(&format!("{ROOT}?q=owned-openapi-policy")).await;
    assert_response(&document, ROOT, "get", &listed);
    assert_eq!(listed.json()["total"], 1);
    let projected = h.get(&format!("{ROOT}?q=owned-openapi-policy&fields=id,version,content_hash")).await;
    assert_response(&document, ROOT, "get", &projected);
    assert_eq!(projected.json()["items"][0].as_object().unwrap().len(), 3);
    assert_response(&document, CURRENT, "get", &h.get(&path).await);
    let mut updated = body;
    updated["expected_version"] = json!(1);
    updated["action"] = json!("audit");
    assert!(matches(&document, schema(&document, "UpdateSignedPolicy"), &updated));
    let changed = h.request("PUT", &path, Some(&h.admin), Some(updated)).await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    assert_response(&document, CURRENT, "put", &changed);
    assert_signed(&h, &changed.json()["policy"]);
    let removed = h.request("DELETE", &format!("{path}?expected_version=2"), Some(&h.admin), None).await;
    assert_eq!(removed.status, StatusCode::OK, "{}", removed.text);
    assert_response(&document, CURRENT, "delete", &removed);
    assert_eq!(h.get(&path).await.status, StatusCode::NOT_FOUND);
    let history = h.get(&format!("{path}/versions")).await;
    assert_response(&document, HISTORY, "get", &history);
    let versions = history.json()["versions"].as_array().unwrap().clone();
    assert_eq!(versions.iter().map(|p| p["version"].as_u64().unwrap()).collect::<Vec<_>>(), vec![1, 2, 3]);
    assert_eq!(versions[2]["enabled"], false);
    assert!(versions[2]["deleted_at"].is_string());
    for version in &versions {
        assert_signed(&h, version);
    }
    let restore = json!({"version":1,"expected_version":3});
    assert!(matches(&document, schema(&document, "RestoreSignedPolicy"), &restore));
    let restored = h.post(&format!("{path}/versions/1/restore"), restore).await;
    assert_eq!(restored.status, StatusCode::OK, "{}", restored.text);
    assert_response(&document, RESTORE, "post", &restored);
    assert_eq!(restored.json()["policy"]["version"], 4);
    assert_signed(&h, &restored.json()["policy"]);
    assert!(restored.json()["policy"].get("deleted_at").is_none());
}

#[tokio::test]
async fn documented_strict_inputs_reject_client_identity_signatures_and_invalid_cas_before_mutation() {
    let h = setup().await;
    let document = spec(&h).await;
    let body = json!({"name":"owned-schema-strict","language":"cel","source":"true ? {\"action\":\"allow\"} : {}"});
    let created = h.post(ROOT, body.clone()).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let policy = created.json()["policy"].clone();
    let path = format!("{ROOT}/{}", policy["id"].as_str().unwrap());
    for key in ["id", "tenant_id", "version", "signature", "content_hash"] {
        let mut bad = body.clone();
        bad[key] = json!("caller-controlled");
        assert!(!matches(&document, schema(&document, "CreateSignedPolicy"), &bad));
        assert_eq!(h.post(ROOT, bad).await.status, StatusCode::BAD_REQUEST, "{key}");
    }
    for expected in [Value::Null, json!(0)] {
        let mut bad = body.clone();
        bad["expected_version"] = expected;
        assert!(!matches(&document, schema(&document, "UpdateSignedPolicy"), &bad));
        assert_eq!(h.request("PUT", &path, Some(&h.admin), Some(bad)).await.status, StatusCode::BAD_REQUEST);
    }
    let mut invalid_restore = json!({"version":1,"expected_version":1});
    invalid_restore["source"] = json!("caller-supplied history");
    assert!(!matches(&document, schema(&document, "RestoreSignedPolicy"), &invalid_restore));
    assert_eq!(h.post(&format!("{path}/versions/1/restore"), invalid_restore).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(h.get(&path).await.json()["policy"], policy);
    assert_eq!(h.get(&format!("{path}/versions")).await.json()["versions"].as_array().unwrap().len(), 1);
}
