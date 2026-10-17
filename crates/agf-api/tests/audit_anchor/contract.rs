//! 用真实 route 返回核对公开结构子集；格式、签名及身份由既有生产回归另行验证。
use super::*;
const ROOT: &str = "/api/v1/runtime/audit/anchors";

fn kind_matches(kind: &str, value: &Value) -> bool {
    match kind {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "integer" => value.is_i64() || value.is_u64(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => false,
    }
}
fn matches(doc: &Value, rule: &Value, value: &Value) -> bool {
    if let Some(reference) = rule["$ref"].as_str() {
        return reference
            .strip_prefix('#')
            .and_then(|path| doc.pointer(path))
            .is_some_and(|rule| matches(doc, rule, value));
    }
    if let Some(choices) = rule["oneOf"].as_array() {
        return choices.iter().filter(|rule| matches(doc, rule, value)).count() == 1;
    }
    if rule["type"].as_str().is_some_and(|kind| !kind_matches(kind, value))
        || rule["enum"].as_array().is_some_and(|choices| !choices.contains(value))
    {
        return false;
    }
    if let Some(fields) = value.as_object() {
        if rule["required"]
            .as_array()
            .is_some_and(|keys| keys.iter().any(|key| key.as_str().is_none_or(|key| !fields.contains_key(key))))
        {
            return false;
        }
        for (key, value) in fields {
            if let Some(rule) = rule["properties"].get(key) {
                if !matches(doc, rule, value) {
                    return false;
                }
            } else if rule["additionalProperties"] == false {
                return false;
            }
        }
    }
    if let Some(values) = value.as_array() {
        if rule["maxItems"].as_u64().is_some_and(|limit| u64::try_from(values.len()).unwrap() > limit) {
            return false;
        }
        if rule.get("items").is_some_and(|rule| values.iter().any(|value| !matches(doc, rule, value))) {
            return false;
        }
    }
    if value.as_i64().is_some_and(|value| rule["minimum"].as_i64().is_some_and(|limit| value < limit)) {
        return false;
    }
    true
}
fn shape(doc: &Value, name: &str, value: &Value) {
    let schema = &doc["components"]["schemas"][name];
    assert!(schema.is_object(), "{name} 缺失");
    assert!(matches(doc, schema, value), "{name} 与真实返回不符: {value}");
}
fn references(doc: &Value, value: &Value) {
    match value {
        Value::Object(fields) => {
            if let Some(reference) = fields.get("$ref").and_then(Value::as_str) {
                assert!(reference.strip_prefix('#').and_then(|path| doc.pointer(path)).is_some(), "{reference}");
            }
            for child in fields.values() {
                references(doc, child);
            }
        }
        Value::Array(values) => {
            for child in values {
                references(doc, child);
            }
        }
        _ => {}
    }
}

#[tokio::test]
async fn public_contract_matches_actual_bound_key_bootstrap_append_retry_and_management_verification() {
    let h = setup().await;
    let doc = h.get("/api/v1/openapi.json").await;
    assert_eq!(doc.status, StatusCode::OK);
    let doc = doc.json();
    let op = &doc["paths"][ROOT]["post"];
    assert_eq!(op["operationId"], "appendAgentAuditAnchor");
    assert_eq!(op["security"], json!([{"apiKey":[]}]));
    assert_eq!(op["x-required-permissions"], json!(["policies:read"]));
    assert_eq!(op["x-required-subject"], "current-agent-bound-api-key");
    assert_eq!(
        op["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/AgentAuditBatch"
    );
    assert_eq!(
        op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/AgentAuditAcknowledgement"
    );
    assert_eq!(doc["paths"]["/api/v1/audit/verify"]["get"]["x-required-permissions"], json!(["audit:read"]));
    references(&doc, op);
    references(&doc, &doc["components"]["schemas"]);
    let (key, _) = key(&h).await;
    let mut batch = AgentAuditBatch { chain_id: Id::new(), previous: None, entries: Vec::new() };
    shape(&doc, "AgentAuditBatch", &serde_json::to_value(&batch).unwrap());
    let first = h.request_with("POST", ROOT, &[("x-agf-key", &key)], Some(serde_json::to_value(&batch).unwrap())).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    shape(&doc, "AgentAuditAcknowledgement", &first.json());
    assert_eq!(first.json()["durable"], false);
    assert_eq!(first.json()["replayed"], false);
    let checkpoint: SignedAuditAnchor = serde_json::from_value(first.json()["checkpoint"].clone()).unwrap();
    batch.entries.push(record(&checkpoint));
    batch.previous = Some(checkpoint);
    shape(&doc, "AgentAuditBatch", &serde_json::to_value(&batch).unwrap());
    let committed = append(&h, &key, &batch).await;
    assert_eq!(committed.status, StatusCode::OK, "{}", committed.text);
    shape(&doc, "AgentAuditAcknowledgement", &committed.json());
    let replay = append(&h, &key, &batch).await;
    assert_eq!(replay.status, StatusCode::OK);
    shape(&doc, "AgentAuditAcknowledgement", &replay.json());
    assert_eq!(replay.json()["replayed"], true);
    assert_eq!(replay.json()["checkpoint"], committed.json()["checkpoint"]);
    let management = h.get("/api/v1/audit/verify").await;
    assert_eq!(management.status, StatusCode::OK);
    shape(&doc, "AnchoredAuditVerification", &management.json());
    assert_eq!(management.json()["anchoring"]["initial_checkpoint_required"], true);
    assert_eq!(management.json()["anchoring"]["fully_anchored"], false);
}

#[tokio::test]
async fn contract_and_route_reject_top_level_identity_override_unknown_fields_and_missing_entries() {
    let h = setup().await;
    let (key, _) = key(&h).await;
    let doc = h.get("/api/v1/openapi.json").await.json();
    let schema = &doc["components"]["schemas"]["AgentAuditBatch"];
    assert_eq!(schema["properties"]["entries"]["maxItems"], 256);
    assert_eq!(schema["additionalProperties"], false);
    for invalid in [
        json!({"chain_id":Id::new(),"entries":[],"tenant_id":h.other_tenant}),
        json!({"chain_id":Id::new(),"entries":[],"agent_id":Id::new()}),
        json!({"chain_id":Id::new()}),
    ] {
        assert!(!matches(&doc, schema, &invalid));
        let rejected = h.request_with("POST", ROOT, &[("x-agf-key", &key)], Some(invalid)).await;
        assert_eq!(rejected.status, StatusCode::BAD_REQUEST, "{}", rejected.text);
        assert!(rejected.content_type().starts_with("application/problem+json"));
    }
    let batch = AgentAuditBatch { chain_id: Id::new(), previous: None, entries: Vec::new() };
    assert_eq!(append(&h, &h.admin, &batch).await.status, StatusCode::FORBIDDEN);
    assert_eq!(append(&h, &h.api_key, &batch).await.status, StatusCode::FORBIDDEN);
}
