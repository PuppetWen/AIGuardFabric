//! Real document/router checks; offline tests never fabricate a SQL Role receipt.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{error::DomainResult, ids::Id};
use common::*;

const ROLE: &str = "/api/v1/alicloud/agentteams/role-mappings";
const ASSET: &str = "/api/v1/alicloud/agentteams/role-mappings/{asset}";
const REQUEST: &str = "/api/v1/alicloud/agentteams/role-mappings/{asset}/requests/{request}";
const PROFILE: &str = "/api/v1/models/semantic-cache/profile";

async fn document(h: &Harness) -> Value {
    let response = h.get("/api/v1/openapi.json").await;
    assert_eq!(response.status, StatusCode::OK);
    response.json()
}
fn schema<'a>(document: &'a Value, name: &str) -> &'a Value {
    document.pointer(&format!("/components/schemas/{name}")).unwrap()
}
// Interpret exactly the schema keywords emitted by the two owned contracts.
fn matches(document: &Value, rule: &Value, value: &Value) -> bool {
    if let Some(reference) = rule["$ref"].as_str() {
        return matches(document, document.pointer(reference.strip_prefix('#').unwrap()).unwrap(), value);
    }
    if let Some(alternatives) = rule["anyOf"].as_array() {
        return alternatives.iter().any(|rule| matches(document, rule, value));
    }
    if let Some(choices) = rule["enum"].as_array() {
        if !choices.contains(value) {
            return false;
        }
    }
    let type_ok = match rule["type"].as_str() {
        None => true,
        Some("object") => value.is_object(),
        Some("array") => value.is_array(),
        Some("null") => value.is_null(),
        Some("string") => value.is_string(),
        Some("boolean") => value.is_boolean(),
        Some("integer") => value.is_i64() || value.is_u64(),
        _ => false,
    };
    if !type_ok {
        return false;
    }
    if let Some(number) = value.as_f64() {
        if rule["minimum"].as_f64().is_some_and(|bound| number < bound)
            || rule["maximum"].as_f64().is_some_and(|bound| number > bound)
        {
            return false;
        }
    }
    if let Some(text) = value.as_str() {
        let length = u64::try_from(text.chars().count()).unwrap();
        if rule["minLength"].as_u64().is_some_and(|bound| length < bound)
            || rule["maxLength"].as_u64().is_some_and(|bound| length > bound)
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
        if rule["required"]
            .as_array()
            .is_some_and(|required| required.iter().any(|name| !fields.contains_key(name.as_str().unwrap())))
        {
            return false;
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
        if rule["maxItems"].as_u64().is_some_and(|bound| u64::try_from(items.len()).unwrap() > bound) {
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
async fn profile_body(h: &Harness) -> Value {
    let mut ids = Vec::new();
    for model in ["owned-contract-chat", "owned-contract-embedding"] {
        let response = h
            .post(
                "/api/v1/gateway/endpoints",
                json!({"name":model,"model":model,
            "provider":"mock","base_url":"http://mock.invalid/v1","local_deployment":true}),
            )
            .await;
        assert_eq!(response.status, StatusCode::CREATED);
        ids.push(response.json()["id"].clone());
    }
    json!({"expected_version":0,"enabled":true,"settings":{
        "chat_endpoint_id":ids[0],"chat_model":"owned-contract-chat","chat_model_revision":"chat-revision-1",
        "embedding_endpoint_id":ids[1],"embedding_model":"owned-contract-embedding","embedding_model_revision":"embedding-revision-1",
        "dimensions":64,"send_dimensions":false,"max_input_tokens":8192,"embedding_micro_per_1k":0,
        "threshold_ppm":950_000,"ttl_seconds":300,"classification_floor":"internal","mode":"mock_vector"}})
}
async fn local_snapshot(h: &Harness) -> DomainResult<Value> {
    Ok(json!({"profiles":h.state.configurations.list::<Value>(h.tenant,"semantic-cache-profile").await?,
        "mappings":h.state.configurations.list::<Value>(h.tenant,"agentteams-role-governance").await?,
        "intents":h.state.configurations.list::<Value>(h.tenant,"agentteams-role-governance-intent").await?,
        "audit":h.state.store.audit_stats(h.tenant)?}))
}
#[tokio::test]
async fn role_document_matches_real_offline_catalog_and_strict_administrator_request() -> DomainResult<()> {
    let h = setup().await;
    let document = document(&h).await;
    for (path, method) in [(ROLE, "get"), (ASSET, "get"), (ASSET, "put"), (REQUEST, "get")] {
        let operation = &document["paths"][path][method];
        assert!(operation["operationId"].is_string());
        assert_eq!(
            operation["x-required-permissions"],
            if method == "put" {
                json!(["alicloud:read", "platform:admin", "assets:write"])
            } else {
                json!(["alicloud:read", "platform:admin"])
            }
        );
        assert_eq!(
            operation["security"],
            if method == "put" { json!([{"bearerAuth":[]}]) } else { json!([{"bearerAuth":[]},{"apiKey":[]}]) }
        );
    }
    let before = local_snapshot(&h).await?;
    let response = h.get(ROLE).await;
    assert_eq!(response.status, StatusCode::OK);
    let catalog = response.json();
    assert!(matches(&document, schema(&document, "AgentTeamsRoleCatalog"), &catalog));
    assert_eq!(catalog["catalogAvailable"], false);
    assert_eq!(catalog["canManage"], false);
    assert_eq!(catalog["mappedCount"], 0);
    assert_eq!(catalog["roles"], json!([]));
    let asset = Id::new();
    let request = Id::new();
    let url = format!("{ROLE}/{asset}");
    assert_eq!(h.get(&url).await.status, StatusCode::NOT_FOUND);
    assert_eq!(h.get(&format!("{url}/requests/{request}")).await.status, StatusCode::NOT_FOUND);
    let input = json!({"request_id":request,"expected_version":0,"confirm_local_constraint":true,"change":{"action":"disable"}});
    assert!(matches(&document, schema(&document, "AgentTeamsRoleInput"), &input));
    assert_eq!(
        h.request("PUT", &url, Some(&h.admin), Some(input.clone())).await.status,
        StatusCode::PRECONDITION_FAILED
    );
    let mut unknown = input.clone();
    unknown["authority"] = json!("client-cannot-supply");
    assert!(!matches(&document, schema(&document, "AgentTeamsRoleInput"), &unknown));
    assert_eq!(h.request("PUT", &url, Some(&h.admin), Some(unknown)).await.status, StatusCode::BAD_REQUEST);
    let mut denied = input;
    denied["confirm_local_constraint"] = json!(false);
    assert!(!matches(&document, schema(&document, "AgentTeamsRoleInput"), &denied));
    assert_eq!(h.request("PUT", &url, Some(&h.admin), Some(denied)).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(h.request("GET", ROLE, None, None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(h.request("GET", ROLE, Some(&h.viewer), None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(local_snapshot(&h).await?, before);
    Ok(())
}
#[tokio::test]
async fn profile_document_matches_default_and_saved_mock_intent_without_placement_claim() -> DomainResult<()> {
    let h = setup().await;
    let document = document(&h).await;
    for (method, permission) in [("get", "models:read"), ("put", "models:write")] {
        let operation = &document["paths"][PROFILE][method];
        assert!(operation["operationId"].is_string());
        assert_eq!(operation["x-required-permissions"], json!([permission]));
        assert_eq!(operation["security"], json!([{"bearerAuth":[]},{"apiKey":[]}]));
    }
    assert_eq!(document["paths"][PROFILE]["put"]["x-max-request-bytes"], 16 * 1024);
    let before = local_snapshot(&h).await?;
    let initial = h.get(PROFILE).await;
    assert_eq!(initial.status, StatusCode::OK);
    let initial = initial.json();
    assert!(matches(&document, schema(&document, "SemanticCacheProfileView"), &initial));
    assert_eq!(
        initial,
        json!({"version":0,"enabled":false,"settings":null,"placementVerified":false,"providerWeightsRevisionVerified":false})
    );
    assert_eq!(local_snapshot(&h).await?, before);
    let valid = profile_body(&h).await;
    assert!(matches(&document, schema(&document, "SemanticCacheProfileInput"), &valid));
    let saved = h.request("PUT", PROFILE, Some(&h.admin), Some(valid.clone())).await;
    assert_eq!(saved.status, StatusCode::OK);
    assert!(matches(&document, schema(&document, "SemanticCacheProfileView"), &saved.json()));
    assert_eq!(saved.json()["placementVerified"], false);
    assert_eq!(saved.json()["providerWeightsRevisionVerified"], false);
    assert_eq!(saved.json()["settings"], valid["settings"]);
    assert_eq!(h.get(PROFILE).await.json(), saved.json());
    let current = local_snapshot(&h).await?;
    let mut unknown = valid.clone();
    unknown["domain"] = json!("untrusted");
    assert!(!matches(&document, schema(&document, "SemanticCacheProfileInput"), &unknown));
    assert_eq!(h.request("PUT", PROFILE, Some(&h.admin), Some(unknown)).await.status, StatusCode::BAD_REQUEST);
    let mut invalid = valid.clone();
    invalid["settings"]["embedding_micro_per_1k"] = json!(1);
    assert!(!matches(&document, schema(&document, "SemanticCacheProfileInput"), &invalid));
    assert_eq!(h.request("PUT", PROFILE, Some(&h.admin), Some(invalid)).await.status, StatusCode::BAD_REQUEST);
    let mut null = valid.clone();
    null["settings"] = Value::Null;
    assert!(!matches(&document, schema(&document, "SemanticCacheProfileInput"), &null));
    assert_eq!(h.request("PUT", PROFILE, Some(&h.admin), Some(null)).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(h.request("PUT", PROFILE, Some(&h.admin), Some(valid)).await.status, StatusCode::CONFLICT);
    assert_eq!(h.request("GET", PROFILE, None, None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        h.request("PUT", PROFILE, Some(&h.viewer), Some(json!({"expected_version":1,"enabled":false}))).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(local_snapshot(&h).await?, current);
    Ok(())
}
