//! No imported test targets: compare the real router with the owned schema keywords.
use super::*;
pub(super) const BASE: &str = "/api/v1/alicloud/agentteams/orchestration-definitions";
pub(super) const CONFIG: &str = "/api/v1/alicloud/connections/alicloud-agentteams";
pub(super) const KIND: &str = "agentteams-application-orchestration";

pub(super) fn schema<'a>(document: &'a Value, name: &str) -> &'a Value {
    document.pointer(&format!("/components/schemas/{name}")).unwrap()
}
pub(super) fn matches(document: &Value, rule: &Value, value: &Value) -> bool {
    if let Some(reference) = rule["$ref"].as_str() {
        return matches(document, document.pointer(reference.strip_prefix('#').unwrap()).unwrap(), value);
    }
    if let Some(alternatives) = rule["anyOf"].as_array() {
        return alternatives.iter().any(|rule| matches(document, rule, value));
    }
    if rule["enum"].as_array().is_some_and(|choices| !choices.contains(value)) {
        return false;
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
            || rule["x-max-utf8-bytes"].as_u64().is_some_and(|bound| u64::try_from(text.len()).unwrap() > bound)
        {
            return false;
        }
        if rule["format"] == "uuid" && Id::parse(text).is_err() {
            return false;
        }
        if rule["format"] == "date-time" && Timestamp::parse_rfc3339(text).is_err() {
            return false;
        }
        if rule["pattern"].as_str().is_some_and(|pattern| !regex::Regex::new(pattern).unwrap().is_match(text)) {
            return false;
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
        let length = u64::try_from(items.len()).unwrap();
        if rule["maxItems"].as_u64().is_some_and(|bound| length > bound)
            || rule["minItems"].as_u64().is_some_and(|bound| length < bound)
            || (rule["uniqueItems"] == true
                && items.iter().enumerate().any(|(index, item)| items[..index].contains(item)))
        {
            return false;
        }
        if rule.get("items").is_some_and(|child| items.iter().any(|item| !matches(document, child, item))) {
            return false;
        }
    }
    true
}
pub(super) async fn openapi(h: &Harness) -> Value {
    let response = h.get("/api/v1/openapi.json").await;
    assert_eq!(response.status, StatusCode::OK);
    response.json()
}
pub(super) async fn snapshot(h: &Harness) -> DomainResult<Value> {
    Ok(json!({"definitions":h.state.configurations.list::<Value>(h.tenant,KIND).await?,
        "connections":h.state.configurations.list::<Value>(h.tenant,"cloud-integration").await?,
        "inventory":h.state.configurations.list::<Value>(h.tenant,"cloud-inventory").await?,
        "audit":h.state.store.audit_stats_durable(h.tenant).await?}))
}
pub(super) fn configuration(enabled: bool, version: u64) -> Value {
    json!({"expected_version":version,"enabled":enabled,"mock":true,
        "settings":{"instance_id":"owned-orchestration","region_id":"cn-hangzhou","account_id":"owned-no-cloud"}})
}
pub(super) async fn prepared() -> (Harness, Value) {
    let h = setup().await;
    assert_eq!(h.request("PUT", CONFIG, Some(&h.admin), Some(configuration(true, 0))).await.status, StatusCode::OK);
    assert_eq!(
        h.post(
            "/api/v1/alicloud/agentteams/sync",
            json!({"request_id":Id::new(),"configuration_version":1,"confirm_live":false})
        )
        .await
        .status,
        StatusCode::OK
    );
    let response = h.get(BASE).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json()["modeSupported"], true);
    let target = response.json()["teams"][0].clone();
    (h, target)
}
pub(super) fn path(target: &Value) -> String {
    format!("{BASE}/teams/{}", target["teamName"].as_str().unwrap())
}
pub(super) fn definition(target: &Value) -> Value {
    let mut doc = target["template"].clone();
    doc["nodes"] = json!([{"node_id":"first","name":"Owned original declaration","agent_ids":[target["workers"][0]["name"]],"depends_on":[],"trigger":"manual"}]);
    doc
}
pub(super) fn input(target: &Value, version: u64, change: Value) -> Value {
    json!({"request_id":Id::new(),"expected_version":version,"configuration_version":target["source"]["configurationVersion"],
        "inventory_fingerprint":target["source"]["inventoryFingerprint"],"change":change,
        "confirm_application_owned":true,"confirm_mock_sync":true,"confirm_source_change":false})
}
pub(super) async fn save(h: &Harness, target: &Value, body: Value) -> Resp {
    h.request("PUT", &path(target), Some(&h.admin), Some(body)).await
}
