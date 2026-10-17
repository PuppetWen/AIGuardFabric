#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod cms_queue_support;
mod common;
use agf_core::{error::DomainResult, ids::Id};
use cms_queue_support::*;
use common::*;
fn shape(document: &Value, rule: &Value, value: &Value) -> bool {
    if let Some(reference) = rule["$ref"].as_str() {
        return shape(document, document.pointer(reference.strip_prefix('#').unwrap()).unwrap(), value);
    }
    if let Some(options) = rule["anyOf"].as_array() {
        return options.iter().any(|rule| shape(document, rule, value));
    }
    if let Some(options) = rule["oneOf"].as_array() {
        return options.iter().filter(|rule| shape(document, rule, value)).count() == 1;
    }
    if let Some(options) = rule["enum"].as_array() {
        if !options.contains(value) {
            return false;
        }
    }
    if let Some(kind) = rule["type"].as_str() {
        if !match kind {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "integer" => value.is_u64() || value.is_i64(),
            "number" => value.is_number(),
            "string" => value.is_string(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            _ => false,
        } {
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
            if let Some(child) = rule["properties"].get(key) {
                if !shape(document, child, value) {
                    return false;
                }
            } else if rule["additionalProperties"] == false {
                return false;
            }
        }
    }
    if let Some(items) = value.as_array() {
        if rule["maxItems"].as_u64().is_some_and(|max| items.len() as u64 > max) {
            return false;
        }
        if items.iter().any(|item| !shape(document, &rule["items"], item)) {
            return false;
        }
    }
    true
}
#[tokio::test]
async fn seven_public_operations_have_fixed_grants_strict_inputs_and_truthful_boundaries() -> DomainResult<()> {
    let h = setup().await;
    let document = get(&h, "/api/v1/openapi.json").await?;
    let paths = document["paths"].as_object().ok_or_else(|| error("paths missing"))?;
    let actual = paths
        .iter()
        .filter(|(path, _)| path.starts_with(BASE))
        .map(|(_, value)| {
            value.as_object().unwrap().keys().filter(|key| ["get", "post"].contains(&key.as_str())).count()
        })
        .sum::<usize>();
    assert_eq!(actual, 7);
    for (suffix, method) in [
        ("", "get"),
        ("/items/{id}", "get"),
        ("/requests/{id}", "get"),
        ("/enqueue", "post"),
        ("/send", "post"),
        ("/items/{id}/recover-local", "post"),
        ("/archive", "post"),
    ] {
        let op = &document["paths"][format!("{BASE}{suffix}")][method];
        assert_eq!(
            op["x-required-permissions"],
            if method == "get" { json!(["alicloud:read"]) } else { json!(["alicloud:read", "alicloud:write"]) }
        );
        assert_eq!(op["security"], json!([{"bearerAuth":[]},{"apiKey":[]}]));
        let text = op["description"].as_str().unwrap();
        assert!(text.contains("无ClientToken") && text.contains("Unknown") && text.contains("不发送"));
    }
    assert_eq!(document["components"]["schemas"]["CmsQueueRecoverInput"]["additionalProperties"], false);
    assert_eq!(document["components"]["schemas"]["CmsQueueArchiveInput"]["properties"]["item_ids"]["maxItems"], 32);
    Ok(())
}
#[tokio::test]
async fn actual_mock_state_receipt_and_archived_item_match_closed_schemas() -> DomainResult<()> {
    let h = setup().await;
    let document = get(&h, "/api/v1/openapi.json").await?;
    configure(&h, 0, true).await?;
    let state = get(&h, BASE).await?;
    assert!(shape(&document, &document["components"]["schemas"]["CmsQueueState"], &state));
    let (item, request, receipt) = accepted(&h).await?;
    assert!(shape(&document, &document["components"]["schemas"]["CmsQueueReceipt"], &receipt));
    let current = get(&h, BASE).await?;
    post(
        &h,
        &format!("{BASE}/archive"),
        json!({"request_id":Id::new(),"expected_generation":number(&current,"generation")?,"item_ids":[item]}),
    )
    .await?;
    let historical = get(&h, &format!("{BASE}/requests/{request}")).await?;
    assert!(shape(&document, &document["components"]["schemas"]["CmsQueueReceipt"], &historical));
    assert_eq!(historical["originalAttempts"], receipt["originalAttempts"]);
    assert!(historical["items"][0]["archivedAt"].is_string());
    Ok(())
}
