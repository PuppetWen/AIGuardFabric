//! Candidate HTTP contract covers actual anonymous/read-only behavior; no provider or database.
mod common;
use common::*;

#[tokio::test]
async fn receipt_get_is_pure_and_never_initializes_an_unknown_attempt() {
    let h = setup().await;
    let id = agf_core::ids::Id::new();
    let path = format!("/api/v1/gateway/attempts/{id}");
    let before = h.state.store.audit_chain_durable(h.tenant, 0, i64::MAX).await;
    assert_eq!(h.request("GET", &path, None, None).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(h.get(&path).await.status, StatusCode::NOT_FOUND);
    let after = h.state.store.audit_chain_durable(h.tenant, 0, i64::MAX).await;
    assert!(before.is_ok() && after.is_ok());
    assert_eq!(serde_json::to_value(before.ok()).ok(), serde_json::to_value(after.ok()).ok());
    for kind in [
        "gateway-attempt-fact-v1",
        "gateway-attempt-active-v1",
        "gateway-settlement-pending-v1",
        "gateway-rejection-fact-v1",
    ] {
        let rows = h.state.configurations.list::<Value>(h.tenant, kind).await;
        assert!(rows.is_ok_and(|rows| rows.is_empty()));
    }
    assert_eq!(h.state.meter.snapshot().total.calls, 0);
}
#[tokio::test]
async fn openapi_pins_pure_get_empty_local_recovery_and_never_grants_execution() {
    let h = setup().await;
    let document = h.get("/api/v1/openapi.json").await;
    assert_eq!(document.status, StatusCode::OK);
    let doc = document.json();
    let root = "/api/v1/gateway/attempts/{id}";
    let recover = format!("{root}/recover");
    assert_eq!(doc["paths"][root]["get"]["x-required-permissions"], json!(["models:read"]));
    assert_eq!(doc["paths"][&recover]["post"]["x-required-permissions"], json!(["models:write"]));
    assert_eq!(doc["components"]["schemas"]["GatewaySettlementRecovery"]["additionalProperties"], false);
    let receipt = &doc["components"]["schemas"]["GatewaySettlementReceipt"];
    assert_eq!(receipt["properties"]["mayExecute"]["const"], false);
    assert!(receipt["required"].as_array().is_some_and(|fields| fields.contains(&json!("components"))));
    assert_eq!(receipt["properties"]["components"]["type"], json!(["array", "null"]));
    assert_eq!(receipt["properties"]["components"]["maxItems"], 8);
    assert_eq!(receipt["properties"]["components"]["items"]["additionalProperties"], false);
    assert_eq!(receipt["properties"]["components"]["items"]["required"], json!(["usageId", "evidence", "costMicro"]));
    assert_eq!(
        receipt["properties"]["components"]["items"]["properties"]["evidence"]["enum"],
        json!(["not-sent", "local-reply", "sent-usage-known", "sent-usage-partial", "sent-usage-unknown"])
    );
    assert!(
        receipt["properties"]["outcomeEvidence"]["enum"]
            .as_array()
            .is_some_and(|values| values.contains(&json!("sent-usage-partial")))
    );
    assert!(doc["paths"][root]["get"]["description"].as_str().is_some_and(|s| s.contains("Pure local read")));
    assert!(doc["paths"][recover]["post"]["description"].as_str().is_some_and(|s| s.contains("Does not dispatch")));
}
