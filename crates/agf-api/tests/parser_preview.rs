//! Parser preview reads only bundled fixtures and executes the actual engine without writing events.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
#[tokio::test]
async fn preview_has_roundtrippable_definition_and_actual_sample() {
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).project_root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").to_string_lossy().into_owned();
    h.app = build_router(h.state.clone());
    let path = "/api/v1/parsers/aliyun-waf-webhook/preview";
    assert_eq!(h.request("GET", path, None, None).await.status, StatusCode::UNAUTHORIZED);
    let preview = h.get(path).await;
    assert_eq!(preview.status, StatusCode::OK, "{}", preview.text);
    let data = preview.json();
    let definition: agf_core::parser::ParserDefinition =
        serde_json::from_str(data["definition_json"].as_str().unwrap()).unwrap();
    assert_eq!(definition.key, "aliyun-waf-webhook");
    assert!(!data["sample_raw"].as_str().unwrap().is_empty());
    assert_eq!(data["outcome"]["matched"], true);
    for key in ["aliyun-waf-sls-json", "aliyun-sas-baseline-json"] {
        let preview = h.get(&format!("/api/v1/parsers/{key}/preview")).await;
        assert_eq!(preview.status, StatusCode::OK, "{}", preview.text);
        assert!(preview.json()["sample_raw"].as_str().is_some_and(|raw| !raw.is_empty()), "{key}: {}", preview.text);
        assert_eq!(preview.json()["outcome"]["matched"], true, "{key}: {}", preview.text);
    }
    let before = h.state.ingest_sink.event_count(h.tenant).await.unwrap();
    let parsed = h.post("/api/v1/parsers/aliyun-waf-webhook/test", json!({"sample":data["sample_raw"]})).await;
    assert_eq!(parsed.status, StatusCode::OK, "{}", parsed.text);
    assert_eq!(parsed.json()["matched"], true);
    assert!(!parsed.json()["fields"].as_object().unwrap().is_empty());
    assert_eq!(h.state.ingest_sink.event_count(h.tenant).await.unwrap(), before);
    let invalid = h.post("/api/v1/parsers/aliyun-waf-webhook/test", json!({"sample":"this is not WAF JSON"})).await;
    assert_eq!(invalid.status, StatusCode::OK);
    assert_eq!(invalid.json()["matched"], false);
    assert_eq!(
        h.post("/api/v1/parsers/aliyun-waf-webhook/test", json!({"sample":"x".repeat(65537)})).await.status,
        StatusCode::BAD_REQUEST
    );
}
