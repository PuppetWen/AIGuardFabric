//! 规则发布需要正负样本通过；读写角色、租户及版本冲突一致。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;

#[tokio::test]
async fn configuration_preview_versions_and_permissions() {
    let h = setup().await;
    let examples = h.get("/api/v1/correlation/examples").await;
    assert_eq!(examples.status, StatusCode::OK, "{}", examples.text);
    let definitions = examples.json()["items"].as_array().unwrap().clone();
    assert_eq!(definitions.len(), 4);
    for (index, value) in definitions.iter().enumerate() {
        let mut definition = value["definition"].clone();
        assert_eq!(h.post("/api/v1/correlation/validate", definition.clone()).await.json()["passed"], true);
        definition["enabled"] = json!(true);
        let saved = h.post("/api/v1/correlation/rules", json!({"definition":definition,"expected_version":0})).await;
        assert_eq!(saved.status, StatusCode::OK, "{index}: {}", saved.text);
        assert_eq!(saved.json()["current"]["version"], 1);
        assert_eq!(
            h.post("/api/v1/correlation/rules", json!({"definition":definition,"expected_version":0})).await.status,
            StatusCode::CONFLICT
        );
        definition["enabled"] = json!(false);
        let disabled = h.post("/api/v1/correlation/rules", json!({"definition":definition,"expected_version":1})).await;
        assert_eq!(disabled.json()["current"]["version"], 2);
        let forbidden = h
            .request(
                "POST",
                "/api/v1/correlation/rules",
                Some(&h.viewer),
                Some(json!({"definition":definition,"expected_version":2})),
            )
            .await;
        assert_eq!(forbidden.status, StatusCode::FORBIDDEN);
    }
    let listed = h.get("/api/v1/correlation/rules").await.json();
    assert_eq!(listed["items"].as_array().unwrap().len(), 4);
    assert_eq!(listed["items"][0]["history"].as_array().unwrap().len(), 2);
    assert!(agf_api::correlation::registry::get(&h.state, h.other_tenant).await.unwrap().entries.is_empty());
    let mut bad = definitions[0]["definition"].clone();
    bad["positive"] = bad["negative"].clone();
    assert_eq!(h.post("/api/v1/correlation/validate", bad.clone()).await.json()["passed"], false);
    assert_eq!(
        h.post("/api/v1/correlation/rules", json!({"definition":bad,"expected_version":2})).await.status,
        StatusCode::BAD_REQUEST
    );
}
