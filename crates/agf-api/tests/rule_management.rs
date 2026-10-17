//! Published rules affect the real scanner without restart and are isolated by tenant.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;

fn definition() -> String {
    "key: TENANT-CUSTOM\nname: Test marker\ndomain: prompt-attack\nseverity: high\nkind: keyword\ntarget: prompt\naction: deny\ndetection:\n  type: keyword\n  any: [uniqueTenantMarker]\nsamples:\n  positive: [uniqueTenantMarker]\n  negative: [clean]\n".into()
}

#[tokio::test]
async fn zero_rollout_still_validates_samples_without_matching_normal_scans() {
    let h = setup().await;
    let source = format!("{}rollout_percent: 0\n", definition());
    let published = h.post("/api/v1/rules", json!({"yaml":source,"expectedVersion":0})).await;
    assert_eq!(published.status, StatusCode::OK, "{}", published.text);
    assert_eq!(h.post("/api/v1/rules/TENANT-CUSTOM/regression", json!({})).await.json()["passed"], true);
    let scan = h
        .post("/api/v1/scans", json!({"targets":[{"label":"sample","kind":"prompt","text":"uniqueTenantMarker"}]}))
        .await;
    assert!(scan.json()["job"]["rule_hits"].get("TENANT-CUSTOM").is_none(), "{}", scan.text);
}

#[tokio::test]
async fn publish_disable_restore_and_regression_failure_are_real() {
    let h = setup().await;
    let created = h.post("/api/v1/rules", json!({"yaml":definition()})).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    let path = "/api/v1/rules/TENANT-CUSTOM";
    let target = json!({"targets":[{"label":"sample","kind":"prompt","text":"uniqueTenantMarker"}]});
    let scan = h.post("/api/v1/scans", target.clone()).await;
    assert_eq!(scan.json()["job"]["rule_hits"]["TENANT-CUSTOM"], 1, "{}", scan.text);
    let patched = h.request("PATCH", path, Some(&h.admin), Some(json!({"enabled":false}))).await;
    assert_eq!(patched.status, StatusCode::OK, "{}", patched.text);
    let scan = h.post("/api/v1/scans", target.clone()).await;
    assert!(scan.json()["job"]["rule_hits"].get("TENANT-CUSTOM").is_none());
    let invalid = h
        .post(
            "/api/v1/rules",
            json!({"yaml":definition().replace("negative: [clean]","negative: [uniqueTenantMarker]")}),
        )
        .await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST, "{}", invalid.text);
    assert_eq!(h.get(path).await.json()["rule"]["version"], 2);
    let restored = h.post(&format!("{path}/versions/1/restore"), json!({})).await;
    assert_eq!(restored.status, StatusCode::OK, "{}", restored.text);
    assert_eq!(restored.json()["rule"]["version"], 3);
    assert_eq!(h.post("/api/v1/scans", target).await.json()["job"]["rule_hits"]["TENANT-CUSTOM"], 1);
    assert_eq!(h.get(&format!("{path}/versions")).await.json()["items"].as_array().unwrap().len(), 3);
    let cross = h
        .request_with(
            "GET",
            path,
            &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &h.other_tenant.to_string())],
            None,
        )
        .await;
    assert_eq!(cross.status, StatusCode::NOT_FOUND);
    let denied = h.request("POST", "/api/v1/rules", Some(&h.viewer), Some(json!({"yaml":definition()}))).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
}
