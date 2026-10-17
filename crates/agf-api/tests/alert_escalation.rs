//! Escalation settings validate writes and retain drafts through version conflicts.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;

#[tokio::test]
async fn policy_permissions_validation_and_versions() {
    let h = setup().await;
    let path = "/api/v1/alerts/escalation-config";
    assert_unauthorized(&h, "GET", path, None).await;
    let initial = h.get(path).await.json();
    assert_eq!(initial["version"], 0);
    assert_eq!(initial["canWrite"], true);
    assert_eq!(initial["automaticAvailable"], false);
    assert_eq!(initial["policies"].as_array().unwrap().len(), 5);
    let routes: Vec<_> = initial["policies"].as_array().unwrap().iter().map(|p| p["route"].clone()).collect();
    assert!(routes.iter().all(|r| r["enabled"] == false));
    let mut body = json!({"expectedVersion":0,"routes":routes,"reason":"initial draft"});
    let viewer = h.request("GET", path, Some(&h.viewer), None).await.json();
    assert_eq!(viewer["canWrite"], false);
    assert_eq!(h.request("PUT", path, Some(&h.viewer), Some(body.clone())).await.status, StatusCode::FORBIDDEN);
    let saved = h.request("PUT", path, Some(&h.admin), Some(body.clone())).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.json()["version"], 1);
    assert_eq!(saved.json()["history"][0]["reason"], "initial draft");
    assert_eq!(h.request("PUT", path, Some(&h.admin), Some(body.clone())).await.status, StatusCode::CONFLICT);
    body["expectedVersion"] = json!(1);
    for mutation in 0..5 {
        let mut invalid = body.clone();
        match mutation {
            0 => invalid["routes"][0]["responseMinutes"] = json!(0),
            1 => invalid["routes"][0]["tiers"][1]["overdueMinutes"] = json!(0),
            2 => invalid["routes"][0]["tiers"][0]["level"] = json!(2),
            3 => invalid["reason"] = json!(" "),
            _ => invalid["routes"][1]["severity"] = json!("critical"),
        }
        let response = h.request("PUT", path, Some(&h.admin), Some(invalid)).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{}", response.text);
    }
    body["routes"][0]["enabled"] = json!(true);
    assert_eq!(
        h.request("PUT", path, Some(&h.admin), Some(body.clone())).await.status,
        StatusCode::PRECONDITION_FAILED
    );
    let key = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("alerts:*")],
        ..ApiKeyIssueRequest::named(h.tenant, "machine", Timestamp::now())
    });
    h.state.store.api_key_create_durable(&key.record).await.unwrap();
    assert_eq!(h.request_with("GET", path, &[("x-agf-key", &key.plaintext)], None).await.json()["canWrite"], false);
    assert_eq!(
        h.request_with("PUT", path, &[("x-agf-key", &key.plaintext)], Some(body)).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(h.get(path).await.json()["version"], 1);
    assert_eq!(h.get("/api/v1/alerts/escalation-history").await.json()["total"], 0);
}
