//! 回滚应增加新版本，编译失败不能破坏当前生效版本。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;
#[tokio::test]
async fn history_rollback_and_invalid_dsl_are_transactional() {
    let h = setup().await;
    let policy = json!({"name":"history-test","language":"cel","source":"{\"action\":\"audit\"}","action":"audit"});
    let created = h.post("/api/v1/policies", policy.clone()).await;
    let id = created.json()["policy"]["id"].as_str().unwrap().to_owned();
    let changed = h
        .request(
            "PUT",
            &format!("/api/v1/policies/{id}"),
            Some(&h.admin),
            Some(json!({"name":"history-test","language":"cel","source":"{\"action\":\"deny\"}","action":"deny","expected_version":1})),
        )
        .await;
    assert_eq!(changed.json()["policy"]["version"], 2);
    let bad = h
        .request(
            "PUT",
            &format!("/api/v1/policies/{id}"),
            Some(&h.admin),
            Some(json!({"name":"history-test","language":"cel","source":"this is not valid cel","action":"deny","expected_version":2})),
        )
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST, "{}", bad.text);
    assert_eq!(h.get(&format!("/api/v1/policies/{id}")).await.json()["policy"]["version"], 2);
    let restored =
        h.post(&format!("/api/v1/policies/{id}/versions/1/restore"), json!({"version":1,"expected_version":2})).await;
    assert_eq!(restored.status, StatusCode::OK, "{}", restored.text);
    assert_eq!(restored.json()["policy"]["version"], 3);
    assert_eq!(restored.json()["policy"]["action"], "audit");
    assert_eq!(h.get(&format!("/api/v1/policies/{id}/versions")).await.json()["versions"].as_array().unwrap().len(), 3);
}
