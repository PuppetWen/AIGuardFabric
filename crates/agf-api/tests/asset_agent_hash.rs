//! The endpoint collector's bounded file digest reaches the governed asset, including unavailable evidence.
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;
use common::*;

#[tokio::test]
async fn endpoint_skill_digests_update_history_and_clear_unavailable_evidence() {
    let h = setup().await;
    let mut body = json!({"collector_id":"hash-collector","hostname":"hash-host",
        "report":{"collector_id":"hash-collector","collected_at":Timestamp::now(),"hostname":"hash-host",
            "os":"windows/x86_64","agents":[],"mcp_configs":[],"credential_hits":[],"scan_scope":[],"agent_version":"0.1.0"},
        "extras":{"skills":[{"name":"Hash verification skill","kind":"skill","source_path":"fixture/SKILL.md",
            "content_sha256":"a".repeat(64),"content_hash_status":"verified"}]}});
    let initial = h.post("/api/v1/ingest/agent", body.clone()).await;
    assert_eq!(initial.status, StatusCode::OK, "{}", initial.text);
    let assets = h.get("/api/v1/assets?q=Hash%20verification%20skill").await.json();
    let id = assets["items"][0]["id"].as_str().unwrap();
    let uri = format!("/api/v1/assets/{id}");
    body["extras"]["skills"][0]["content_sha256"] = json!("b".repeat(64));
    assert_eq!(h.post("/api/v1/ingest/agent", body.clone()).await.status, StatusCode::OK);
    let detail = h.get(&uri).await.json();
    assert_eq!(detail["asset"]["attributes"]["content_sha256"], "b".repeat(64));
    assert!(
        detail["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["field"] == "content_sha256" && row["risky"] == true)
    );
    body["extras"]["skills"][0]["content_sha256"] = Value::Null;
    body["extras"]["skills"][0]["content_hash_status"] = json!("unreadable");
    assert_eq!(h.post("/api/v1/ingest/agent", body.clone()).await.status, StatusCode::OK);
    let unavailable = h.get(&uri).await.json();
    assert!(unavailable["asset"]["attributes"]["content_sha256"].is_null());
    assert_eq!(unavailable["asset"]["attributes"]["content_hash_status"], "unreadable");
    body["extras"]["skills"][0]["content_hash_status"] = json!("verified");
    assert_eq!(h.post("/api/v1/ingest/agent", body.clone()).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(h.get(&uri).await.json()["changes"], unavailable["changes"]);
    body["extras"]["skills"][0]["content_sha256"] = json!("not-a-hash");
    assert_eq!(h.post("/api/v1/ingest/agent", body).await.status, StatusCode::BAD_REQUEST);
}
