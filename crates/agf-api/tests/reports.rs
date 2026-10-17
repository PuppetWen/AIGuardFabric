//! Report formats, schedule execution and tenant boundaries.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;

#[tokio::test]
async fn finding_report_respects_requested_time_window() {
    use agf_core::{
        enums::{RiskDomain, Severity},
        risk::Finding,
    };
    let h = setup().await;
    let mut old =
        Finding::new(h.tenant, RiskDomain::PromptAttack, Severity::High, "test", "old-window-marker", "s", "fix");
    old.first_seen_at = Timestamp::now().offset_secs(-7200);
    let recent =
        Finding::new(h.tenant, RiskDomain::PromptAttack, Severity::High, "test", "new-window-marker", "s", "fix");
    h.state.store.finding_insert(&old).unwrap();
    h.state.store.finding_insert(&recent).unwrap();
    let response = h.post("/api/v1/reports", json!({"kind":"findings","window_secs":3600})).await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
    let json = response.json();
    let markdown = json["report"]["body"].as_str().unwrap();
    assert!(markdown.contains("new-window-marker"));
    assert!(!markdown.contains("old-window-marker"));
}

#[tokio::test]
async fn each_format_downloads_real_content_and_preserves_tenant_boundary() {
    let h = setup().await;
    for (format, mime, prefix) in [
        ("pdf", "application/pdf", "%PDF-1.7"),
        ("html", "text/html", "<!doctype html>"),
        ("markdown", "text/markdown", "# 中文验收报告"),
        ("json", "application/json", "{"),
        ("csv", "text/csv", "\u{feff}line,text"),
    ] {
        let response = h.post("/api/v1/reports", json!({"title":"中文验收报告","format":format})).await;
        assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
        let report = response.json()["report"].clone();
        let path = format!("/api/v1/reports/{}/download", report["id"].as_str().unwrap());
        let downloaded = h.get(&path).await;
        assert_eq!(downloaded.status, StatusCode::OK);
        assert!(downloaded.content_type().starts_with(mime));
        assert!(downloaded.text.starts_with(prefix), "{}", downloaded.text);
        assert_eq!(report["artifact_bytes"].as_u64().unwrap(), downloaded.bytes.len() as u64);
        use sha2::Digest;
        assert_eq!(report["content_hash"], hex::encode(sha2::Sha256::digest(&downloaded.bytes)));
        let other = h
            .request_with(
                "GET",
                &path,
                &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &h.other_tenant.to_string())],
                None,
            )
            .await;
        assert_ne!(other.status, StatusCode::OK);
    }
    assert_eq!(h.post("/api/v1/reports", json!({"format":"docx"})).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(h.post("/api/v1/reports", json!({"window_secs":0})).await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn stored_artifacts_keep_original_bytes_after_renderer_changes() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use sha2::Digest;
    let h = setup().await;
    let created = h.post("/api/v1/reports", json!({"title":"历史报表","format":"pdf"})).await;
    assert_eq!(created.status, StatusCode::CREATED);
    let mut report = created.json()["report"].clone();
    let id = report["id"].as_str().unwrap().parse().unwrap();
    // Model an artifact persisted by an earlier renderer, including non-UTF-8 bytes.
    let original = b"%PDF-1.4\n%\x80\xff legacy artifact\n%%EOF\n";
    report["artifact_base64"] = json!(STANDARD.encode(original));
    report["artifact_bytes"] = json!(original.len());
    report["content_hash"] = json!(hex::encode(sha2::Sha256::digest(original)));
    h.state.configurations.put(h.tenant, agf_api::report_service::REPORTS, id, &report).await.unwrap();
    let downloaded = h.get(&format!("/api/v1/reports/{id}/download")).await;
    assert_eq!(downloaded.status, StatusCode::OK);
    assert_eq!(downloaded.bytes, original);
}

#[tokio::test]
async fn scheduler_generates_once_per_minute_and_honors_pause_and_delete() {
    let h = setup().await;
    assert_eq!(h.get("/api/v1/reports/schedules").await.json()["total"], 0);
    let created = h.post("/api/v1/reports/schedules", json!({"name":"minute","cron":"* * * * *","format":"pdf"})).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let id = created.json()["schedule"]["id"].as_str().unwrap().to_owned();
    // Keep both observations within one minute, even when the wall clock is at xx:xx:59.
    let now = Timestamp::from_unix_secs(Timestamp::now().unix_secs() / 60 * 60 + 10).unwrap();
    let (a, b) =
        tokio::join!(agf_api::report_service::tick(&h.state, now), agf_api::report_service::tick(&h.state, now));
    assert_eq!(a.unwrap() + b.unwrap(), 1);
    assert_eq!(agf_api::report_service::tick(&h.state, now.offset_secs(1)).await.unwrap(), 0);
    let reports = h.get("/api/v1/reports").await.json();
    assert_eq!(reports["total"], 1);
    assert_eq!(reports["items"][0]["schedule_id"], id);
    let path = format!("/api/v1/reports/schedules/{id}");
    let version = h.get("/api/v1/reports/schedules").await.json()["items"][0]["version"].as_u64().unwrap();
    let paused =
        h.request("PATCH", &path, Some(&h.admin), Some(json!({"enabled":false,"expected_version":version}))).await;
    assert_eq!(paused.status, StatusCode::OK, "{}", paused.text);
    assert_eq!(agf_api::report_service::tick(&h.state, now.offset_secs(120)).await.unwrap(), 0);
    assert_eq!(h.post(&format!("{path}/run"), json!({})).await.status, StatusCode::OK);
    let retained = h.get("/api/v1/reports").await.json()["total"].clone();
    assert_eq!(
        h.request("DELETE", &format!("{path}?expected_version={}", paused.json()["version"]), Some(&h.admin), None)
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(h.get("/api/v1/reports/schedules").await.json()["total"], 0);
    assert_eq!(h.post(&format!("{path}/run"), json!({})).await.status, StatusCode::NOT_FOUND);
    assert_eq!(h.get("/api/v1/reports").await.json()["total"], retained, "deleting a schedule must keep reports");
}
