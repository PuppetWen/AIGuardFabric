#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::*;

async fn create(h: &Harness) -> Value {
    let response =
        h.post("/api/v1/reports/schedules", json!({"name":"before","cron":"0 0 * * *","format":"json"})).await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
    response.json()["schedule"].clone()
}

#[tokio::test]
async fn stale_toggle_and_delete_cannot_overwrite_another_administrators_plan() {
    let h = setup().await;
    let row = create(&h).await;
    let path = format!("/api/v1/reports/schedules/{}", row["id"].as_str().unwrap());
    let paused = h.request("PATCH", &path, Some(&h.admin), Some(json!({"enabled":false,"expected_version":1}))).await;
    assert_eq!(paused.status, StatusCode::OK, "{}", paused.text);
    assert_eq!(paused.json()["version"], 2);
    assert_eq!(
        h.request("PATCH", &path, Some(&h.admin), Some(json!({"enabled":true,"expected_version":1}))).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        h.request("PATCH", &path, Some(&h.admin), Some(json!({"enabled":true}))).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        h.request("DELETE", &format!("{path}?expected_version=1"), Some(&h.admin), None).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(h.request("DELETE", &path, Some(&h.admin), None).await.status, StatusCode::BAD_REQUEST);
    let still_saved = h.get("/api/v1/reports/schedules").await.json();
    assert_eq!(still_saved["items"][0]["enabled"], false);
    assert_eq!(still_saved["items"][0]["version"], 2);
    assert_eq!(
        h.request("DELETE", &format!("{path}?expected_version=2"), Some(&h.admin), None).await.status,
        StatusCode::OK
    );
    let deleted = h.get("/api/v1/audit?actor=report-schedule-delete&action=delete").await.json();
    assert_eq!(deleted["total"], 1);
    assert_eq!(deleted["items"][0]["target"]["id"], row["id"]);
}

#[tokio::test]
async fn edit_preserves_history_rejects_stale_data_and_renders_new_content() {
    let h = setup().await;
    let row = create(&h).await;
    let path = format!("/api/v1/reports/schedules/{}", row["id"].as_str().unwrap());
    let first = h.post(&format!("{path}/run"), json!({})).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    let manual_audit = h.get("/api/v1/audit?actor=report-schedule-run&action=export").await.json();
    assert_eq!(manual_audit["total"], 1);
    assert_eq!(manual_audit["items"][0]["target"]["id"], first.json()["report"]["id"]);
    let change = json!({"expected_version":row["version"],"name":"after","kind":"findings",
        "format":"csv","cron":"30 4 * * MON","window_secs":604_800,"channel_ids":[]});
    let saved = h.request("PATCH", &path, Some(&h.admin), Some(change.clone())).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.json()["version"], 2);
    assert_eq!(saved.json()["name"], "after");
    assert_eq!(saved.json()["window_secs"], 604_800);
    assert_eq!(saved.json()["last_report_id"], first.json()["report"]["id"]);
    assert_eq!(h.request("PATCH", &path, Some(&h.admin), Some(change)).await.status, StatusCode::CONFLICT);
    let second = h.post(&format!("{path}/run"), json!({})).await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.text);
    assert_ne!(first.json()["report"]["id"], second.json()["report"]["id"]);
    assert_eq!(second.json()["report"]["format"], "csv");
    assert_eq!(second.json()["report"]["title"], "after");
    assert_eq!(h.get("/api/v1/reports").await.json()["total"], 2);
}

#[tokio::test]
async fn selected_channels_are_tenant_scoped_private_and_deliver_report_subscriptions() {
    let h = setup().await;
    let saved = h
        .request(
            "PUT",
            "/api/v1/settings/notifications/in-app",
            Some(&h.admin),
            Some(json!({"enabled":true,"minSeverity":"critical","settings":{},"secrets":{}})),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let channels = h.get("/api/v1/reports/channels").await;
    assert_eq!(channels.status, StatusCode::OK, "{}", channels.text);
    let list = channels.json();
    let channel = list["items"][0]["id"].clone();
    assert_eq!(list["items"][0].as_object().unwrap().len(), 3, "only id, channel and enabled are public");
    let row = create(&h).await;
    let path = format!("/api/v1/reports/schedules/{}", row["id"].as_str().unwrap());
    let updated = h
        .request("PATCH", &path, Some(&h.admin), Some(json!({"expected_version":1,"channel_ids":[channel,channel]})))
        .await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.text);
    assert_eq!(updated.json()["channel_ids"].as_array().unwrap().len(), 1);
    assert_eq!(h.post(&format!("{path}/run"), json!({})).await.status, StatusCode::OK);
    let inbox = h.state.configurations.list::<Value>(h.tenant, "notification-inbox").await.unwrap();
    assert_eq!(inbox.len(), 1, "alert severity threshold must not suppress a report subscription");
    let other = h.post("/api/v1/tenants", json!({"slug":"report-other","name":"Other"})).await.json();
    let denied = h
        .request_with(
            "POST",
            "/api/v1/reports/schedules",
            &[("Authorization", &format!("Bearer {}", h.admin)), ("X-AGF-Tenant", other["id"].as_str().unwrap())],
            Some(json!({"name":"cross","cron":"0 0 * * *","channel_ids":[channel]})),
        )
        .await;
    assert_eq!(denied.status, StatusCode::BAD_REQUEST);
    let unknown = h
        .request(
            "PATCH",
            &path,
            Some(&h.admin),
            Some(json!({"expected_version":2,"channel_ids":[agf_core::ids::Id::new()]})),
        )
        .await;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn running_plan_cannot_be_edited_and_pause_does_not_change_artifact_identity() {
    use agf_api::report_service::{SCHEDULES, ScheduleRecord};
    let h = setup().await;
    let row = create(&h).await;
    let id = agf_core::ids::Id::parse(row["id"].as_str().unwrap()).unwrap();
    h.state
        .configurations
        .mutate::<ScheduleRecord, _>(h.tenant, SCHEDULES, id, |row| {
            row.lease_until = Some(Timestamp::now().offset_secs(300));
            row.claimed_at = Some(Timestamp::now());
            Ok(())
        })
        .await
        .unwrap();
    let path = format!("/api/v1/reports/schedules/{id}");
    let edited = h.request("PATCH", &path, Some(&h.admin), Some(json!({"expected_version":1,"name":"busy"}))).await;
    assert_eq!(edited.status, StatusCode::CONFLICT);
    let paused = h.request("PATCH", &path, Some(&h.admin), Some(json!({"expected_version":1,"enabled":false}))).await;
    assert_eq!(paused.status, StatusCode::OK, "{}", paused.text);
    assert_eq!(paused.json()["content_version"], row["content_version"]);
    assert_eq!(paused.json()["version"], 2);
    assert!(!paused.json()["claimed_at"].is_null());
    assert_eq!(
        h.request("PATCH", &path, Some(&h.admin), Some(json!({"name":"missing-version"}))).await.status,
        StatusCode::BAD_REQUEST
    );
}
