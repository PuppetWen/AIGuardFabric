//! Stable notification channel names match configuration routes and survive legacy JSON.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::notify::ChannelKind;
use common::*;

#[tokio::test]
async fn published_channel_names_roundtrip_through_save_and_test_routes() {
    let h = setup().await;
    let listed = h.get("/api/v1/settings/notifications").await.json();
    for kind in ChannelKind::all() {
        assert!(listed.as_array().unwrap().iter().any(|row| row["channel"] == kind.as_str()));
        assert_eq!(serde_json::to_value(kind).unwrap(), kind.as_str());
    }
    for (name, legacy, target, secrets) in [
        ("dingtalk", "ding-talk", "https://oapi.dingtalk.com/robot/send?access_token=test", json!({})),
        ("wecom", "we-com", "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test", json!({})),
        ("pagerduty", "pager-duty", "", json!({"routing_key":"test-routing-key"})),
    ] {
        let saved = h
            .request(
                "PUT",
                &format!("/api/v1/settings/notifications/{name}"),
                Some(&h.admin),
                Some(json!({"enabled":true,"target":target,"settings":{},"secrets":secrets})),
            )
            .await;
        assert_eq!(saved.status, StatusCode::OK, "{name}: {}", saved.text);
        assert_eq!(saved.json()["channel"], name);
        let sent = h.post(&format!("/api/v1/settings/notifications/{name}/test"), json!({})).await;
        assert_eq!(sent.status, StatusCode::OK, "{name}: {}", sent.text);
        assert_eq!(sent.json()["any_delivered"], true, "{}", sent.text);
        let old: ChannelKind = serde_json::from_value(json!(legacy)).unwrap();
        assert_eq!(old.as_str(), name);
        assert_eq!(agf_api::notification_config::parse(legacy).unwrap(), old);
    }
    assert_eq!(listed.as_array().unwrap().iter().find(|row| row["channel"] == "in-app").unwrap()["mocked"], false);
}

#[tokio::test]
async fn api_key_profile_exposes_only_its_actual_grants() {
    let h = setup().await;
    let me = h.request_with("GET", "/api/v1/auth/me", &[("x-agf-key", &h.api_key)], None).await;
    assert_eq!(me.status, StatusCode::OK, "{}", me.text);
    assert_eq!(me.json()["permissions"], json!(["assets:*"]));
    assert_eq!(me.json()["read_only"], false);
    assert_eq!(me.json()["user"], Value::Null);
    let viewer = h.request("GET", "/api/v1/auth/me", Some(&h.viewer), None).await;
    assert_eq!(viewer.json()["read_only"], true);
}
