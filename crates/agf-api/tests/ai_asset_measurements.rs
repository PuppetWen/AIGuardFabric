//! Resource views must distinguish absent observations from measured zero.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{
    asset::Asset,
    enums::{AssetKind, LifecycleState},
};
use common::*;

#[tokio::test]
async fn absent_invalid_and_zero_measurements_remain_distinct() {
    let h = setup().await;
    for (kind, path, wrapper, fields) in [
        (AssetKind::Agent, "agents", "agent", vec!["activeSessions", "toolCount", "heartbeatIntervalSec"]),
        (AssetKind::McpServer, "mcps", "mcp_server", vec!["toolCount"]),
        (AssetKind::Skill, "skills", "skill", vec!["attachedAgents"]),
        (
            AssetKind::ModelEndpoint,
            "models/endpoints",
            "model_endpoint",
            vec!["inputPricePerKTok", "outputPricePerKTok", "priority", "latencyP95Ms"],
        ),
    ] {
        let mut asset = Asset::new(h.tenant, kind, "unknown-observation", path);
        asset.last_seen_at = None;
        asset.updated_at = Timestamp::now();
        h.state.store.asset_upsert(&asset).unwrap();
        let uri = format!("/api/v1/{path}/{}", asset.id);
        let reply = h.get(&uri).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
        let body = reply.json();
        let view = &body[wrapper];
        for field in &fields {
            assert!(view[*field].is_null(), "{field}: {view}");
        }
        if matches!(kind, AssetKind::Agent | AssetKind::McpServer) {
            assert!(view["online"].is_null(), "{view}");
            assert!(view[if kind == AssetKind::Agent { "lastHeartbeatAt" } else { "lastSeenAt" }].is_null());
        }
        if kind == AssetKind::McpServer {
            assert_eq!(view["transport"], "unknown");
        }
        if kind == AssetKind::ModelEndpoint {
            for field in ["local", "mockMode", "fallback"] {
                assert!(view[field].is_null());
            }
            for (key, value) in [("local_deployment", false), ("mock_mode", true), ("fallback", false)] {
                asset.attributes.insert(key.into(), json!(value));
            }
        }
        for key in [
            "active_sessions",
            "tool_count",
            "attached_agents",
            "input_price_per_ktok",
            "output_price_per_ktok",
            "priority",
            "latency_p95_ms",
        ] {
            asset.attributes.insert(key.into(), json!(0));
        }
        asset.attributes.insert("heartbeat_interval_secs".into(), json!(60));
        h.state.store.asset_upsert(&asset).unwrap();
        let updated = h.get(&uri).await.json();
        if kind == AssetKind::ModelEndpoint {
            assert_eq!(updated[wrapper]["local"], false);
            assert_eq!(updated[wrapper]["mockMode"], true);
            assert_eq!(updated[wrapper]["fallback"], false);
        }
        for field in &fields {
            assert_eq!(
                updated[wrapper][*field].as_f64(),
                Some(if *field == "heartbeatIntervalSec" { 60.0 } else { 0.0 })
            );
        }
        asset.attributes.insert("tool_count".into(), json!(-1));
        asset.attributes.insert("active_sessions".into(), json!("0"));
        asset.attributes.insert("heartbeat_interval_secs".into(), json!(0));
        asset.attributes.insert("input_price_per_ktok".into(), json!(-0.1));
        asset.attributes.insert("priority".into(), json!(u64::MAX));
        h.state.store.asset_upsert(&asset).unwrap();
        let invalid = h.get(&uri).await.json();
        for field in ["toolCount", "activeSessions", "heartbeatIntervalSec", "inputPricePerKTok", "priority"] {
            assert!(invalid[wrapper][field].is_null(), "{field}: {invalid}");
        }
    }
}

#[tokio::test]
async fn observation_status_uses_recorded_time_and_interval_not_edit_time() {
    let h = setup().await;
    let mut asset = Asset::new(h.tenant, AssetKind::Agent, "observation-status", "observation-status");
    let uri = format!("/api/v1/agents/{}", asset.id);
    for (age, interval, lifecycle, expected) in [
        (120, Some(60), LifecycleState::Trial, json!(true)),
        (190, Some(60), LifecycleState::Trial, json!(false)),
        (280, None, LifecycleState::Trial, json!(true)),
        (310, None, LifecycleState::Trial, json!(false)),
        (-60, None, LifecycleState::Trial, Value::Null),
        (0, Some(60), LifecycleState::Archived, json!(false)),
    ] {
        asset.last_seen_at = Some(Timestamp::from_unix_secs(Timestamp::now().unix_secs() - age).unwrap());
        asset.updated_at = Timestamp::now();
        asset.lifecycle = lifecycle;
        asset.attributes.insert("heartbeat_interval_secs".into(), json!(interval));
        h.state.store.asset_upsert(&asset).unwrap();
        let detail = h.get(&uri).await.json();
        assert_eq!(detail["agent"]["online"], expected, "{age}/{interval:?}: {detail}");
        assert_eq!(detail["agent"]["lastHeartbeatAt"], json!(asset.last_seen_at));
    }
}
