//! Effective Mock/Live mode is part of a collector's frozen resource identity.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::ids::Id;
use common::*;

const SOURCES: &str = "/api/v1/alicloud/agentteams/audit-sources";

async fn fixture(explicit_mock: bool) -> (Harness, Id, Value) {
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = true;
    h.app = build_router(h.state.clone());
    let cloud = h
        .request(
            "PUT",
            "/api/v1/alicloud/connections/alicloud-agentteams",
            Some(&h.admin),
            Some(json!({"expected_version":0,"enabled":true,"mock":explicit_mock,
            "settings":{"instance_id":"mode-boundary"}})),
        )
        .await;
    assert_eq!(cloud.status, StatusCode::OK, "{}", cloud.text);
    let inventory = h
        .post(
            "/api/v1/alicloud/agentteams/sync",
            json!({"request_id":Id::new(),"configuration_version":1,"confirm_live":false}),
        )
        .await;
    assert_eq!(inventory.status, StatusCode::OK, "{}", inventory.text);
    let source = h.post("/api/v1/ingest/sources", json!({"name":"mode-boundary","protocol":"http-webhook"})).await;
    assert_eq!(source.status, StatusCode::CREATED, "{}", source.text);
    let id = Id::parse(source.json()["id"].as_str().unwrap()).unwrap();
    let bound = h
        .request("PUT", &format!("{SOURCES}/{id}"), Some(&h.admin), Some(json!({"expected_version":0,"enabled":true})))
        .await;
    assert_eq!(bound.status, StatusCode::OK, "{}", bound.text);
    assert_eq!(bound.json()["mocked"], true);
    (h, id, bound.json())
}

async fn push(h: &Harness, source: Id, binding: &Value) -> Resp {
    h.post(
        &format!("{SOURCES}/{source}/events"),
        json!({"binding_id":binding["bindingId"],
        "events":[{"event_id":Id::new().to_string(),"event_time":Timestamp::now(),"kind":"heartbeat"}]}),
    )
    .await
}

#[tokio::test]
async fn turning_off_environment_mock_invalidates_a_mock_inventory_without_a_cloud_revision_change() {
    let (mut h, id, bound) = fixture(false).await;
    let before = h.state.ingest_sink.event_count(h.tenant).await.unwrap();
    assert!(agf_api::agentteams_audit::binding::context(&h.state, h.tenant).await.unwrap().is_some());
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    assert!(agf_api::agentteams_audit::binding::context(&h.state, h.tenant).await.is_err());
    assert_eq!(push(&h, id, &bound).await.status, StatusCode::CONFLICT);
    assert_eq!(h.state.ingest_sink.event_count(h.tenant).await.unwrap(), before);
    assert_eq!(h.state.ingest_sink.raw_count(h.tenant).await.unwrap(), 0);
    let stored = agf_api::agentteams_audit::binding::load(&h.state, h.tenant, id).await.unwrap().unwrap();
    assert_eq!(stored.binding_id.to_string(), bound["bindingId"].as_str().unwrap());
    assert!(stored.mocked, "rejected ingestion must not relabel recorded Mock identity");
}

#[tokio::test]
async fn an_explicit_mock_cloud_remains_mock_when_environment_changes_and_a_mislabeled_binding_is_rejected() {
    let (mut h, id, bound) = fixture(true).await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    h.app = build_router(h.state.clone());
    assert_eq!(push(&h, id, &bound).await.status, StatusCode::OK);
    let before = h.state.ingest_sink.event_count(h.tenant).await.unwrap();
    let mut stored = agf_api::agentteams_audit::binding::load(&h.state, h.tenant, id).await.unwrap().unwrap();
    stored.mocked = false;
    h.state.configurations.put(h.tenant, agf_api::agentteams_audit::binding::KIND, id, &stored).await.unwrap();
    assert_eq!(push(&h, id, &bound).await.status, StatusCode::CONFLICT);
    assert_eq!(h.state.ingest_sink.event_count(h.tenant).await.unwrap(), before);
}
