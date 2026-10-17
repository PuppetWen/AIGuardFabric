//! Audit bindings use the same complete relationship evidence as inventory views.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
#[path = "cloud_relations_helpers/mod.rs"]
mod relations;
use agf_api::agentteams_audit::binding;
use agf_core::ids::Id;
use common::*;
use relations::*;

struct Collector {
    source: Id,
    key: String,
    binding: Value,
}
async fn collector(f: &Fixture) -> Collector {
    let source =
        f.h.post("/api/v1/ingest/sources", json!({"name":"relationship-collector","protocol":"http-webhook"})).await;
    assert_eq!(source.status, StatusCode::CREATED, "{}", source.text);
    let source = Id::parse(source.json()["id"].as_str().unwrap()).unwrap();
    let bound =
        f.h.request(
            "PUT",
            &format!("{SOURCES}/{source}"),
            Some(&f.h.admin),
            Some(json!({"expected_version":0,"enabled":true})),
        )
        .await;
    assert_eq!(bound.status, StatusCode::OK, "{}", bound.text);
    Collector { source, key: source_key(&f.h, f.h.tenant), binding: bound.json() }
}
fn source_key(h: &Harness, tenant: TenantId) -> String {
    let issued = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![
            Permission::from_raw("sources:write"),
            Permission::from_raw("sources:read"),
            Permission::from_raw("alicloud:read"),
        ],
        ..ApiKeyIssueRequest::named(tenant, "relationship-collector", Timestamp::now())
    });
    h.state.store.api_key_insert(issued.record).unwrap();
    issued.plaintext
}
async fn push(f: &Fixture, collector: &Collector, event: Value) -> Resp {
    f.h.request(
        "POST",
        &format!("{SOURCES}/{}/events", collector.source),
        Some(&collector.key),
        Some(json!({"binding_id":collector.binding["bindingId"],"events":[event]})),
    )
    .await
}
fn heartbeat() -> Value {
    json!({"event_id":Id::new().to_string(),"event_time":Timestamp::now(),"kind":"heartbeat"})
}
fn message(worker: &str, team: Option<&str>) -> Value {
    let mut value = json!({"event_id":Id::new().to_string(),"event_time":Timestamp::now(),"kind":"message",
        "from_worker":worker,"message":"actual collector message"});
    if let Some(team) = team {
        value["from_team"] = json!(team);
    }
    value
}
async fn counts(f: &Fixture) -> (u64, u64) {
    (
        f.h.state.ingest_sink.event_count(f.h.tenant).await.unwrap(),
        f.h.state.ingest_sink.raw_count(f.h.tenant).await.unwrap(),
    )
}

#[tokio::test]
async fn inferred_group_memberships_are_frozen_into_audit_bindings_but_humans_never_are() {
    let f = Fixture::new().await;
    let mut directory = Directory::valid();
    directory.team_field("WorkerNames", None);
    directory.add_team("second-team", json!([WORKER]));
    directory.worker_field(
        "Groups",
        Some(json!([{"Type":"team","Name":TEAM,"Role":"member"},
        {"Type":"team","Name":"second-team","Role":"reviewer"}])),
    );
    let teams = f.succeed(&directory).await;
    assert_eq!(row(&teams, TEAM)["relationshipEvidence"], "worker-groups");
    let collector = collector(&f).await;
    let frozen = binding::load(&f.h.state, f.h.tenant, collector.source).await.unwrap().unwrap();
    assert_eq!(frozen.members.len(), 1);
    assert!(frozen.members[WORKER].teams.contains(TEAM));
    assert!(frozen.members[WORKER].teams.contains("second-team"));
    assert!(!frozen.members.contains_key("human-local"));
    for team in [TEAM, "second-team"] {
        let accepted = push(&f, &collector, message(WORKER, Some(team))).await;
        assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.text);
    }
    let before = counts(&f).await;
    assert_eq!(before, (2, 2));
    for event in [message(WORKER, None), message("human-local", Some(TEAM)), message(WORKER, Some("foreign-team"))] {
        let rejected = push(&f, &collector, event).await;
        assert_eq!(rejected.status, StatusCode::BAD_REQUEST, "{}", rejected.text);
        assert_eq!(counts(&f).await, before);
    }
    let events = f.h.get("/api/v1/alicloud/agentteams/audit-events").await.json();
    for item in events["items"].as_array().unwrap() {
        assert_eq!(item["fromAssetId"], json!(frozen.members[WORKER].asset_id));
        assert_eq!(item["authorized"], Value::Null);
    }
}

#[tokio::test]
async fn equivalent_relationship_refresh_keeps_binding_but_actual_membership_changes_require_review() {
    let f = Fixture::new().await;
    f.governed_baseline().await;
    let mut collector = collector(&f).await;
    assert_eq!(push(&f, &collector, heartbeat()).await.status, StatusCode::OK);
    let old = binding::load(&f.h.state, f.h.tenant, collector.source).await.unwrap().unwrap();
    let mut same = Directory::valid();
    same.worker_field(
        "Groups",
        Some(json!([{"Type":"team","Name":TEAM,"Role":"member"},
        {"Type":"team","Name":TEAM,"Role":"member"}])),
    );
    f.install(&same).await;
    let refreshed = f.sync().await;
    assert_eq!(refreshed.status, StatusCode::OK, "{}", refreshed.text);
    assert_eq!(refreshed.json()["bindingsRefreshed"], 1);
    let current = binding::load(&f.h.state, f.h.tenant, collector.source).await.unwrap().unwrap();
    assert_eq!(current.binding_id, old.binding_id);
    assert_eq!(current.bound_at, old.bound_at);
    assert_eq!(current.version, old.version + 1);
    assert_eq!(current.members, old.members);
    assert_eq!(push(&f, &collector, message(WORKER, Some(TEAM))).await.status, StatusCode::OK);
    let mut conflict = Directory::valid();
    conflict.worker_field("Groups", Some(json!([])));
    let captured = f.capture().await;
    f.reject(&conflict, &captured, "failed relationship refresh").await;
    let unchanged = binding::load(&f.h.state, f.h.tenant, collector.source).await.unwrap().unwrap();
    assert_eq!(serde_json::to_value(&unchanged).unwrap(), serde_json::to_value(&current).unwrap());
    assert_eq!(push(&f, &collector, heartbeat()).await.status, StatusCode::OK);
    let mut changed = Directory::valid();
    changed.team_field("WorkerNames", Some(json!([])));
    changed.worker_field("Groups", Some(json!([])));
    f.install(&changed).await;
    let updated = f.sync().await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.text);
    assert_eq!(updated.json()["bindingsRefreshed"], 0);
    assert_eq!(f.h.get(SOURCES).await.json()["items"][0]["acceptsEvents"], false);
    let before = counts(&f).await;
    assert_eq!(push(&f, &collector, heartbeat()).await.status, StatusCode::CONFLICT);
    assert_eq!(counts(&f).await, before);
    let rebound =
        f.h.request(
            "PUT",
            &format!("{SOURCES}/{}", collector.source),
            Some(&f.h.admin),
            Some(json!({"expected_version":current.version,"enabled":true})),
        )
        .await;
    assert_eq!(rebound.status, StatusCode::OK, "{}", rebound.text);
    assert_ne!(rebound.json()["bindingId"], collector.binding["bindingId"]);
    collector.binding = rebound.json();
    assert_eq!(push(&f, &collector, message(WORKER, Some(TEAM))).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(counts(&f).await, before);
    assert_eq!(push(&f, &collector, message(WORKER, None)).await.status, StatusCode::OK);
    let assets = f.h.state.store.asset_list_all(f.h.tenant).unwrap();
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0].owner.as_deref(), Some("manual-owner"));
    assert_eq!(assets[0].attributes["manual-note"], "keep me");
}

#[tokio::test]
async fn relationship_assets_bindings_and_events_are_tenant_isolated_and_viewers_cannot_manage_them() {
    let f = Fixture::new().await;
    f.succeed(&Directory::valid()).await;
    let collector = collector(&f).await;
    let before = counts(&f).await;
    let other_key = source_key(&f.h, f.h.other_tenant);
    let other_sources = f.h.request("GET", SOURCES, Some(&other_key), None).await;
    assert_eq!(other_sources.status, StatusCode::OK, "{}", other_sources.text);
    assert_eq!(other_sources.json()["items"], json!([]));
    let other_teams = f.h.request("GET", TEAMS, Some(&other_key), None).await;
    assert_eq!(other_teams.status, StatusCode::OK, "{}", other_teams.text);
    assert_eq!(other_teams.json(), json!([]));
    assert!(agf_api::cloud_inventory::load(&f.h.state, f.h.other_tenant).await.unwrap().is_none());
    let frozen = binding::load(&f.h.state, f.h.tenant, collector.source).await.unwrap().unwrap();
    assert!(f.h.state.store.asset_get(f.h.other_tenant, frozen.members[WORKER].asset_id).unwrap().is_none());
    assert!(binding::load(&f.h.state, f.h.other_tenant, collector.source).await.unwrap().is_none());
    let path = format!("{SOURCES}/{}", collector.source);
    let foreign =
        f.h.request(
            "POST",
            &format!("{path}/events"),
            Some(&other_key),
            Some(json!({"binding_id":collector.binding["bindingId"],"events":[heartbeat()]})),
        )
        .await;
    assert!(matches!(foreign.status, StatusCode::NOT_FOUND | StatusCode::CONFLICT), "{}", foreign.text);
    assert_eq!(counts(&f).await, before);
    assert_eq!(
        f.h.request("PUT", &path, Some(&f.h.viewer), Some(json!({"expected_version":1,"enabled":false}))).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.h.request(
            "POST",
            SYNC,
            Some(&f.h.viewer),
            Some(json!({"request_id":Id::new(),"configuration_version":1,"confirm_live":true}))
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
}
