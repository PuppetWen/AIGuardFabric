//! Trace reads keep authenticated collector evidence separate from completeness and authorization.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::ids::Id;
use common::*;

const CONFIG: &str = "/api/v1/alicloud/connections/alicloud-agentteams";
const SOURCES: &str = "/api/v1/alicloud/agentteams/audit-sources";
const TRACE: &str = "/api/v1/alicloud/agentteams/traces";

struct TraceHarness {
    h: Harness,
    source: String,
    binding: Value,
}

impl TraceHarness {
    async fn new() -> Self {
        let mut h = setup().await;
        Arc::make_mut(&mut h.state.config).mock_mode = false;
        h.app = build_router(h.state.clone());
        let saved = h
            .request(
                "PUT",
                CONFIG,
                Some(&h.admin),
                Some(json!({"expected_version":0,
                "enabled":true,"mock":true,"settings":{"instance_id":"inst-demo"}})),
            )
            .await;
        assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
        sync(&h).await;
        let created = h.post("/api/v1/ingest/sources", json!({"name":"trace-source","protocol":"http-webhook"})).await;
        assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
        let source = created.json()["id"].as_str().unwrap().to_owned();
        let bound = h
            .request(
                "PUT",
                &format!("{SOURCES}/{source}"),
                Some(&h.admin),
                Some(json!({"expected_version":0,"enabled":true})),
            )
            .await;
        assert_eq!(bound.status, StatusCode::OK, "{}", bound.text);
        Self { h, source, binding: bound.json() }
    }

    async fn push(&self, events: Vec<Value>) {
        let sent = self
            .h
            .post(
                &format!("{SOURCES}/{}/events", self.source),
                json!({"binding_id":self.binding["bindingId"],"events":events}),
            )
            .await;
        assert_eq!(sent.status, StatusCode::OK, "{}", sent.text);
    }
}

async fn sync(h: &Harness) {
    let result = h
        .post(
            "/api/v1/alicloud/agentteams/sync",
            json!({"request_id":Id::new(),"configuration_version":1,"confirm_live":false}),
        )
        .await;
    assert_eq!(result.status, StatusCode::OK, "{}", result.text);
}

fn event(id: &str, trace: &str, span: &str, parent: Option<&str>) -> Value {
    json!({"event_id":id,"event_time":Timestamp::now(),"kind":"call","status":"success",
        "from_team":"my-team","from_worker":"worker-demo","to_team":"my-team","to_worker":"worker-demo",
        "trace_id":trace,"span_id":span,"parent_span_id":parent,"task_id":"same-task"})
}

fn cursor(value: &Value) -> &str {
    value["nextCursor"].as_str().unwrap()
}

#[tokio::test]
async fn trace_graph_uses_all_bounded_evidence_independently_of_the_event_page() {
    let a = TraceHarness::new().await;
    a.push(vec![
        event("root", "trace-main", "root", None),
        event("child", "trace-main", "child", Some("root")),
        event("independent", "trace-main", "independent", None),
        event("other-trace", "other-trace", "other", None),
    ])
    .await;
    let first = a.h.get(&format!("{TRACE}/trace-main?limit=1")).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    let first = first.json();
    assert_eq!(first["totalEvents"], 3);
    assert_eq!(first["items"].as_array().unwrap().len(), 1);
    assert_eq!(first["graph"]["nodes"].as_array().unwrap().len(), 3);
    assert_eq!(first["graph"]["edges"].as_array().unwrap().len(), 1);
    assert_eq!(first["graph"]["status"], "observed");
    assert_eq!(first["complete"], false);
    assert_eq!(first["coverage"], "observed_only");
    let nodes = first["graph"]["nodes"].as_array().unwrap();
    let root = nodes.iter().find(|node| node["spanId"] == "root").unwrap();
    let child = nodes.iter().find(|node| node["spanId"] == "child").unwrap();
    assert_eq!(first["graph"]["edges"][0]["fromNodeId"], root["id"]);
    assert_eq!(first["graph"]["edges"][0]["toNodeId"], child["id"]);
    for node in nodes {
        assert_eq!(node["authorized"], Value::Null);
        assert!(node.get("messagePreview").is_none() && node.get("raw").is_none());
    }
    let second = a.h.get(&format!("{TRACE}/trace-main?limit=1&cursor={}", cursor(&first))).await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.text);
    let second = second.json();
    assert_ne!(first["items"][0]["id"], second["items"][0]["id"]);
    assert_eq!(first["graph"], second["graph"]);
    let third = a.h.get(&format!("{TRACE}/trace-main?limit=200&cursor={}", cursor(&second))).await;
    assert_eq!(third.status, StatusCode::OK, "{}", third.text);
    assert_eq!(third.json()["items"].as_array().unwrap().len(), 1);
    assert_eq!(third.json()["nextCursor"], Value::Null);
}

#[tokio::test]
async fn cursor_is_authenticated_bound_to_the_query_and_not_to_inventory_refresh_time() {
    let a = TraceHarness::new().await;
    a.push(vec![event("a", "cursor-trace", "a", None), event("b", "cursor-trace", "b", Some("a"))]).await;
    let first = a.h.get(&format!("{TRACE}/cursor-trace?limit=1")).await.json();
    let token = cursor(&first);
    for path in [
        format!("{TRACE}/cursor-trace?cursor={token}a"),
        format!("{TRACE}/other-trace?cursor={token}"),
        format!("{TRACE}/cursor-trace?cursor={token}&from=2000-01-01T00:00:00Z"),
    ] {
        let result = a.h.get(&path).await;
        assert_eq!(result.status, StatusCode::BAD_REQUEST, "{}", result.text);
    }
    // A later receive is outside the first query's watermark, even for this same trace.
    tokio::time::sleep(std::time::Duration::from_millis(3)).await;
    a.push(vec![event("later", "cursor-trace", "later", None)]).await;
    sync(&a.h).await;
    let next = a.h.get(&format!("{TRACE}/cursor-trace?cursor={token}")).await;
    assert_eq!(next.status, StatusCode::OK, "{}", next.text);
    assert_eq!(next.json()["totalEvents"], 2);
    assert_eq!(next.json()["scopeId"], first["scopeId"]);
    let disabled =
        a.h.request(
            "PUT",
            CONFIG,
            Some(&a.h.admin),
            Some(json!({"expected_version":1,"enabled":false,"mock":true,"settings":{"instance_id":"inst-demo"}})),
        )
        .await;
    assert_eq!(disabled.status, StatusCode::OK, "{}", disabled.text);
    let stale = a.h.get(&format!("{TRACE}/cursor-trace?cursor={token}")).await;
    assert_eq!(stale.status, StatusCode::CONFLICT, "{}", stale.text);
}

#[tokio::test]
async fn unknown_inventory_and_unobserved_trace_are_distinct_and_queries_are_bounded() {
    let h = setup().await;
    let unknown = h.get(&format!("{TRACE}/none")).await;
    assert_eq!(unknown.status, StatusCode::OK, "{}", unknown.text);
    assert_eq!(unknown.json()["totalEvents"], Value::Null);
    assert_eq!(unknown.json()["graph"]["status"], "unavailable");
    let a = TraceHarness::new().await;
    let empty = a.h.get(&format!("{TRACE}/none")).await;
    assert_eq!(empty.status, StatusCode::OK, "{}", empty.text);
    assert_eq!(empty.json()["totalEvents"], 0);
    assert_eq!(empty.json()["graph"]["status"], "unobserved");
    let now = Timestamp::now();
    for query in [
        "limit=0".to_owned(),
        "limit=201".into(),
        "unexpected=yes".into(),
        format!("from={now}&until={now}"),
        format!("from={}&until={now}", now.offset_secs(-31 * 86_400)),
        format!("until={}", now.offset_secs(120)),
    ] {
        let result = a.h.get(&format!("{TRACE}/none?{query}")).await;
        assert_eq!(result.status, StatusCode::BAD_REQUEST, "{query}: {}", result.text);
    }
    let issued = a.h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("alicloud:read")],
        ..ApiKeyIssueRequest::named(a.h.tenant, "trace-no-source-read", now)
    });
    a.h.state.store.api_key_insert(issued.record).unwrap();
    let denied = a.h.request("GET", &format!("{TRACE}/none"), Some(&issued.plaintext), None).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN, "{}", denied.text);
}

#[tokio::test]
async fn conflicting_and_incomplete_span_evidence_never_invents_an_edge() {
    let a = TraceHarness::new().await;
    let mut without_span = event("without-span", "conflict-trace", "unused", None);
    without_span.as_object_mut().unwrap().remove("span_id");
    a.push(vec![
        event("duplicate-one", "conflict-trace", "duplicate", None),
        event("duplicate-two", "conflict-trace", "duplicate", None),
        event("ambiguous", "conflict-trace", "ambiguous", Some("duplicate")),
        event("missing", "conflict-trace", "missing", Some("unobserved-parent")),
        event("cycle-a", "conflict-trace", "cycle-a", Some("cycle-b")),
        event("cycle-b", "conflict-trace", "cycle-b", Some("cycle-a")),
        without_span,
    ])
    .await;
    let read = a.h.get(&format!("{TRACE}/conflict-trace?limit=1")).await;
    assert_eq!(read.status, StatusCode::OK, "{}", read.text);
    let read = read.json();
    assert_eq!(read["totalEvents"], 7);
    assert_eq!(read["graph"]["status"], "conflict");
    assert_eq!(read["graph"]["edges"], json!([]));
    let issues = read["graph"]["issues"].as_array().unwrap();
    for kind in ["duplicate_span", "ambiguous_parent", "missing_parent", "cycle", "missing_span"] {
        assert!(issues.iter().any(|issue| issue["kind"] == kind), "{kind}: {read}");
    }
}
