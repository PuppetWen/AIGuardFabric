//! Authenticated audit lifecycle, atomic batches and observed (not inferred) metrics.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{asset::Asset, enums::AssetKind, ids::Id};
use common::*;

const CONFIG: &str = "/api/v1/alicloud/connections/alicloud-agentteams";
const SOURCES: &str = "/api/v1/alicloud/agentteams/audit-sources";
const EVENTS: &str = "/api/v1/alicloud/agentteams/audit-events";
const TEAMS: &str = "/api/v1/alicloud/agentteams";
const CROSS: &str = "/api/v1/alicloud/cross-team-calls";

struct AuditHarness {
    h: Harness,
    source: String,
    binding: Value,
    key: String,
}
impl AuditHarness {
    async fn new() -> Self {
        Self::with_fixture(true).await
    }
    async fn with_fixture(extended: bool) -> Self {
        let mut h = setup().await;
        Arc::make_mut(&mut h.state.config).mock_mode = false;
        h.app = build_router(h.state.clone());
        let saved = h
            .request(
                "PUT",
                CONFIG,
                Some(&h.admin),
                Some(json!({"expected_version":0,
            "enabled":true,"mock":true,"settings":{"instance_id":"inst-audit"}})),
            )
            .await;
        assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
        let synced = h
            .post(
                "/api/v1/alicloud/agentteams/sync",
                json!({"request_id":Id::new(),
            "configuration_version":1,"confirm_live":false}),
            )
            .await;
        assert_eq!(synced.status, StatusCode::OK, "{}", synced.text);
        if extended {
            extend_fixture(&h).await;
        }
        let created = h.post("/api/v1/ingest/sources", json!({"name":"audit-source","protocol":"http-webhook"})).await;
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
        let key = source_key(&h, h.tenant);
        Self { h, source, binding: bound.json(), key }
    }
    fn batch(&self, events: Vec<Value>) -> Value {
        json!({"binding_id":self.binding["bindingId"],"events":events})
    }
    async fn push(&self, body: Value) -> Resp {
        self.h.request("POST", &format!("{SOURCES}/{}/events", self.source), Some(&self.key), Some(body)).await
    }
    async fn change(&self, version: u64, enabled: bool) -> Resp {
        self.h
            .request(
                "PUT",
                &format!("{SOURCES}/{}", self.source),
                Some(&self.h.admin),
                Some(json!({"expected_version":version,"enabled":enabled})),
            )
            .await
    }
    async fn counts(&self) -> (u64, u64) {
        (
            self.h.state.ingest_sink.event_count(self.h.tenant).await.unwrap(),
            self.h.state.ingest_sink.raw_count(self.h.tenant).await.unwrap(),
        )
    }
}

fn source_key(h: &Harness, tenant: TenantId) -> String {
    let issued = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("sources:write")],
        ..ApiKeyIssueRequest::named(tenant, "audit-collector", Timestamp::now())
    });
    h.state.store.api_key_insert(issued.record).unwrap();
    issued.plaintext
}

async fn extend_fixture(h: &Harness) {
    // Explicit test-only fixture extension: two teams share a real mapped Worker;
    // a second mapped Worker has no audit event, so its count must remain unobserved.
    let name = agf_api::cloud_inventory::NAME;
    let mut snapshot = agf_api::cloud_inventory::load(&h.state, h.tenant).await.unwrap().unwrap();
    let mut receiving = snapshot.teams[0].clone();
    receiving["Name"] = json!("receiving-team");
    snapshot.teams.push(receiving);
    let mut idle = snapshot.workers[0].clone();
    idle["Name"] = json!("idle-worker");
    snapshot.workers.push(idle);
    snapshot.teams[0]["WorkerNames"].as_array_mut().unwrap().push(json!("idle-worker"));
    snapshot.workers[0]["Groups"] = json!([
        {"Type":"team","Name":"my-team","Role":"member"},
        {"Type":"team","Name":"receiving-team","Role":"member"}
    ]);
    snapshot.workers[1]["Groups"] = json!([{ "Type":"team","Name":"my-team","Role":"member" }]);
    let asset = Asset::new(h.tenant, AssetKind::Agent, "idle-worker", "agentteams-audit-idle-fixture");
    h.state.store.asset_upsert(&asset).unwrap();
    snapshot.assets.insert("idle-worker".into(), asset.id);
    let cfg = agf_api::cloud_store::load(&h.state, h.tenant, name).await.unwrap().unwrap();
    let mut private = agf_api::integration_store::Private::default();
    private.settings.insert("snapshot".into(), serde_json::to_value(&snapshot).unwrap());
    let sealed = agf_api::integration_store::Stored {
        private: agf_api::model_gateway::encrypt(&h.state, h.tenant, cfg.id, serde_json::to_string(&private).unwrap())
            .unwrap(),
        updated_at: snapshot.checked_at,
        ..cfg
    };
    h.state.configurations.put(h.tenant, "cloud-inventory", sealed.id, &sealed).await.unwrap();
}

fn call(id: &str, at: Timestamp) -> Value {
    json!({"event_id":id,"event_time":at,"kind":"call","from_team":"my-team","from_worker":"worker-demo",
        "to_team":"receiving-team","to_worker":"worker-demo","status":"success","duration_ms":12,
        "trace_id":"11111111111111111111111111111111","span_id":"2222222222222222"})
}
fn heartbeat(id: &str, at: Timestamp) -> Value {
    json!({"event_id":id,"event_time":at,"kind":"heartbeat"})
}
fn team<'a>(rows: &'a Value, name: &str) -> &'a Value {
    rows.as_array().unwrap().iter().find(|row| row["name"] == name).unwrap()
}

#[tokio::test]
async fn mock_inventory_receives_safe_call_message_task_and_heartbeat_evidence() {
    let a = AuditHarness::new().await;
    let before = a.h.get(TEAMS).await.json();
    assert_eq!(team(&before, "my-team")["metricsAvailable"], false);
    let sources = a.h.get(SOURCES).await.json();
    assert_eq!(sources["items"][0]["state"], "waiting");
    assert_eq!(sources["items"][0]["acceptsEvents"], true);
    assert!(!sources.to_string().contains("members"));
    let secret = "AKIA7F4M2Q8Z6N3R5T9V";
    let at = Timestamp::now();
    let message = json!({"event_id":"message-one","event_time":at,"kind":"message","from_team":"my-team",
        "from_worker":"worker-demo","message":format!("AWS access key {secret}"),"trace_id":"trace-message"});
    let task = json!({"event_id":"task-one","event_time":at,"kind":"task","from_team":"my-team",
        "from_worker":"worker-demo","task_id":"task-one","status":"unknown"});
    let pushed = a.push(a.batch(vec![call("call-one", at), message, task, heartbeat("heartbeat-one", at)])).await;
    assert_eq!(pushed.status, StatusCode::OK, "{}", pushed.text);
    assert_eq!(pushed.json()["accepted"], 4);
    assert_eq!(pushed.json()["authorizationStatus"], "unknown");
    assert_eq!(a.counts().await, (4, 4));
    let events = a.h.get(EVENTS).await;
    assert_eq!(events.status, StatusCode::OK, "{}", events.text);
    assert_eq!(events.json()["items"].as_array().unwrap().len(), 4);
    assert!(!events.text.contains(secret), "{}", events.text);
    for row in events.json()["items"].as_array().unwrap() {
        assert_eq!(row["authorized"], Value::Null);
        assert_eq!(row["mocked"], true);
        assert!(row.get("raw").is_none() && row.get("headers").is_none());
    }
    let teams = a.h.get(TEAMS).await.json();
    let active = team(&teams, "my-team");
    assert_eq!(active["metricsAvailable"], true);
    assert_eq!(active["crossTeamCalls24h"], 1);
    let members = active["members"].as_array().unwrap();
    let worker = members.iter().find(|row| row["id"] == "worker-demo").unwrap();
    let idle = members.iter().find(|row| row["id"] == "idle-worker").unwrap();
    assert_eq!(worker["invocations24h"], 1);
    assert_eq!(worker["metricsAvailable"], true);
    assert_eq!(idle["metricsAvailable"], false);
    let calls = a.h.get(CROSS).await.json();
    assert_eq!(calls[0]["count24h"], 1);
    assert_eq!(calls[0]["authorized"], Value::Null);
    assert_eq!(calls[0]["sensitiveData"], Value::Null);
    assert_eq!(a.h.get(SOURCES).await.json()["items"][0]["state"], "active");
}

#[tokio::test]
async fn invalid_tail_and_untrusted_identity_fields_never_publish_a_partial_batch() {
    let a = AuditHarness::new().await;
    let at = Timestamp::now();
    let mut invalid = call("bad-tail", at);
    invalid["to_worker"] = json!("not-in-inventory");
    let result = a.push(a.batch(vec![call("valid-head", at), invalid])).await;
    assert_eq!(result.status, StatusCode::BAD_REQUEST, "{}", result.text);
    assert_eq!(a.counts().await, (0, 0));
    for field in ["tenant", "account", "from_asset_id", "to_asset_id", "assetId", "authorized"] {
        let mut event = call("untrusted-field", at);
        event[field] = json!("injected-sensitive-value");
        let result = a.push(a.batch(vec![event])).await;
        assert_eq!(result.status, StatusCode::BAD_REQUEST, "{field}: {}", result.text);
        assert!(!result.text.contains("injected-sensitive-value"));
        assert_eq!(a.counts().await, (0, 0));
    }
    let bound_at = Timestamp::parse_rfc3339(a.binding["boundAt"].as_str().unwrap()).unwrap();
    let result = a.push(a.batch(vec![call("before-binding", bound_at.offset_secs(-1))])).await;
    assert_eq!(result.status, StatusCode::BAD_REQUEST, "{}", result.text);
    assert_eq!(a.counts().await, (0, 0));
}

#[tokio::test]
async fn business_retries_are_deduplicated_and_a_conflicting_tail_rolls_back_the_head() {
    let a = AuditHarness::new().await;
    let at = Timestamp::now();
    let event = call("same-business-id", at);
    let batch = a.batch(vec![event.clone()]);
    assert_eq!(a.push(batch.clone()).await.json()["accepted"], 1);
    let retry = a.push(batch).await;
    assert_eq!(retry.status, StatusCode::OK, "{}", retry.text);
    assert_eq!(retry.json()["accepted"], 0);
    assert_eq!(retry.json()["deduped"], 1);
    let mut changed = event;
    changed["status"] = json!("error");
    let conflict = a.push(a.batch(vec![call("not-committed-head", at), changed])).await;
    assert_eq!(conflict.status, StatusCode::CONFLICT, "{}", conflict.text);
    assert_eq!(a.counts().await, (1, 1));
    assert_eq!(a.h.get(CROSS).await.json()[0]["count24h"], 1);
}

#[tokio::test]
async fn reads_and_ingestion_require_the_correct_tenant_and_permissions() {
    let a = AuditHarness::new().await;
    let path = format!("{SOURCES}/{}", a.source);
    let events_path = format!("{path}/events");
    assert_eq!(
        a.h.request("PUT", &path, Some(&a.h.viewer), Some(json!({"expected_version":1,"enabled":false}))).await.status,
        StatusCode::FORBIDDEN
    );
    let batch = a.batch(vec![heartbeat("permission-check", Timestamp::now())]);
    assert_eq!(a.h.request("POST", &events_path, None, Some(batch.clone())).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        a.h.request("POST", &events_path, Some(&a.h.viewer), Some(batch.clone())).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        a.h.request("POST", &events_path, Some(&a.h.api_key), Some(batch.clone())).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(a.h.request("GET", EVENTS, Some(&a.key), None).await.status, StatusCode::FORBIDDEN);
    assert_eq!(
        a.h.request("PUT", &path, Some(&a.key), Some(json!({"expected_version":1,"enabled":false}))).await.status,
        StatusCode::FORBIDDEN
    );
    let foreign_key = source_key(&a.h, a.h.other_tenant);
    assert_ne!(a.h.request("POST", &events_path, Some(&foreign_key), Some(batch.clone())).await.status, StatusCode::OK);
    let headers = [("authorization", format!("Bearer {}", a.h.admin)), ("x-agf-tenant", a.h.other_tenant.to_string())];
    let headers: Vec<_> = headers.iter().map(|(key, value)| (*key, value.as_str())).collect();
    for path in [EVENTS, SOURCES] {
        let response = a.h.request_with("GET", path, &headers, None).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text);
        assert!(response.json()["items"].as_array().unwrap().is_empty());
        assert!(!response.text.contains(a.source.as_str()));
    }
    assert_eq!(a.push(batch).await.status, StatusCode::OK);
    assert_eq!(a.counts().await, (1, 1));
}

#[tokio::test]
async fn disable_rebind_source_and_cloud_revision_changes_reject_old_sender_bindings() {
    let mut a = AuditHarness::new().await;
    assert_eq!(a.change(0, true).await.status, StatusCode::CONFLICT);
    let old = a.batch(vec![heartbeat("old-binding", Timestamp::now())]);
    assert_eq!(a.change(1, false).await.status, StatusCode::OK);
    assert_eq!(a.push(old.clone()).await.status, StatusCode::CONFLICT);
    assert_eq!(a.h.get(SOURCES).await.json()["items"][0]["state"], "disabled");
    let rebound = a.change(2, true).await;
    assert_eq!(rebound.status, StatusCode::OK, "{}", rebound.text);
    assert_ne!(rebound.json()["bindingId"], a.binding["bindingId"]);
    a.binding = rebound.json();
    assert_eq!(a.push(old).await.status, StatusCode::CONFLICT);
    let valid = a.batch(vec![heartbeat("new-binding", Timestamp::now())]);
    assert_eq!(a.push(valid.clone()).await.status, StatusCode::OK);
    let patched =
        a.h.request(
            "PATCH",
            &format!("/api/v1/ingest/sources/{}", a.source),
            Some(&a.h.admin),
            Some(json!({"enabled":false})),
        )
        .await;
    assert_eq!(patched.status, StatusCode::OK);
    assert_eq!(a.push(valid.clone()).await.status, StatusCode::CONFLICT);
    assert_eq!(
        a.h.request(
            "PATCH",
            &format!("/api/v1/ingest/sources/{}", a.source),
            Some(&a.h.admin),
            Some(json!({"enabled":true}))
        )
        .await
        .status,
        StatusCode::OK
    );
    let stale = a.h.get(SOURCES).await.json();
    assert_eq!(stale["items"][0]["state"], "stale");
    assert_eq!(stale["items"][0]["acceptsEvents"], false);
    assert_eq!(a.push(valid).await.status, StatusCode::CONFLICT);
    let changed =
        a.h.request(
            "PUT",
            CONFIG,
            Some(&a.h.admin),
            Some(json!({"expected_version":1,
        "enabled":true,"mock":true,"settings":{"instance_id":"another-instance"}})),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    assert_eq!(a.push(a.batch(vec![heartbeat("changed-cloud", Timestamp::now())])).await.status, StatusCode::CONFLICT);
    assert_eq!(a.counts().await, (1, 1));
}

#[tokio::test]
async fn unchanged_inventory_refresh_keeps_the_sender_binding_and_retry_identity() {
    let a = AuditHarness::with_fixture(false).await;
    let batch = a.batch(vec![heartbeat("before-daily-sync", Timestamp::now())]);
    assert_eq!(a.push(batch.clone()).await.json()["accepted"], 1);
    let sync =
        a.h.post(
            "/api/v1/alicloud/agentteams/sync",
            json!({"request_id":Id::new(),
        "configuration_version":1,"confirm_live":false}),
        )
        .await;
    assert_eq!(sync.status, StatusCode::OK, "{}", sync.text);
    let sources = a.h.get(SOURCES).await;
    assert_eq!(sources.status, StatusCode::OK, "{}", sources.text);
    let binding = &sources.json()["items"][0];
    assert_eq!(binding["bindingId"], a.binding["bindingId"]);
    assert_eq!(binding["boundAt"], a.binding["boundAt"]);
    assert_eq!(binding["acceptsEvents"], true);
    let retry = a.push(batch).await;
    assert_eq!(retry.status, StatusCode::OK, "{}", retry.text);
    assert_eq!(retry.json()["deduped"], 1);
    assert_eq!(a.push(a.batch(vec![heartbeat("after-daily-sync", Timestamp::now())])).await.json()["accepted"], 1);
    assert_eq!(a.counts().await, (2, 2));
    assert_eq!(
        team(&a.h.get(TEAMS).await.json(), "my-team")["metricsAvailable"],
        false,
        "heartbeats provide source freshness, not observed Worker call volume"
    );
}

#[tokio::test]
async fn cursor_pages_use_stable_ties_and_counts_include_all_events_in_the_24_hour_window() {
    let a = AuditHarness::new().await;
    // This fixture models a binding established two days ago, so historical window
    // boundaries can be tested without weakening the live binding-time contract.
    let source_id = Id::parse(&a.source).unwrap();
    let mut saved = agf_api::agentteams_audit::binding::load(&a.h.state, a.h.tenant, source_id).await.unwrap().unwrap();
    saved.bound_at = Timestamp::now().offset_secs(-2 * 86_400);
    a.h.state
        .configurations
        .put(a.h.tenant, agf_api::agentteams_audit::binding::KIND, source_id, &saved)
        .await
        .unwrap();
    let at = Timestamp::now().offset_secs(-5);
    let mut batch: Vec<_> = (0..51).map(|index| call(&format!("page-{index}"), at)).collect();
    batch.push(call("older-than-window", at.offset_secs(-25 * 3_600)));
    batch.push(call("not-yet-in-window", at.offset_secs(120)));
    assert_eq!(a.push(a.batch(batch)).await.json()["accepted"], 53);
    let first = a.h.get(&format!("{EVENTS}?limit=10")).await.json();
    let mut page = first.clone();
    let mut seen = std::collections::BTreeSet::new();
    loop {
        assert_eq!(page["windowFrom"], first["windowFrom"]);
        assert_eq!(page["windowTo"], first["windowTo"]);
        for row in page["items"].as_array().unwrap() {
            assert!(seen.insert(row["id"].as_str().unwrap().to_owned()));
            assert!(!["older-than-window", "not-yet-in-window"].contains(&row["eventId"].as_str().unwrap()));
        }
        let Some(cursor) = page["nextCursor"].as_str() else { break };
        let response = a.h.get(&format!("{EVENTS}?limit=10&cursor={cursor}")).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text);
        page = response.json();
    }
    assert_eq!(seen.len(), 51);
    assert_eq!(a.h.get(CROSS).await.json()[0]["count24h"], 51);
    let teams = a.h.get(TEAMS).await.json();
    let members = team(&teams, "my-team")["members"].as_array().unwrap();
    let observed = members.iter().find(|member| member["id"] == "worker-demo").unwrap();
    assert_eq!(observed["invocations24h"], 51);
    assert_eq!(observed["metricsAvailable"], true);
    let idle = members.iter().find(|member| member["id"] == "idle-worker").unwrap();
    assert_eq!(idle["metricsAvailable"], false, "pagination must not assign another Worker's volume to idle members");
    let cursor = first["nextCursor"].as_str().unwrap();
    let foreign =
        a.h.request_with(
            "GET",
            &format!("{EVENTS}?cursor={cursor}"),
            &[("authorization", &format!("Bearer {}", a.h.admin)), ("x-agf-tenant", &a.h.other_tenant.to_string())],
            None,
        )
        .await;
    assert_eq!(foreign.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn source_eps_rejects_a_whole_batch_without_consuming_partial_tokens() {
    let mut a = AuditHarness::new().await;
    // max_eps is persisted source policy, outside the public creation DTO.
    let id = Id::parse(&a.source).unwrap();
    let mut record = agf_api::source_store::load(&a.h.state, a.h.tenant, id).await.unwrap();
    let source = record.source.as_mut().unwrap();
    source.max_eps = 1;
    source.updated_at = Timestamp::now();
    a.h.state.configurations.put(a.h.tenant, agf_api::source_store::KIND, id, &record).await.unwrap();
    let rebound = a.change(1, true).await;
    assert_eq!(rebound.status, StatusCode::OK, "{}", rebound.text);
    a.binding = rebound.json();
    let at = Timestamp::now();
    let too_large = a.push(a.batch(vec![heartbeat("eps-batch-one", at), heartbeat("eps-batch-two", at)])).await;
    assert_eq!(too_large.status, StatusCode::TOO_MANY_REQUESTS, "{}", too_large.text);
    assert_eq!(a.counts().await, (0, 0));
    let first = a.push(a.batch(vec![heartbeat("eps-first", Timestamp::now())])).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text);
    assert_eq!(first.json()["accepted"], 1, "a rejected batch must not consume its first token");
    assert_eq!(a.counts().await, (1, 1));
    let second = a.push(a.batch(vec![heartbeat("eps-second", Timestamp::now())])).await;
    assert_eq!(second.status, StatusCode::TOO_MANY_REQUESTS, "{}", second.text);
    assert_eq!(a.counts().await, (1, 1));
}
