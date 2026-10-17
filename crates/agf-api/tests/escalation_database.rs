//! Real PostgreSQL: atomic alert/outbox receipts, competing workers, activation scope and revocation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::{alert_escalation as escalation, notification_config as channel, notification_outbox as queue};
use agf_core::{
    enums::{AlertState, Severity},
    ids::{Id, deterministic_id},
    notify::ChannelKind,
};
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use common::*;

async fn sql_setup() -> Harness {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let database =
        Database::from_pool(sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap());
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::ApiStore::with_database(store.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(store)));
    let tenant = agf_api::tenant_directory::new(format!("escalation-{}", Id::new()), "Escalation verification".into());
    h.tenant = agf_api::tenant_directory::save(&h.state, tenant, true).await.unwrap().id;
    h.app = build_router(h.state.clone());
    channel::save(
        &h.state,
        h.tenant,
        ChannelKind::InApp,
        serde_json::from_value(json!({"enabled":true,"minSeverity":"info"})).unwrap(),
    )
    .await
    .unwrap();
    h
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn sql_notification_versions_serialize_across_instances() {
    let h = sql_setup().await;
    let mut other = h.state.clone();
    other.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(h.state.store.database().cloned()));
    let update = |severity| {
        serde_json::from_value(json!({"expectedVersion":1,"enabled":true,
        "minSeverity":severity}))
        .unwrap()
    };
    let (first, second) = tokio::join!(
        channel::save(&h.state, h.tenant, ChannelKind::InApp, update("high")),
        channel::save(&other, h.tenant, ChannelKind::InApp, update("critical")),
    );
    assert_eq!(u8::from(first.is_ok()) + u8::from(second.is_ok()), 1);
    assert_eq!(
        u8::from(matches!(first, Err(agf_core::error::DomainError::Conflict(_))))
            + u8::from(matches!(second, Err(agf_core::error::DomainError::Conflict(_)))),
        1
    );
    let saved = other
        .configurations
        .get::<channel::StoredChannel>(h.tenant, channel::KIND, channel::id(h.tenant, ChannelKind::InApp))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(saved.version, 2);
    finish(&h).await;
}
async fn call(h: &Harness, method: &str, path: &str, body: Option<Value>) -> Resp {
    h.request_with(
        method,
        path,
        &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &h.tenant.to_string())],
        body,
    )
    .await
}
async fn policy(h: &Harness, include: bool, enabled: bool) -> Value {
    let current = call(h, "GET", "/api/v1/alerts/escalation-config", None).await.json();
    let mut routes: Vec<_> = current["policies"].as_array().unwrap().iter().map(|p| p["route"].clone()).collect();
    routes[0] = json!({"severity":"critical","responseMinutes":1,"enabled":enabled,
        "tiers":[{"level":1,"overdueMinutes":0,"target":"on-call","channels":["in-app"]},
        {"level":2,"overdueMinutes":1,"target":"team-lead","channels":["in-app"]}]});
    let response = call(h,"PUT","/api/v1/alerts/escalation-config",Some(json!({
        "expectedVersion":current["version"],"routes":routes,"reason":"SQL escalation check","includeExisting":include}))).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    response.json()
}
async fn alert(h: &Harness, old: bool) -> Id {
    let response = call(
        h,
        "POST",
        "/api/v1/alerts",
        Some(json!({"title":"escalation verification","severity":"critical","dedup_key":Id::new()})),
    )
    .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
    let id = Id::parse(response.json()["alert_id"].as_str().unwrap()).unwrap();
    if old {
        let database = h.state.store.database().unwrap();
        let mut tx = database.db().begin_tenant(h.tenant).await.unwrap();
        sqlx::query("UPDATE alerts SET first_seen_at=$2 WHERE id=$1")
            .bind(id.as_uuid())
            .bind(Timestamp::now().offset_secs(-600).as_datetime())
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    id
}
async fn receipts(h: &Harness) -> Value {
    let response = call(h, "GET", "/api/v1/alerts/escalation-history", None).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    response.json()
}
async fn finish(h: &Harness) {
    let mut entry =
        agf_api::tenant_directory::list(&h.state).await.unwrap().into_iter().find(|t| t.id == h.tenant).unwrap();
    entry.enabled = false;
    agf_api::tenant_directory::save(&h.state, entry, false).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn sql_escalation_competing_workers_persist_once_and_cancel_unsent() {
    let h = sql_setup().await;
    let id = alert(&h, true).await;
    policy(&h, true, true).await;
    let now = Timestamp::now();
    let (a, b) = tokio::join!(escalation::tick(&h.state, now), escalation::tick(&h.state, now));
    a.unwrap();
    b.unwrap();
    let rows = receipts(&h).await;
    assert_eq!(rows["total"], 2, "{rows}");
    let stored = h.state.store.alert_get_durable(h.tenant, id).await.unwrap().unwrap();
    assert_eq!(stored.state, AlertState::Escalated);
    assert_eq!(stored.escalation_level, 2);
    assert_eq!(stored.sla_due_at, Some(stored.first_seen_at.offset_secs(60)));
    assert!(stored.sla_breached);
    // Reload SQL-backed caches as on a second API instance. No duplicate tier after policy edits.
    let mut restarted = h.state.clone();
    let database = h.state.store.database().unwrap().clone();
    restarted.store = Arc::new(agf_api::ApiStore::with_database(database.clone()));
    restarted.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(database)));
    policy(&h, true, true).await;
    escalation::tick(&restarted, now.offset_secs(10)).await.unwrap();
    assert_eq!(receipts(&h).await["total"], 2);
    let jobs = queue::history(&h.state, h.tenant).await.unwrap();
    assert_eq!(jobs.len(), 2);
    let first = Id::parse(jobs[0]["id"].as_str().unwrap()).unwrap();
    assert_eq!(queue::attempt(&h.state, h.tenant, first, Timestamp::now()).await.unwrap()["status"], "delivered");
    h.state.store.alert_set_state_durable(h.tenant, id, AlertState::Acknowledged, None).await.unwrap();
    let second = Id::parse(jobs[1]["id"].as_str().unwrap()).unwrap();
    assert_eq!(queue::attempt(&h.state, h.tenant, second, Timestamp::now()).await.unwrap()["status"], "suppressed");
    assert_eq!(h.state.configurations.list::<Value>(h.tenant, "notification-inbox").await.unwrap().len(), 1);
    // Other-tenant read under the runtime role cannot see immutable receipts.
    let database = h.state.store.database().unwrap();
    let mut tx = database.db().begin_tenant(TenantId::new()).await.unwrap();
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM alert_escalation_receipts").fetch_one(&mut *tx).await.unwrap();
    assert_eq!(count, 0);
    tx.commit().await.unwrap();
    let legacy = call(&h, "GET", "/api/v1/alerts/escalation-routes", None).await.json();
    assert_eq!(legacy[0]["enabled"], true);
    assert_eq!(legacy[0]["afterMinutes"], 1);
    assert_eq!(legacy[0]["tiers"][0]["channels"], json!(["in-app"]));
    finish(&h).await;
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn sql_escalation_activation_scope_and_disabled_channel_recovery() {
    let h = sql_setup().await;
    let old = alert(&h, true).await;
    policy(&h, false, true).await;
    let fresh = alert(&h, false).await;
    let future = Timestamp::now().offset_secs(180);
    channel::save(
        &h.state,
        h.tenant,
        ChannelKind::InApp,
        serde_json::from_value(json!({"expectedVersion":1,"enabled":false,"minSeverity":"info"})).unwrap(),
    )
    .await
    .unwrap();
    escalation::tick(&h.state, future).await.unwrap();
    assert_eq!(receipts(&h).await["total"], 0);
    let health = call(&h, "GET", "/api/v1/alerts/escalation-config", None).await.json();
    assert!(health["health"]["error"].as_str().unwrap().contains("渠道"));
    channel::save(
        &h.state,
        h.tenant,
        ChannelKind::InApp,
        serde_json::from_value(json!({"expectedVersion":2,"enabled":true,"minSeverity":"info"})).unwrap(),
    )
    .await
    .unwrap();
    escalation::tick(&h.state, future).await.unwrap();
    let rows = receipts(&h).await;
    assert_eq!(rows["total"], 2, "{rows}");
    assert!(rows["items"].as_array().unwrap().iter().all(|r| r["alert_id"] == fresh.to_string()));
    assert_eq!(h.state.store.alert_get_durable(h.tenant, old).await.unwrap().unwrap().escalation_level, 0);
    policy(&h, false, false).await;
    for job in queue::history(&h.state, h.tenant).await.unwrap() {
        let result =
            queue::attempt(&h.state, h.tenant, Id::parse(job["id"].as_str().unwrap()).unwrap(), Timestamp::now())
                .await
                .unwrap();
        assert_eq!(result["status"], "suppressed");
    }
    policy(&h, true, true).await;
    escalation::tick(&h.state, future).await.unwrap();
    assert_eq!(receipts(&h).await["total"], 4);
    finish(&h).await;
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn sql_escalation_full_outbox_rolls_back_and_revoked_publisher_stops_delivery() {
    let h = sql_setup().await;
    let id = alert(&h, true).await;
    policy(&h, true, true).await;
    let channel = h
        .state
        .configurations
        .get::<channel::StoredChannel>(h.tenant, channel::KIND, channel::id(h.tenant, ChannelKind::InApp))
        .await
        .unwrap()
        .unwrap();
    queue::enqueue(
        &h.state,
        h.tenant,
        vec![channel],
        "test",
        Id::new(),
        "capacity fixture",
        "test",
        Severity::Critical,
    )
    .await
    .unwrap();
    let queue_id = deterministic_id("agf.notification-outbox", &h.tenant.to_string());
    let before: Value = h.state.configurations.get(h.tenant, queue::KIND, queue_id).await.unwrap().unwrap();
    let template = before["jobs"].as_object().unwrap().values().next().unwrap();
    let mut full = before.clone();
    for _ in 1..1024 {
        let id = Id::new();
        let mut job = template.clone();
        job["id"] = json!(id);
        full["jobs"][id.to_string()] = job;
    }
    h.state.configurations.put(h.tenant, queue::KIND, queue_id, &full).await.unwrap();
    escalation::tick(&h.state, Timestamp::now()).await.unwrap();
    assert_eq!(receipts(&h).await["total"], 0);
    let stored = h.state.store.alert_get_durable(h.tenant, id).await.unwrap().unwrap();
    assert_eq!(stored.state, AlertState::Open);
    assert_eq!(stored.escalation_level, 0);
    h.state.configurations.put(h.tenant, queue::KIND, queue_id, &before).await.unwrap();
    escalation::tick(&h.state, Timestamp::now()).await.unwrap();
    assert_eq!(receipts(&h).await["total"], 2);
    let mut config = escalation::get(&h.state, h.tenant).await.unwrap();
    config.publisher.as_mut().unwrap().id = Id::new();
    h.state.configurations.put(h.tenant, escalation::KIND, escalation::id(h.tenant), &config).await.unwrap();
    let receipt = receipts(&h).await;
    let job = Id::parse(receipt["items"][0]["notification_ids"][0].as_str().unwrap()).unwrap();
    assert_eq!(queue::attempt(&h.state, h.tenant, job, Timestamp::now()).await.unwrap()["status"], "suppressed");
    let another = alert(&h, true).await;
    escalation::tick(&h.state, Timestamp::now()).await.unwrap();
    assert_eq!(h.state.store.alert_get_durable(h.tenant, another).await.unwrap().unwrap().escalation_level, 0);
    let health = call(&h, "GET", "/api/v1/alerts/escalation-config", None).await.json();
    assert!(health["health"]["error"].as_str().unwrap().contains("发布者"));
    finish(&h).await;
}
