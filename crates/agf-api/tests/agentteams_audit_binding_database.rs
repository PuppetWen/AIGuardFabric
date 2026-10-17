//! Real SQL checks for binding revisions, audit rollback and inventory lifecycle.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::{agentteams_audit::binding, source_store};
use agf_core::{audit::AuditActor, ids::Id};
use agf_ingest::pipeline::SqlSink;
use agf_storage::{AuditRepo, Database, Store, configuration::ConfigStore, objectstore::MemoryObjectStore};
use common::*;
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

const CLOUD: &str = "/api/v1/alicloud/connections/alicloud-agentteams";
const SYNC: &str = "/api/v1/alicloud/agentteams/sync";
const SOURCES: &str = "/api/v1/ingest/sources";

struct Fixture {
    h: Harness,
    db: Arc<Store>,
    tenant: TenantId,
    source: Id,
}

async fn call(h: &Harness, tenant: TenantId, method: &str, uri: &str, body: Option<Value>) -> Resp {
    let bearer = format!("Bearer {}", h.admin);
    let tenant = tenant.to_string();
    h.request_with(method, uri, &[("authorization", &bearer), ("x-agf-tenant", &tenant)], body).await
}

fn binding_path(source: Id) -> String {
    format!("/api/v1/alicloud/agentteams/audit-sources/{source}")
}

async fn save(f: &Fixture, source: Id, version: u64, enabled: bool) -> Resp {
    call(&f.h, f.tenant, "PUT", &binding_path(source), Some(json!({"expected_version":version,"enabled":enabled})))
        .await
}

async fn create_source(h: &Harness, tenant: TenantId) -> Id {
    let response = call(
        h,
        tenant,
        "POST",
        SOURCES,
        Some(json!({"name":format!("binding-sql-{}",Id::new()),"protocol":"http-webhook"})),
    )
    .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
    Id::parse(response.json()["id"].as_str().unwrap()).unwrap()
}

async fn sync(f: &Fixture) -> Resp {
    call(
        &f.h,
        f.tenant,
        "POST",
        SYNC,
        Some(json!({"request_id":Id::new(),"configuration_version":1,"confirm_live":false})),
    )
    .await
}

async fn heartbeat(f: &Fixture, binding_id: Id) -> Resp {
    call(
        &f.h,
        f.tenant,
        "POST",
        &format!("{}/events", binding_path(f.source)),
        Some(json!({"binding_id":binding_id,"events":[{
            "event_id":Id::new().to_string(),"event_time":Timestamp::now(),"kind":"heartbeat"
        }]})),
    )
    .await
}

async fn fixture() -> Fixture {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap();
    let db = Database::from_pool(pool);
    db.migrate().await.unwrap();
    let db = Arc::new(Store::new(db, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.state.configurations = Arc::new(ConfigStore::new(Some(db.clone())));
    h.state.ingest_sink = Arc::new(SqlSink::new(db.clone()).with_event_outbox(true));
    let tenant = agf_api::tenant_directory::new(format!("binding-sql-{}", Id::new()), "Binding SQL regression".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.app = build_router(h.state.clone());
    let cloud = call(
        &h,
        tenant.id,
        "PUT",
        CLOUD,
        Some(json!({"expected_version":0,"enabled":true,"mock":true,
            "settings":{"instance_id":format!("inst-{}",Id::new()),"account_id":Id::new().to_string()}})),
    )
    .await;
    assert_eq!(cloud.status, StatusCode::OK, "{}", cloud.text);
    let source = create_source(&h, tenant.id).await;
    let f = Fixture { h, db, tenant: tenant.id, source };
    let synced = sync(&f).await;
    assert_eq!(synced.status, StatusCode::OK, "{}", synced.text);
    f
}

async fn stored(f: &Fixture, source: Id) -> Option<Value> {
    f.h.state.configurations.get(f.tenant, binding::KIND, source).await.unwrap()
}

async fn chain(f: &Fixture) -> (i64, String) {
    let mut tx = f.db.db().begin_tenant(f.tenant).await.unwrap();
    let stats = AuditRepo::chain_stats(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    stats
}

async fn binding_audits(f: &Fixture, source: Id) -> i64 {
    let mut tx = f.db.db().begin_tenant(f.tenant).await.unwrap();
    let count = sqlx::query_scalar(
        "SELECT count(*) FROM audit_logs WHERE outcome='success'
        AND target->>'kind'=$1 AND target->>'id'=$2",
    )
    .bind(binding::KIND)
    .bind(source.to_string())
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    count
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn concurrent_routers_create_and_disable_only_one_expected_revision() {
    let f = fixture().await;
    // Separate API instances have independent caches; the database must serialize creation.
    let mut second = f.h.clone();
    second.state.configurations = Arc::new(ConfigStore::new(Some(f.db.clone())));
    second.state.store = Arc::new(agf_api::store::ApiStore::with_database(f.db.clone()));
    second.app = build_router(second.state.clone());
    for (expected, enabled) in [(0, true), (1, false)] {
        let path = binding_path(f.source);
        let body = json!({"expected_version":expected,"enabled":enabled});
        let before = binding_audits(&f, f.source).await;
        let (left, right) = tokio::join!(
            call(&f.h, f.tenant, "PUT", &path, Some(body.clone())),
            call(&second, f.tenant, "PUT", &path, Some(body)),
        );
        assert_eq!(
            [left.status, right.status].iter().filter(|status| **status == StatusCode::OK).count(),
            1,
            "only one expected revision may commit: {} | {}",
            left.text,
            right.text
        );
        assert_eq!([left.status, right.status].iter().filter(|status| **status == StatusCode::CONFLICT).count(), 1);
        let winner = if left.status == StatusCode::OK { left.json() } else { right.json() };
        let saved = stored(&f, f.source).await.unwrap();
        assert_eq!(saved["version"], expected + 1);
        assert_eq!(saved["enabled"], enabled);
        assert_eq!(saved["binding_id"], winner["bindingId"]);
        assert_eq!(binding_audits(&f, f.source).await, before + 1, "a losing revision must not append a success audit");
    }
    assert_eq!(binding_audits(&f, f.source).await, 2);
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn audit_failure_rolls_back_binding_creation_and_update_and_preserves_retry() {
    let f = fixture().await;
    let initial = save(&f, f.source, 0, true).await;
    assert_eq!(initial.status, StatusCode::OK, "{}", initial.text);
    let new_source = create_source(&f.h, f.tenant).await;
    let before = stored(&f, f.source).await.unwrap();
    let chain_before = chain(&f).await;
    let constraint = format!("agf_test_binding_audit_{}", Id::new().as_uuid().simple());
    assert!(constraint.len() <= 63 && constraint.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'));
    let install = format!(
        "ALTER TABLE audit_logs ADD CONSTRAINT {constraint}
        CHECK (NOT (tenant_id='{}'::uuid AND target->>'kind'='{}'
        AND target->>'id' IN ('{}','{}'))) NOT VALID",
        f.tenant,
        binding::KIND,
        f.source,
        new_source
    );
    sqlx::query(&install).execute(f.db.db().pool()).await.unwrap();
    // Always remove exactly this test's constraint before propagating an assertion panic.
    let outcome = AssertUnwindSafe(async {
        let rejected_create = save(&f, new_source, 0, true).await;
        let rejected_update = save(&f, f.source, 1, false).await;
        for response in [&rejected_create, &rejected_update] {
            assert!(!response.status.is_success(), "audit failure cannot report success: {}", response.text);
        }
        assert!(stored(&f, new_source).await.is_none(), "failed creation must not leave a binding row");
        assert_eq!(stored(&f, f.source).await.unwrap(), before);
        assert_eq!(chain(&f).await, chain_before, "failed audit must preserve count and hash chain tail");
    })
    .catch_unwind()
    .await;
    sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}"))
        .execute(f.db.db().pool())
        .await
        .unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
    let retried_create = save(&f, new_source, 0, true).await;
    let retried_update = save(&f, f.source, 1, false).await;
    assert_eq!(retried_create.status, StatusCode::OK, "{}", retried_create.text);
    assert_eq!(retried_update.status, StatusCode::OK, "{}", retried_update.text);
    assert_eq!(stored(&f, new_source).await.unwrap()["version"], 1);
    assert_eq!(stored(&f, f.source).await.unwrap()["version"], 2);
    assert_eq!(chain(&f).await.0, chain_before.0 + 2);
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn disabled_or_changed_resources_cannot_publish_a_new_binding_revision() {
    let f = fixture().await;
    assert_eq!(save(&f, f.source, 0, true).await.status, StatusCode::OK);
    let before = stored(&f, f.source).await.unwrap();
    let chain_before = chain(&f).await;
    let config_id = agf_api::integration_store::id(f.tenant, agf_api::cloud_inventory::NAME);
    for (kind, id, label, path, value, expected_status) in [
        (
            source_store::KIND,
            f.source,
            "disabled source",
            "/source/enabled",
            json!(false),
            StatusCode::PRECONDITION_FAILED,
        ),
        (source_store::KIND, f.source, "deleted source tombstone", "/source", Value::Null, StatusCode::NOT_FOUND),
        (
            agf_api::cloud_store::KIND,
            config_id,
            "disabled cloud",
            "/enabled",
            json!(false),
            StatusCode::PRECONDITION_FAILED,
        ),
        (
            agf_api::cloud_store::KIND,
            config_id,
            "changed cloud revision",
            "/version",
            json!(2),
            StatusCode::PRECONDITION_FAILED,
        ),
        (
            "cloud-inventory",
            config_id,
            "changed inventory revision",
            "/version",
            json!(2),
            StatusCode::PRECONDITION_FAILED,
        ),
        (
            "cloud-inventory",
            config_id,
            "same-version mismatched snapshot timestamp",
            "/updated_at",
            json!(Timestamp::now().offset_secs(1)),
            StatusCode::CONFLICT,
        ),
    ] {
        let original: Value = f.h.state.configurations.get(f.tenant, kind, id).await.unwrap().unwrap();
        let mut changed = original.clone();
        *changed.pointer_mut(path).unwrap() = value;
        f.h.state.configurations.put(f.tenant, kind, id, &changed).await.unwrap();
        let rejected = save(&f, f.source, 1, true).await;
        f.h.state.configurations.put(f.tenant, kind, id, &original).await.unwrap();
        assert_eq!(rejected.status, expected_status, "{label}: {}", rejected.text);
        assert_eq!(stored(&f, f.source).await.unwrap(), before, "{label}");
        assert_eq!(chain(&f).await, chain_before, "{label}");
    }
    let saved = save(&f, f.source, 1, true).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.json()["version"], 2);
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn equivalent_inventory_refresh_preserves_binding_identity_and_advances_optimistic_version() {
    let f = fixture().await;
    assert_eq!(save(&f, f.source, 0, true).await.status, StatusCode::OK);
    let before: binding::Binding = binding::load(&f.h.state, f.tenant, f.source).await.unwrap().unwrap();
    let mut version = before.version;
    let mut inventory_at = before.inventory_updated_at;
    for _ in 0..2 {
        let synced = sync(&f).await;
        assert_eq!(synced.status, StatusCode::OK, "{}", synced.text);
        let after = binding::load(&f.h.state, f.tenant, f.source).await.unwrap().unwrap();
        let snapshot = agf_api::cloud_inventory::load(&f.h.state, f.tenant).await.unwrap().unwrap();
        assert_eq!(after.binding_id, before.binding_id, "equivalent inventory must preserve collector identity");
        assert_eq!(after.bound_at, before.bound_at);
        assert_eq!(after.scope_id, before.scope_id);
        assert_eq!(after.version, version + 1);
        assert_ne!(after.inventory_updated_at, inventory_at);
        assert_eq!(after.inventory_updated_at, snapshot.checked_at);
        assert_eq!(serde_json::to_value(&after.members).unwrap(), serde_json::to_value(&before.members).unwrap());
        let source = source_store::load(&f.h.state, f.tenant, f.source).await.unwrap().source.unwrap();
        let context = binding::context(&f.h.state, f.tenant).await.unwrap().unwrap();
        assert!(binding::current(&after, &context, &source));
        let continued = heartbeat(&f, before.binding_id).await;
        assert_eq!(continued.status, StatusCode::OK, "{}", continued.text);
        assert_eq!(continued.json()["accepted"], 1, "collector must continue after each equivalent refresh");
        version = after.version;
        inventory_at = after.inventory_updated_at;
    }
    let outdated = save(&f, f.source, before.version, false).await;
    assert_eq!(outdated.status, StatusCode::CONFLICT, "{}", outdated.text);
    let latest = save(&f, f.source, version, false).await;
    assert_eq!(latest.status, StatusCode::OK, "{}", latest.text);
    assert_eq!(latest.json()["version"], version + 1);
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn changed_cloud_scope_cannot_refresh_or_accept_the_previous_worker_mapping() {
    let f = fixture().await;
    assert_eq!(save(&f, f.source, 0, true).await.status, StatusCode::OK);
    let before = binding::load(&f.h.state, f.tenant, f.source).await.unwrap().unwrap();
    let changed = call(
        &f.h,
        f.tenant,
        "PUT",
        CLOUD,
        Some(json!({"expected_version":1,"enabled":true,"mock":true,"settings":{
            "instance_id":format!("switched-{}",Id::new()),"account_id":Id::new().to_string()
        }})),
    )
    .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    let synced = call(
        &f.h,
        f.tenant,
        "POST",
        SYNC,
        Some(json!({"request_id":Id::new(),"configuration_version":2,"confirm_live":false})),
    )
    .await;
    assert_eq!(synced.status, StatusCode::OK, "{}", synced.text);
    assert_eq!(synced.json()["bindingsRefreshed"], 0);
    let after = binding::load(&f.h.state, f.tenant, f.source).await.unwrap().unwrap();
    assert_eq!(serde_json::to_value(&after).unwrap(), serde_json::to_value(&before).unwrap());
    let rejected = heartbeat(&f, before.binding_id).await;
    assert_eq!(rejected.status, StatusCode::CONFLICT, "{}", rejected.text);
    let accepted = save(&f, f.source, before.version, true).await;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.text);
    let rebound = binding::load(&f.h.state, f.tenant, f.source).await.unwrap().unwrap();
    assert_ne!(rebound.scope_id, before.scope_id);
    assert_ne!(rebound.binding_id, before.binding_id);
    assert_ne!(rebound.members["worker-demo"].asset_id, before.members["worker-demo"].asset_id);
    assert_eq!(heartbeat(&f, rebound.binding_id).await.status, StatusCode::OK);
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn inventory_refresh_configuration_or_audit_failure_rolls_back_snapshot_and_binding_together() {
    let f = fixture().await;
    assert_eq!(save(&f, f.source, 0, true).await.status, StatusCode::OK);
    let config_id = agf_api::integration_store::id(f.tenant, agf_api::cloud_inventory::NAME);
    let snapshot_before: Value =
        f.h.state.configurations.get(f.tenant, "cloud-inventory", config_id).await.unwrap().unwrap();
    let binding_before = stored(&f, f.source).await.unwrap();
    let chain_before = chain(&f).await;
    for (table, predicate) in [
        (
            "console_configurations",
            format!("tenant_id='{}'::uuid AND kind='{}' AND id='{}'::uuid", f.tenant, binding::KIND, f.source),
        ),
        ("audit_logs", format!("tenant_id='{}'::uuid AND actor->>'name'='binding-refresh-sql-fault'", f.tenant)),
    ] {
        let constraint = format!("agf_test_binding_refresh_{}", Id::new().as_uuid().simple());
        assert!(constraint.len() <= 63);
        sqlx::query(&format!("ALTER TABLE {table} ADD CONSTRAINT {constraint} CHECK (NOT ({predicate})) NOT VALID"))
            .execute(f.db.db().pool())
            .await
            .unwrap();
        let outcome = AssertUnwindSafe(async {
            // Exercise the publication transaction directly: an HTTP failure audit is a separate
            // legitimate operation and would obscure whether this success audit rolled back.
            let result = agf_api::cloud_inventory::sync(
                &f.h.state,
                f.tenant,
                "binding-refresh-test".into(),
                AuditActor {
                    id: None,
                    kind: "service".into(),
                    name: "binding-refresh-sql-fault".into(),
                    source_ip: None,
                    user_agent: None,
                    session_id: None,
                },
                agf_api::cloud_inventory::SyncRequest {
                    request_id: Id::new(),
                    configuration_version: 1,
                    confirm_live: false,
                },
            )
            .await;
            assert!(result.is_err(), "{table} fault must reject inventory publication");
            let snapshot_after: Value =
                f.h.state.configurations.get(f.tenant, "cloud-inventory", config_id).await.unwrap().unwrap();
            assert_eq!(snapshot_after, snapshot_before, "{table}: encrypted snapshot must remain unchanged");
            assert_eq!(
                stored(&f, f.source).await.unwrap(),
                binding_before,
                "{table}: no binding revision may escape rollback"
            );
            assert_eq!(chain(&f).await, chain_before, "{table}: success audit cannot escape rollback");
        })
        .catch_unwind()
        .await;
        sqlx::query(&format!("ALTER TABLE {table} DROP CONSTRAINT {constraint}"))
            .execute(f.db.db().pool())
            .await
            .unwrap();
        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
    }
    let retried = sync(&f).await;
    assert_eq!(retried.status, StatusCode::OK, "{}", retried.text);
    assert_eq!(retried.json()["bindingsRefreshed"], 1);
    assert_eq!(stored(&f, f.source).await.unwrap()["version"], 2);
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn returning_to_previous_membership_does_not_revive_a_binding_that_became_stale() {
    let f = fixture().await;
    assert_eq!(save(&f, f.source, 0, true).await.status, StatusCode::OK);
    let before = binding::load(&f.h.state, f.tenant, f.source).await.unwrap().unwrap();
    let config_id = agf_api::integration_store::id(f.tenant, agf_api::cloud_inventory::NAME);
    let mut inventory: agf_api::integration_store::Stored =
        f.h.state.configurations.get(f.tenant, "cloud-inventory", config_id).await.unwrap().unwrap();
    let mut private = agf_api::integration_store::decrypt(&f.h.state, f.tenant, &inventory).unwrap();
    // Model a complete provider snapshot B in the same cloud scope: Worker still exists,
    // but no longer belongs to the team frozen in snapshot A. Keep the real encrypted envelope.
    inventory.updated_at = inventory.updated_at.offset_secs(1);
    let snapshot = private.settings.get_mut("snapshot").unwrap();
    snapshot["checked_at"] = json!(inventory.updated_at);
    snapshot["teams"][0]["WorkerNames"] = json!([]);
    snapshot["workers"][0]["Groups"] = json!([]);
    inventory.private =
        agf_api::model_gateway::encrypt(&f.h.state, f.tenant, config_id, serde_json::to_string(&private).unwrap())
            .unwrap();
    f.h.state.configurations.put(f.tenant, "cloud-inventory", config_id, &inventory).await.unwrap();
    assert_eq!(heartbeat(&f, before.binding_id).await.status, StatusCode::CONFLICT);
    // The ordinary Mock API now returns the original membership A. Equality with old A alone
    // must not revive a binding pinned before intervening B; only explicit review can rebind.
    let restored = sync(&f).await;
    assert_eq!(restored.status, StatusCode::OK, "{}", restored.text);
    assert_eq!(restored.json()["bindingsRefreshed"], 0);
    assert_eq!(stored(&f, f.source).await.unwrap(), serde_json::to_value(&before).unwrap());
    assert_eq!(heartbeat(&f, before.binding_id).await.status, StatusCode::CONFLICT);
    let rebound = save(&f, f.source, before.version, true).await;
    assert_eq!(rebound.status, StatusCode::OK, "{}", rebound.text);
    let after = binding::load(&f.h.state, f.tenant, f.source).await.unwrap().unwrap();
    assert_ne!(after.binding_id, before.binding_id);
    assert_eq!(heartbeat(&f, after.binding_id).await.status, StatusCode::OK);
}
