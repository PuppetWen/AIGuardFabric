//! 专用 PostgreSQL 验收：策略/配额/采集日志跨实例保持，签名拒绝篡改。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{
    enums::{IngestProtocol, QuotaDimension},
    event::RawLog,
    ids::Id,
    quota::{Quota, QuotaConsumption},
};
use agf_ingest::pipeline::{Sink, SqlSink};
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use common::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires AGF_TEST_DATABASE_URL pointing to an isolated test database"]
async fn control_state_and_ingest_survive_fresh_instances() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap();
    let database = Database::from_pool(pool.clone());
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut first = setup().await;
    first.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    first.state.configurations = Arc::new(agf_api::config_store::ConfigStore::new(Some(store.clone())));
    first.app = build_router(first.state.clone());
    let name = format!("persist-{}", Id::new());
    let created = first
        .post(
            "/api/v1/policies",
            json!({"name":name,"language":"cel","source":"{\"action\":\"audit\"}","action":"audit"}),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let policy: agf_core::policy::Policy = serde_json::from_value(created.json()["policy"].clone()).unwrap();
    let mut quota = Quota::tenant_default(first.tenant, QuotaDimension::Requests, 2);
    quota.name = name.clone();
    quota.window = agf_core::quota::QuotaWindow::Total;
    quota.scope = agf_core::enums::QuotaScope::Session;
    let saved = agf_api::quota_definitions::save(&first.state, first.tenant, quota).await.unwrap();
    let lease = agf_api::runtime_quota::Lease::acquire(
        &first.state,
        first.tenant,
        None,
        &name,
        "owner",
        &QuotaConsumption::one_request(),
    )
    .await
    .unwrap();
    lease.finish(None).await.unwrap();
    let raw = RawLog {
        id: Id::new(),
        tenant_id: first.tenant,
        source_id: Id::new(),
        received_at: Timestamp::now(),
        protocol: IngestProtocol::Webhook,
        payload_b64: "e30=".into(),
        payload_hash: agf_core::secret::content_hash(&name),
        bytes: 2,
        origin: name,
        parsed: false,
        parse_error: None,
        event_id: None,
    };
    SqlSink::new(store.clone()).put_raw(&raw).await.unwrap();
    let mut second = setup().await;
    second.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    second.state.configurations = Arc::new(agf_api::config_store::ConfigStore::new(Some(store.clone())));
    let integration_version = agf_api::integration_store::load(&first.state, first.tenant, "webhook")
        .await
        .unwrap()
        .map_or(0, |row| row.version);
    let integration_body = serde_json::from_value(json!({"enabled":true,"mock":true,
        "expected_version":integration_version,"settings":{},
        "secrets":{"webhook_url":"http://127.0.0.1:18999/PRIVATE-LOCAL-TEST"}}))
    .unwrap();
    agf_api::integration_store::save(&first.state, first.tenant, "webhook", integration_body).await.unwrap();
    let saved_integration = agf_api::integration_store::view(&second.state, first.tenant, "webhook").await.unwrap();
    assert_eq!(saved_integration["version"], integration_version + 1);
    assert!(!saved_integration.to_string().contains("PRIVATE-LOCAL-TEST"));
    let operation: agf_api::integration_runtime::Request = serde_json::from_value(json!({"request_id":Id::new(),
        "configuration_version":integration_version+1,"operation":"send","payload":{"kind":"notification",
        "event_type":"notify.alert","title":"Database receipt","summary":"Local-only mock","severity":"medium",
        "occurred_at":"2026-09-20T10:00:00Z","idempotency_key":Id::new().to_string()}}))
    .unwrap();
    let receipt =
        agf_api::integration_runtime::execute(&first.state, first.tenant, "webhook", "test".into(), operation.clone())
            .await
            .unwrap();
    let repeated =
        agf_api::integration_runtime::execute(&second.state, first.tenant, "webhook", "test".into(), operation)
            .await
            .unwrap();
    assert_eq!(receipt, repeated, "fresh instance must replay the committed receipt");
    assert_eq!(receipt["status"], "succeeded");
    assert!(agf_api::integration_runtime::history(&second.state, TenantId::new(), "webhook").await.unwrap().is_empty());
    assert!(agf_api::policy_store::get(&second.state, second.tenant, policy.id).await.unwrap().is_some());
    assert_eq!(agf_api::runtime_quota::usage(&second.state, second.tenant).await.unwrap()[&saved.id], 1);
    assert!(
        SqlSink::new(store.clone())
            .unparsed_raw(second.tenant, 10000)
            .await
            .unwrap()
            .iter()
            .any(|row| row.id == raw.id)
    );
    assert!(SqlSink::new(store.clone()).unparsed_raw(TenantId::new(), 10000).await.unwrap().is_empty());
    assert_eq!(SqlSink::new(store.clone()).raw_count(TenantId::new()).await.unwrap(), 0);
    assert_eq!(SqlSink::new(store.clone()).event_count(TenantId::new()).await.unwrap(), 0);
    agf_api::policy_store::delete(&second.state, second.tenant, policy.id).await.unwrap();
    assert!(agf_api::policy_store::get(&first.state, first.tenant, policy.id).await.unwrap().is_none());
    // Source configuration and counters survive a fresh control-plane instance.
    first.state.ingest_sink = Arc::new(SqlSink::new(store.clone()));
    first.app = build_router(first.state.clone());
    let source_response = first
        .post(
            "/api/v1/ingest/sources",
            json!({
                "name": format!("persistent-source-{}", Id::new()), "protocol": "http-webhook"
            }),
        )
        .await;
    assert_eq!(source_response.status, StatusCode::CREATED, "{}", source_response.text);
    let source_id = Id::parse(source_response.json()["id"].as_str().unwrap()).unwrap();
    let before_raw = first.state.ingest_sink.raw_count(first.tenant).await.unwrap();
    let pushed = first
        .post(
            &format!("/api/v1/ingest/sources/{source_id}/events"),
            json!({"message":format!("persisted-log-{}",Id::new())}),
        )
        .await;
    assert_eq!(pushed.status, StatusCode::OK, "{}", pushed.text);
    let record = agf_api::source_store::load(&second.state, first.tenant, source_id).await.unwrap();
    assert_eq!(record.received, 1);
    assert_eq!(record.source.unwrap().total_events, 1);
    assert_eq!(SqlSink::new(store.clone()).raw_count(first.tenant).await.unwrap(), before_raw + 1);
    assert!(agf_api::source_store::load(&second.state, TenantId::new(), source_id).await.is_err());
    // Containment survives server replacement; release and tenant isolation use the same SQL store.
    let controlled_agent = Id::new();
    let control = agf_api::containment::Control {
        id: Id::new(),
        case_id: Id::new(),
        action: agf_core::case::ContainmentAction::IsolateAgent,
        target: controlled_agent.to_string(),
        tools: Vec::new(),
        endpoint_id: None,
        active: true,
        actor: "database-test".into(),
        reason: "persist".into(),
        created_at: Timestamp::now(),
        released_by: None,
        released_at: None,
    };
    first.state.configurations.put(first.tenant, agf_api::containment::KIND, control.id, &control).await.unwrap();
    assert!(
        agf_api::containment::enforce(
            &second.state,
            first.tenant,
            Some(controlled_agent),
            "session",
            &json!({}),
            false
        )
        .await
        .is_err()
    );
    assert!(
        agf_api::containment::enforce(
            &second.state,
            TenantId::new(),
            Some(controlled_agent),
            "session",
            &json!({}),
            false
        )
        .await
        .is_ok()
    );
    agf_api::containment::release(&second.state, first.tenant, control.case_id, control.id, "database-test")
        .await
        .unwrap();
    assert!(
        agf_api::containment::enforce(&first.state, first.tenant, Some(controlled_agent), "session", &json!({}), false)
            .await
            .is_ok()
    );
    // Durable reports and scheduler claims are shared by independent server instances.
    let parser_key = format!("persist-parser-{}", Id::new());
    let parser_input = json!({"definition":{"key":parser_key,"name":"Persistent parser","engine":"json-path",
        "pattern":"$","required_fields":["signal"],"mapping":{"map":{"signal":"event.action"}}},
        "sample":"{\"signal\":\"test\"}","enabled":true,"priority":1});
    let parser = first.post("/api/v1/parsers", parser_input).await;
    assert_eq!(parser.status, StatusCode::CREATED, "{}", parser.text);
    let parser_id = Id::parse(parser.json()["id"].as_str().unwrap()).unwrap();
    assert_eq!(agf_api::parser_store::find(&second.state, first.tenant, &parser_key).await.unwrap().id, parser_id);
    assert!(agf_api::parser_store::find(&second.state, TenantId::new(), &parser_key).await.is_err());
    let created = first.post("/api/v1/reports", json!({"title":"持久报表","format":"pdf"})).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let report_id = Id::parse(created.json()["report"]["id"].as_str().unwrap()).unwrap();
    let durable_report = agf_api::report_service::get(&second.state, first.tenant, report_id).await.unwrap().unwrap();
    let original = agf_api::report_service::artifact(&first.state, &durable_report).await.unwrap();
    let reopened = agf_api::report_service::artifact(&second.state, &durable_report).await.unwrap();
    assert_eq!(original, reopened);
    assert!(reopened.0.starts_with(b"%PDF-"));
    let schedule = first.post("/api/v1/reports/schedules", json!({"name":"cross-instance","cron":"* * * * *"})).await;
    assert_eq!(schedule.status, StatusCode::CREATED, "{}", schedule.text);
    let id = Id::parse(schedule.json()["schedule"]["id"].as_str().unwrap()).unwrap();
    let now = Timestamp::now();
    let (a, b) = tokio::join!(
        agf_api::report_service::run_one(
            &first.state,
            first.tenant,
            id,
            now,
            agf_api::report_service::RunOrigin::Scheduled
        ),
        agf_api::report_service::run_one(
            &second.state,
            first.tenant,
            id,
            now,
            agf_api::report_service::RunOrigin::Scheduled
        )
    );
    assert_eq!(usize::from(a.unwrap().is_some()) + usize::from(b.unwrap().is_some()), 1);
    // 独立副本认证必须读取数据库，不能继续接受另一副本已吊销的凭据。
    first.state.store = Arc::new(agf_api::ApiStore::with_database(store.clone()));
    second.state.store = Arc::new(agf_api::ApiStore::with_database(store.clone()));
    let key = first.state.api_keys.issue(ApiKeyIssueRequest::named(first.tenant, "database-key", Timestamp::now()));
    first.state.store.api_key_create_durable(&key.record).await.unwrap();
    assert!(second.state.verify_api_key(&key.plaintext, None).await.is_ok());
    first.state.store.api_key_revoke_durable(first.tenant, key.record.id).await.unwrap();
    assert!(second.state.verify_api_key(&key.plaintext, None).await.is_err());
    let tenant = agf_api::tenant_directory::new(format!("company-{}", Id::new()), "独立企业".into());
    agf_api::tenant_directory::save(&first.state, tenant.clone(), true).await.unwrap();
    assert_eq!(agf_api::tenant_directory::resolve(&second.state, &tenant.slug).await.unwrap().id, tenant.id);
    pool.close().await;
}
