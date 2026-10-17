//! A second API instance must revoke in-flight, SQL-backed red-team campaigns.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use agf_api::ApiStore;
use agf_core::{
    asset::Asset,
    enums::{AssetKind, Severity},
    ids::Id,
    redteam::{AttackCategory, AttackTurn, CampaignState, ExecutionMode, RedteamCase},
};
use agf_scan::redteam::CaseLibrary;
use agf_storage::{AssetRepo, Database, Store, configuration::ConfigStore, objectstore::MemoryObjectStore};
use common::*;
use std::time::Duration;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

const CANARY: &str = "CrossInstanceProtectedValue";

async fn instances() -> (Harness, Harness, Arc<Store>) {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap();
    let database = Database::from_pool(pool);
    database.migrate().await.unwrap();
    let db = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut first = setup().await;
    first.state.store = Arc::new(ApiStore::with_database(db.clone()));
    first.state.configurations = Arc::new(ConfigStore::new(Some(db.clone())));
    let tenant = agf_api::tenant_directory::new(format!("cross-instance-{}", Id::new()), "Cross-instance test".into());
    agf_api::tenant_directory::save(&first.state, tenant.clone(), true).await.unwrap();
    first.tenant = tenant.id;
    first.app = build_router(first.state.clone());
    let mut second = first.clone();
    second.state.store = Arc::new(ApiStore::with_database(db.clone()));
    second.state.configurations = Arc::new(ConfigStore::new(Some(db.clone())));
    second.app = build_router(second.state.clone());
    (first, second, db)
}

async fn post(h: &Harness, uri: &str, body: Value) -> Resp {
    h.request_with(
        "POST",
        uri,
        &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &h.tenant.to_string())],
        Some(body),
    )
    .await
}

async fn get(h: &Harness, uri: &str) -> Resp {
    h.request_with(
        "GET",
        uri,
        &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &h.tenant.to_string())],
        None,
    )
    .await
}

async fn wait_for_campaign(h: &Harness, id: &str) -> Value {
    for _ in 0..400 {
        let response = get(h, &format!("/api/v1/redteam/campaigns/{id}")).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text);
        if matches!(response.json()["campaign"]["state"].as_str(), Some("cancelled" | "completed" | "failed")) {
            return response.json();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("campaign did not finish")
}

async fn wait_for_requests(upstream: &MockServer, count: usize) {
    for _ in 0..150 {
        if upstream.received_requests().await.unwrap().len() >= count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("upstream never received request {count}")
}

async fn asset(db: &Store, tenant: TenantId, kind: AssetKind) -> Asset {
    let asset = Asset::new(tenant, kind, "cross-instance-target", "test");
    db.with_tenant(tenant, {
        let asset = asset.clone();
        move |tx| Box::pin(async move { AssetRepo::upsert(tx, &asset).await })
    })
    .await
    .unwrap();
    asset
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn second_instance_cancels_agent_before_followup_turn() {
    let (mut first, second, db) = instances().await;
    let asset = asset(&db, first.tenant, AssetKind::Agent).await;
    first.state.redteam_cases = Arc::new(CaseLibrary::from_cases(vec![RedteamCase {
        key: "LOCAL-CROSS-INSTANCE-AGENT".into(),
        title: "Two-turn Agent".into(),
        category: AttackCategory::DirectInjection,
        severity: Severity::Critical,
        mode: ExecutionMode::MultiTurn,
        turns: vec![
            AttackTurn { role: "user".into(), content: "First request".into(), expect: vec![] },
            AttackTurn { role: "user".into(), content: "Follow-up request".into(), expect: vec![] },
        ],
        applies_to: vec!["prompt".into()],
        success_signals: vec!["system_prompt_leak".into()],
        required_tools: vec![],
        tags: vec![],
        references: vec![],
        public_poc: false,
        remediation: "Keep protected values private".into(),
        author: "test".into(),
        version: 1,
    }]));
    first.app = build_router(first.state.clone());
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)).set_body_json(json!({
            "choices":[{"message":{"content":"No protected data"},"finish_reason":"stop"}]
        })))
        .expect(1)
        .mount(&upstream)
        .await;
    let url = format!("{}/v1/chat/completions", upstream.uri());
    let profile = post(
        &first,
        "/api/v1/redteam/agent-targets",
        json!({
            "expected_version":0,"asset_id":asset.id,"name":"Cross-instance Agent",
            "url":url,"model":"fixture-model","enabled":true,"protected_canary":CANARY
        }),
    )
    .await;
    assert_eq!(profile.status, StatusCode::OK, "{}", profile.text);
    let launched = post(
        &first,
        "/api/v1/redteam/campaigns",
        json!({
            "name":"cross-instance Agent cancel","execution_mode":"agent-http",
            "target_profile_id":profile.json()["id"],"target_profile_version":1,
            "case_keys":["LOCAL-CROSS-INSTANCE-AGENT"],"max_cases":1,"ci_gate":true
        }),
    )
    .await;
    assert_eq!(launched.status, StatusCode::ACCEPTED, "{}", launched.text);
    let id = launched.json()["task_id"].as_str().unwrap().to_owned();
    wait_for_requests(&upstream, 1).await;
    let audit_before = second.state.store.audit_stats_durable(first.tenant).await.unwrap();
    let deny_audit = format!(
        "ALTER TABLE audit_logs ADD CONSTRAINT deny_cross_instance_cancel_audit CHECK (tenant_id <> '{}'::uuid) NOT VALID",
        first.tenant
    );
    sqlx::query(&deny_audit).execute(db.db().pool()).await.unwrap();
    let rejected = post(&second, &format!("/api/v1/redteam/campaigns/{id}/cancel"), json!({})).await;
    assert!(!rejected.status.is_success(), "{}", rejected.text);
    let still_running =
        first.state.store.campaign_get_durable(first.tenant, id.parse().unwrap()).await.unwrap().unwrap();
    assert_eq!(still_running.campaign.state, CampaignState::Running);
    assert_eq!(second.state.store.audit_stats_durable(first.tenant).await.unwrap(), audit_before);
    sqlx::query("ALTER TABLE audit_logs DROP CONSTRAINT deny_cross_instance_cancel_audit")
        .execute(db.db().pool())
        .await
        .unwrap();
    let cancelled = post(&second, &format!("/api/v1/redteam/campaigns/{id}/cancel"), json!({})).await;
    assert_eq!(cancelled.status, StatusCode::OK, "{}", cancelled.text);
    assert_eq!(wait_for_campaign(&second, &id).await["campaign"]["state"], "cancelled");
    let audit_after = second.state.store.audit_stats_durable(first.tenant).await.unwrap();
    assert_eq!(audit_after.0, audit_before.0 + 1);
    let retried = post(&first, &format!("/api/v1/redteam/campaigns/{id}/cancel"), json!({})).await;
    assert_eq!(retried.status, StatusCode::OK, "{}", retried.text);
    assert_eq!(second.state.store.audit_stats_durable(first.tenant).await.unwrap(), audit_after);
    tokio::time::sleep(Duration::from_millis(5200)).await;
    assert_eq!(upstream.received_requests().await.unwrap().len(), 1);
    let record = first.state.store.campaign_get_durable(first.tenant, id.parse().unwrap()).await.unwrap().unwrap();
    assert!(record.results.is_empty());
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn second_instance_disables_mcp_before_followup_tool_call() {
    let (mut first, second, db) = instances().await;
    let asset = asset(&db, first.tenant, AssetKind::McpServer).await;
    let sequence: RedteamCase =
        serde_yaml::from_str(include_str!("../../../redteam/credential-theft/RT-MCP-002.yaml")).unwrap();
    first.state.redteam_cases = Arc::new(CaseLibrary::from_cases(vec![sequence]));
    first.app = build_router(first.state.clone());
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(header("mcp-method", "tools/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc":"2.0","id":1,"result":{"tools":[{
                "name":"safe_query","annotations":{"readOnlyHint":true},
                "inputSchema":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}
            }]}
        })))
        .expect(1)
        .mount(&upstream)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(header("mcp-method", "tools/call"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(1500)).set_body_json(json!({
            "jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"fixture-doc-7"}]}
        })))
        .expect(1)
        .mount(&upstream)
        .await;
    let url = format!("{}/mcp", upstream.uri());
    let profile = post(
        &first,
        "/api/v1/redteam/mcp-targets",
        json!({
            "expected_version":0,"asset_id":asset.id,"name":"Cross-instance MCP","url":url,
            "tool_name":"safe_query","argument_name":"query","enabled":true,"protected_canary":CANARY
        }),
    )
    .await;
    assert_eq!(profile.status, StatusCode::OK, "{}", profile.text);
    let id = profile.json()["id"].as_str().unwrap().to_owned();
    let launched = post(
        &first,
        "/api/v1/redteam/campaigns",
        json!({
            "name":"cross-instance MCP disable","execution_mode":"mcp-http",
            "target_profile_id":id,"target_profile_version":1,"case_keys":["RT-MCP-002"],
            "max_cases":1,"ci_gate":true
        }),
    )
    .await;
    assert_eq!(launched.status, StatusCode::ACCEPTED, "{}", launched.text);
    let campaign_id = launched.json()["task_id"].as_str().unwrap().to_owned();
    wait_for_requests(&upstream, 2).await;
    let disabled = post(
        &second,
        "/api/v1/redteam/mcp-targets",
        json!({
            "id":id,"expected_version":1,"asset_id":asset.id,"name":"Cross-instance MCP","url":url,
            "tool_name":"safe_query","argument_name":"query","enabled":false
        }),
    )
    .await;
    assert_eq!(disabled.status, StatusCode::OK, "{}", disabled.text);
    assert_eq!(disabled.json()["version"], 2);
    let done = wait_for_campaign(&second, &campaign_id).await;
    assert_eq!(done["campaign"]["ci_passed"], false);
    tokio::time::sleep(Duration::from_millis(1700)).await;
    assert_eq!(upstream.received_requests().await.unwrap().len(), 2);
    let record =
        first.state.store.campaign_get_durable(first.tenant, campaign_id.parse().unwrap()).await.unwrap().unwrap();
    assert!(record.results.iter().all(|result| !result.succeeded && result.finding_id.is_none()));
}
