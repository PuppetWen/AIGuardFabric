//! Tenant-scoped endpoint credentials and discovered tools survive a fresh API instance.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_storage::{AuditRepo, Database, Store, objectstore::MemoryObjectStore};
use common::*;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn endpoint_and_complete_tool_inventory_survive_instance_replacement() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap();
    let database = Database::from_pool(pool.clone());
    database.migrate().await.unwrap();
    let database = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(database.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(database.clone())));
    let tenant = agf_api::tenant_directory::new(format!("mcp-sql-{}", TenantId::new()), "MCP SQL validation".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.app = build_router(h.state.clone());
    let token = format!("Bearer {}", h.admin);
    let tenant_id = tenant.id.to_string();
    let headers = [("authorization", token.as_str()), ("x-agf-tenant", tenant_id.as_str())];
    let upstream = MockServer::start().await;
    Mock::given(method("POST")).respond_with(|request: &wiremock::Request| {
        assert_eq!(request.headers["authorization"],"Bearer sql-only-secret");
        let frame: Value = serde_json::from_slice(&request.body).unwrap();
        let result = if frame["method"] == "server/discover" {
            json!({"serverInfo":{"name":"SQL fixture","version":"1"},"capabilities":{"tools":{}}})
        } else if frame["params"].get("cursor").is_none() {
            json!({"tools":[{"name":"first","description":"read only","inputSchema":{"type":"object"}}],"nextCursor":"second"})
        } else {
            json!({"tools":[{"name":"second","description":"read only","inputSchema":{"type":"object"}}]})
        };
        ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":frame["id"],"result":result}))
    }).mount(&upstream).await;
    let mut input = json!({"expected_version":0,"name":"SQL MCP fixture","url":format!("{}/mcp",upstream.uri()),
        "enabled":true,"idle_timeout_secs":5,"bearer_token":"sql-only-secret"});
    let saved = h.request_with("POST", "/api/v1/mcp/endpoints", &headers, Some(input.clone())).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let id = agf_core::ids::Id::parse(saved.json()["id"].as_str().unwrap()).unwrap();
    let id_text = id.to_string();
    let mut audit_tx = database.db().begin_tenant(tenant.id).await.unwrap();
    let audits = AuditRepo::load_chain(&mut audit_tx, 0, 1_000).await.unwrap();
    assert!(audits.iter().any(|entry| {
        entry.target.kind == "mcp-http-endpoint" && entry.target.id.as_deref() == Some(id_text.as_str())
    }));
    audit_tx.commit().await.unwrap();
    let rows = agf_api::mcp_gateway::config::list(&h.state, tenant.id).await.unwrap();
    assert!(!serde_json::to_string(&rows).unwrap().contains("sql-only-secret"));
    let probe_url = format!("/api/v1/mcp/endpoints/{id}/probe");
    let probe = h.request_with("POST", &probe_url, &headers, Some(json!({"protocol":"2026-07-28"}))).await;
    assert_eq!(probe.status, StatusCode::OK, "{}", probe.text);
    assert_eq!(probe.json()["tools"]["tools"].as_array().unwrap().len(), 2);
    let tools: Value = sqlx::query_scalar("SELECT attributes->'tools' FROM assets WHERE tenant_id=$1 AND id=$2")
        .bind(tenant.id.as_uuid())
        .bind(id.as_uuid())
        .fetch_one(database.db().pool())
        .await
        .unwrap();
    assert_eq!(tools.as_array().unwrap().len(), 2, "success waits for asset SQL commit");
    let mut fresh = h.state.clone();
    fresh.store = Arc::new(agf_api::store::ApiStore::with_database(database.clone()));
    fresh.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(database)));
    h.state = fresh.clone();
    h.app = build_router(fresh);
    let detail = h.request_with("GET", &format!("/api/v1/mcps/{id}"), &headers, None).await;
    assert_eq!(detail.status, StatusCode::OK, "{}", detail.text);
    assert_eq!(detail.json()["mcp_server"]["toolCount"], 2);
    let tools = h.request_with("GET", &format!("/api/v1/mcp-servers/{id}/tools"), &headers, None).await;
    assert_eq!(tools.json().as_array().unwrap().len(), 2);
    assert_eq!(
        agf_api::mcp_gateway::config::credential(&h.state, tenant.id, &rows[0]).unwrap().as_deref(),
        Some("sql-only-secret")
    );
    input.as_object_mut().unwrap().remove("bearer_token");
    input["id"] = json!(id);
    input["expected_version"] = json!(1);
    let (first, second) = tokio::join!(
        h.request_with("POST", "/api/v1/mcp/endpoints", &headers, Some(input.clone())),
        h.request_with("POST", "/api/v1/mcp/endpoints", &headers, Some(input))
    );
    assert!(matches!(
        (first.status, second.status),
        (StatusCode::OK, StatusCode::CONFLICT) | (StatusCode::CONFLICT, StatusCode::OK)
    ));
    let latest = h.request_with("GET", &format!("/api/v1/mcps/{id}"), &headers, None).await;
    assert!(latest.json()["mcp_server"]["toolCount"].is_null(), "old catalog is invalid after reconfiguration");
    assert!(latest.json()["mcp_server"]["lastSeenAt"].is_null());
    assert!(agf_api::mcp_gateway::config::list(&h.state, TenantId::new()).await.unwrap().is_empty());

    let mut audit_tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    let audit_before = AuditRepo::chain_stats(&mut audit_tx).await.unwrap();
    audit_tx.commit().await.unwrap();
    let asset_name_before: String = sqlx::query_scalar("SELECT name FROM assets WHERE tenant_id=$1 AND id=$2")
        .bind(tenant.id.as_uuid())
        .bind(id.as_uuid())
        .fetch_one(&pool)
        .await
        .unwrap();
    let constraint = format!("agf_test_mcp_audit_{}", agf_core::ids::Id::new().as_uuid().simple());
    let create = format!(
        "ALTER TABLE audit_logs ADD CONSTRAINT {constraint} CHECK (tenant_id <> '{}'::uuid) NOT VALID",
        tenant.id
    );
    sqlx::query(&create).execute(&pool).await.unwrap();
    let rejected = h
        .request_with(
            "POST",
            "/api/v1/mcp/endpoints",
            &headers,
            Some(json!({"id":id,"expected_version":2,"name":"Must roll back",
                "url":format!("{}/mcp",upstream.uri()),"enabled":true,"idle_timeout_secs":5})),
        )
        .await;
    let drop_constraint = format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}");
    sqlx::query(&drop_constraint).execute(&pool).await.unwrap();
    assert_eq!(rejected.status, StatusCode::BAD_REQUEST, "audit failure must reject MCP configuration");
    assert!(rejected.text.contains("CHECK"), "the injected audit constraint must cause the rejection");
    assert_eq!(agf_api::mcp_gateway::config::get(&h.state, tenant.id, id).await.unwrap().version, 2);
    let asset_name_after: String = sqlx::query_scalar("SELECT name FROM assets WHERE tenant_id=$1 AND id=$2")
        .bind(tenant.id.as_uuid())
        .bind(id.as_uuid())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(asset_name_after, asset_name_before);
    let mut audit_tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    assert_eq!(AuditRepo::chain_stats(&mut audit_tx).await.unwrap(), audit_before);
    audit_tx.commit().await.unwrap();
    pool.close().await;
}
