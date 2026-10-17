//! Agent and MCP red-team target changes must commit with their success audits.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::tenant_directory;
use agf_core::{asset::Asset, enums::AssetKind, ids::Id};
use agf_storage::{AssetRepo, AuditRepo, Database, Store, objectstore::MemoryObjectStore};
use common::*;

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn agent_and_mcp_target_writes_roll_back_with_failed_audit() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap();
    let database = Database::from_pool(pool.clone());
    database.migrate().await.unwrap();
    let store = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(store.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(store.clone())));
    let tenant = tenant_directory::new(format!("redteam-target-audit-{}", Id::new()), "Red-team target audit".into());
    tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    let agent = Asset::new(tenant.id, AssetKind::Agent, "audit-agent", "test-agent");
    let mcp = Asset::new(tenant.id, AssetKind::McpServer, "audit-mcp", "test-mcp");
    for asset in [&agent, &mcp] {
        let asset = asset.clone();
        store
            .with_tenant(tenant.id, move |tx| Box::pin(async move { AssetRepo::upsert(tx, &asset).await }))
            .await
            .unwrap();
    }
    h.app = build_router(h.state.clone());
    let token = format!("Bearer {}", h.admin);
    let tenant_id = tenant.id.to_string();
    let headers = [("authorization", token.as_str()), ("x-agf-tenant", tenant_id.as_str())];
    let agent_path = "/api/v1/redteam/agent-targets";
    let mcp_path = "/api/v1/redteam/mcp-targets";
    let agent_body = json!({"expected_version":0,"asset_id":agent.id,"name":"Audit Agent",
        "url":"http://127.0.0.1:12345/v1/chat/completions","model":"fixture-model","enabled":true,
        "bearer_token":"local-agent-token","protected_canary":"AGENT_CANARY_123456789"});
    let mcp_body = json!({"expected_version":0,"asset_id":mcp.id,"name":"Audit MCP",
        "url":"http://127.0.0.1:12345/mcp","tool_name":"safe_query","argument_name":"query",
        "enabled":true,"bearer_token":"local-mcp-token","protected_canary":"MCP_CANARY_123456789"});
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    let chain_before = AuditRepo::chain_stats(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    let constraint = format!("agf_test_redteam_target_audit_{}", Id::new().as_uuid().simple());
    let install_constraint = format!(
        "ALTER TABLE audit_logs ADD CONSTRAINT {constraint} CHECK (tenant_id <> '{}'::uuid) NOT VALID",
        tenant.id
    );
    let drop_constraint = format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}");
    sqlx::query(&install_constraint).execute(&pool).await.unwrap();
    for (path, body) in [(agent_path, agent_body.clone()), (mcp_path, mcp_body.clone())] {
        let failed = h.request_with("POST", path, &headers, Some(body)).await;
        assert!(!failed.status.is_success(), "{path}: {}", failed.text);
        let listed = h.request_with("GET", path, &headers, None).await;
        assert_eq!(listed.json()["items"].as_array().unwrap().len(), 0, "{path}");
    }
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    assert_eq!(AuditRepo::chain_stats(&mut tx).await.unwrap(), chain_before);
    tx.commit().await.unwrap();
    sqlx::query(&drop_constraint).execute(&pool).await.unwrap();

    let created_agent = h.request_with("POST", agent_path, &headers, Some(agent_body.clone())).await;
    let created_mcp = h.request_with("POST", mcp_path, &headers, Some(mcp_body.clone())).await;
    assert_eq!(created_agent.status, StatusCode::OK, "{}", created_agent.text);
    assert_eq!(created_mcp.status, StatusCode::OK, "{}", created_mcp.text);
    let agent_id = created_agent.json()["id"].as_str().unwrap().to_owned();
    let mcp_id = created_mcp.json()["id"].as_str().unwrap().to_owned();
    for (actor, id) in [("redteam-agent-target", &agent_id), ("redteam-mcp-target", &mcp_id)] {
        let audit = h.request_with("GET", &format!("/api/v1/audit?actor={actor}&action=create"), &headers, None).await;
        assert_eq!(audit.json()["total"], 1, "{actor}");
        assert_eq!(audit.json()["items"][0]["target"]["id"], id.as_str());
    }
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    let chain_after_create = AuditRepo::chain_stats(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    sqlx::query(&install_constraint).execute(&pool).await.unwrap();
    for (path, id, original) in [(agent_path, &agent_id, &agent_body), (mcp_path, &mcp_id, &mcp_body)] {
        let mut edit = original.clone();
        edit["id"] = json!(id);
        edit["expected_version"] = json!(1);
        edit["name"] = json!("Changed target");
        edit.as_object_mut().unwrap().remove("bearer_token");
        edit.as_object_mut().unwrap().remove("protected_canary");
        let failed = h.request_with("POST", path, &headers, Some(edit)).await;
        assert!(!failed.status.is_success(), "{path}: {}", failed.text);
        let failed =
            h.request_with("DELETE", &format!("{path}/{id}"), &headers, Some(json!({"expected_version":1}))).await;
        assert!(!failed.status.is_success(), "{path}/{id}: {}", failed.text);
        let retained = h.request_with("GET", &format!("{path}/{id}"), &headers, None).await;
        assert_eq!(retained.status, StatusCode::OK, "{path}/{id}: {}", retained.text);
        assert_eq!(retained.json()["version"], 1);
        assert_eq!(retained.json()["name"], original["name"]);
    }
    let mut tx = h.state.store.database().unwrap().db().begin_tenant(tenant.id).await.unwrap();
    assert_eq!(AuditRepo::chain_stats(&mut tx).await.unwrap(), chain_after_create);
    tx.commit().await.unwrap();
    sqlx::query(&drop_constraint).execute(&pool).await.unwrap();
    for (path, id, actor) in
        [(agent_path, &agent_id, "redteam-agent-target"), (mcp_path, &mcp_id, "redteam-mcp-target")]
    {
        let removed =
            h.request_with("DELETE", &format!("{path}/{id}"), &headers, Some(json!({"expected_version":1}))).await;
        assert_eq!(removed.status, StatusCode::OK, "{path}/{id}: {}", removed.text);
        assert_eq!(h.request_with("GET", &format!("{path}/{id}"), &headers, None).await.status, StatusCode::NOT_FOUND);
        let audit = h.request_with("GET", &format!("/api/v1/audit?actor={actor}&action=delete"), &headers, None).await;
        assert_eq!(audit.json()["total"], 1, "{actor}");
        assert_eq!(audit.json()["items"][0]["target"]["id"], id.as_str());
    }
    pool.close().await;
}
