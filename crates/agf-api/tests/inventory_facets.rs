//! Complete inventory facets and pagination, including SQL/memory agreement.
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;
use agf_core::{
    asset::Asset,
    enums::{AssetKind, DiscoverySource, LifecycleState, Protocol},
    ids::Id,
};
use agf_storage::{AssetRepo, Database, Store, objectstore::MemoryObjectStore};
use common::*;

async fn call(h: &Harness, path: &str) -> Resp {
    h.request_with(
        "GET",
        path,
        &[("Authorization", &format!("Bearer {}", h.admin)), ("X-AGF-Tenant", &h.tenant.to_string())],
        None,
    )
    .await
}
async fn verify(h: Harness, database: Option<Arc<Store>>) {
    let mut assets = Vec::new();
    for kind in [AssetKind::Agent, AssetKind::McpServer] {
        for index in 0..55 {
            let mut row = Asset::new(
                h.tenant,
                kind,
                format!("facet-{}-{index:02}", kind.as_str()),
                format!("facet-{}-{index:02}", kind.as_str()),
            );
            row.lifecycle = LifecycleState::Trial;
            row.discovery_source = if index == 54 { DiscoverySource::Manual } else { DiscoverySource::AgentReport };
            row.last_seen_at = (index != 54).then(Timestamp::now);
            row.protocol = (kind == AssetKind::McpServer).then_some(Protocol::McpStdio);
            row.attributes = serde_json::from_value(json!({
                "flavor": if index == 54 {" LANGGRAPH "} else {"langchain"},
                "onboarding_mode": if index == 54 {" SDK_INJECT "} else {"invalid"},
                "heartbeat_interval_secs": 60,
                "transport": if index == 54 {" WEBSOCKET "} else {"invalid"},
                "active_sessions": if index == 54 {Value::Null} else {json!(index)},
                "tool_count": if index == 54 {Value::Null} else {json!(index)},
                "has_plaintext_secret": "true",
                "hasPlaintextSecret": index == 54,
                "tools": [{"name":"unobserved"},{"name":"zero","invocations_24h":0}]
            }))
            .unwrap();
            assets.push(row);
        }
    }
    if let Some(db) = &database {
        db.with_tenant(h.tenant, |tx| {
            Box::pin(async move {
                for asset in assets {
                    AssetRepo::upsert(tx, &asset).await?;
                }
                Ok(())
            })
        })
        .await
        .unwrap();
    } else {
        for asset in assets {
            h.state.store.asset_upsert(&asset).unwrap();
        }
    }
    // Read through a fresh store to ensure SQL is the source of pagination and filters.
    let mut h = h;
    if let Some(db) = database {
        h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db));
    }
    h.app = build_router(h.state.clone());
    for group in ["agents", "mcp-servers"] {
        let page = call(&h, &format!("/api/v1/{group}?page=3&page_size=20")).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.text);
        assert_eq!(page.json()["total"], 55);
        assert_eq!(page.json()["items"].as_array().unwrap().len(), 15);
        assert!(page.json()["items"][14]["name"].as_str().unwrap().ends_with("-54"));
    }
    for path in [
        "/api/v1/agents?flavor=langgraph&management=sdk-inject",
        "/api/v1/agents?observed=unknown",
        "/api/v1/mcp-servers?transport=websocket&plaintext=true&shadow=false",
        "/api/v1/mcp-servers?q=facet-mcp-server-54",
    ] {
        let result = call(&h, path).await;
        assert_eq!(result.status, StatusCode::OK, "{}", result.text);
        assert_eq!(result.json()["total"], 1, "{path}: {}", result.text);
        assert!(result.json()["items"][0]["name"].as_str().unwrap().ends_with("-54"));
    }
    assert_eq!(call(&h, "/api/v1/agents?management=unmanaged&observed=true").await.json()["total"], 54);
    assert_eq!(call(&h, "/api/v1/mcp-servers?transport=stdio&shadow=true&plaintext=false").await.json()["total"], 54);
    for (group, field) in [("agents", "active_sessions"), ("mcp-servers", "tool_count")] {
        for direction in ["", "-"] {
            let rows = call(&h, &format!("/api/v1/{group}?sort={direction}{field}&page_size=100")).await;
            assert_eq!(rows.status, StatusCode::OK, "{}", rows.text);
            assert!(rows.json()["items"][54]["name"].as_str().unwrap().ends_with("-54"));
            assert!(rows.json()["items"][0]["name"].as_str().unwrap().ends_with(if direction.is_empty() {
                "-00"
            } else {
                "-53"
            }));
        }
    }
    let mcp =
        call(&h, "/api/v1/mcp-servers?plaintext=true").await.json()["items"][0]["id"].as_str().unwrap().to_string();
    let tools = call(&h, &format!("/api/v1/mcp-servers/{mcp}/tools")).await.json();
    assert!(tools[0]["invocations24h"].is_null());
    assert_eq!(tools[1]["invocations24h"], 0);
    for path in [
        "/api/v1/agents?flavor=invalid",
        "/api/v1/agents?observed=yes",
        "/api/v1/mcps?transport=ftp",
        "/api/v1/mcps?plaintext=1",
    ] {
        assert_eq!(call(&h, path).await.status, StatusCode::BAD_REQUEST);
    }
    let other = h
        .request_with(
            "GET",
            "/api/v1/agents?management=unmanaged",
            &[("Authorization", &format!("Bearer {}", h.admin)), ("X-AGF-Tenant", &h.other_tenant.to_string())],
            None,
        )
        .await;
    assert_eq!(other.status, StatusCode::OK, "{}", other.text);
    assert_eq!(other.json()["total"], 0);
}
#[tokio::test]
async fn inventory_facets_memory() {
    verify(setup().await, None).await;
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn inventory_facets_sql() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let db = Database::from_pool(sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap());
    db.migrate().await.unwrap();
    let db = Arc::new(Store::new(db, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
    for (other, title) in [(false, "Inventory facets"), (true, "Other inventory facets")] {
        let tenant = agf_api::tenant_directory::new(format!("inventory-facets-{}", Id::new()), title.into());
        agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
        if other {
            h.other_tenant = tenant.id;
        } else {
            h.tenant = tenant.id;
        }
    }
    verify(h, Some(db)).await;
}
