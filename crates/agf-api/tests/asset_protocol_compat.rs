//! Persisted protocol identifiers must render through every inventory view.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use agf_core::ids::Id;
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use common::*;

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn legacy_protocol_names_render_inventory_and_model_endpoints() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(4).connect(&url).await.unwrap();
    let database = Database::from_pool(pool);
    database.migrate().await.unwrap();
    let db = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    let tenant =
        agf_api::tenant_directory::new(format!("protocol-compat-{}", Id::new()), "Protocol compatibility".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.tenant = tenant.id;
    h.app = build_router(h.state.clone());
    let auth = format!("Bearer {}", h.admin);
    let tenant_header = h.tenant.to_string();
    let headers = [("authorization", auth.as_str()), ("x-agf-tenant", tenant_header.as_str())];
    let inserted = h
        .request_with(
            "POST",
            "/api/v1/assets/discovery",
            &headers,
            Some(json!({
                "assets": [{"kind": "model-endpoint", "name": "OpenAI compatible", "fingerprint": "protocol-compat"}]
            })),
        )
        .await;
    assert_eq!(inserted.status, StatusCode::OK, "{}", inserted.text);

    for protocol in ["openai-compat", "websocket"] {
        db.with_tenant(h.tenant, |tx| {
            Box::pin(async move {
                sqlx::query("UPDATE assets SET protocol=$1 WHERE fingerprint='protocol-compat'")
                    .bind(protocol)
                    .execute(&mut **tx)
                    .await
                    .map_err(|e| agf_storage::map_sqlx_err("fixture_protocol", &e))?;
                Ok(())
            })
        })
        .await
        .unwrap();
        for path in ["/api/v1/assets", "/api/v1/models/endpoints"] {
            let response = h.request_with("GET", path, &headers, None).await;
            assert_eq!(response.status, StatusCode::OK, "{path}: {}", response.text);
            let body = response.json();
            assert_eq!(body["total"], 1, "{path}: {body}");
            if path == "/api/v1/assets" {
                assert_eq!(body["items"][0]["protocol"], protocol, "{path}: {body}");
            } else {
                assert_eq!(body["items"][0]["model"], "OpenAI compatible", "{path}: {body}");
            }
        }
    }
}
