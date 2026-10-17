//! Completed synthetic tasks must be visible through SQL-backed console routes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use common::*;

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn seeded_scan_and_campaign_survive_a_fresh_api_instance() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap();
    let database = Database::from_pool(pool);
    database.migrate().await.unwrap();
    let db = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.app = build_router(h.state.clone());
    let report = seed_into(&h);
    assert_eq!(report.inserted("scans"), 2);
    assert_eq!(report.inserted("redteam_campaigns"), 1);
    assert_eq!(h.state.seed_durable_demo_tasks().await.unwrap(), (1, 1));

    let mut fresh = h.clone();
    fresh.state.store = Arc::new(agf_api::store::ApiStore::with_database(db));
    fresh.app = build_router(fresh.state.clone());
    let scans = fresh.get("/api/v1/scans").await;
    assert_eq!(scans.status, StatusCode::OK, "{}", scans.text);
    assert!(scans.json()["total"].as_i64().unwrap() >= 1);
    let campaigns = fresh.get("/api/v1/redteam/campaigns").await;
    assert_eq!(campaigns.status, StatusCode::OK, "{}", campaigns.text);
    assert!(campaigns.json()["total"].as_i64().unwrap() >= 1);
    let campaign_id = campaigns.json()["items"][0]["id"].as_str().unwrap().to_owned();
    let results = fresh.get(&format!("/api/v1/redteam/campaigns/{campaign_id}/results")).await;
    assert_eq!(results.status, StatusCode::OK, "{}", results.text);
    assert!(!results.json().as_array().unwrap().is_empty());
    assert_eq!(h.state.seed_durable_demo_tasks().await.unwrap(), (0, 0));
}
