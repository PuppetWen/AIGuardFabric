//! Skill reviews must not bypass lifecycle, overwrite stale drafts or trust collector approvals.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{
    enums::{AssetKind, DiscoverySource},
    ids::Id,
};
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use common::*;

async fn call(h: &Harness, method: &str, path: &str, body: Option<Value>) -> Resp {
    h.request_with(
        method,
        path,
        &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &h.tenant.to_string())],
        body,
    )
    .await
}
async fn detail(h: &Harness, id: &str) -> Value {
    let reply = call(h, "GET", &format!("/api/v1/skills/{id}"), None).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
    reply.json()["skill"].clone()
}
async fn review(h: &Harness, skill: &Value, target: &str) -> Resp {
    call(
        h,
        "POST",
        &format!("/api/v1/skills/{}/status", skill["id"].as_str().unwrap()),
        Some(json!({"to":target,"owner":"Reviewer","data_class":"confidential",
            "note":"Ownership and data scope reviewed","expected_updated_at":skill["review"]["updatedAt"]})),
    )
    .await
}
async fn verify(h: Harness, db: Option<Arc<Store>>) {
    let response = call(
        &h,
        "POST",
        "/api/v1/assets/register",
        Some(json!({
            "request_id":Id::new(),"kind":"skill","fingerprint":"skill-review","name":"Review sample",
            "owner":"Applicant","department":"Test","data_class":"internal","note":"Validation application"
        })),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let id = response.json()["asset"]["id"].as_str().unwrap().to_string();
    let current = detail(&h, &id).await;
    assert_eq!(current["status"], "pending");
    assert_eq!(review(&h, &current, "production").await.status, StatusCode::CONFLICT);
    let reviewed = review(&h, &current, "under-review").await;
    assert_eq!(reviewed.status, StatusCode::OK, "{}", reviewed.text);
    let current = reviewed.json();
    let trial = review(&h, &current, "trial").await;
    assert_eq!(trial.status, StatusCode::OK, "{}", trial.text);
    let current = trial.json();
    assert_eq!(current["status"], "pending");
    assert!(current["decidedAt"].is_null());
    let approved = review(&h, &current, "production").await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.text);
    let approved = approved.json();
    assert_eq!(approved["status"], "approved");
    assert_eq!(approved["review"]["dataClass"], "confidential");
    assert!(approved["decidedAt"].is_string() && approved["decidedBy"].is_string());
    assert_eq!(review(&h, &current, "production").await.status, StatusCode::CONFLICT);
    let path = format!("/api/v1/skills/{id}/whitelist");
    let body = json!({"domains":["*.EXAMPLE.test","api.example.test","api.example.test"],
        "paths":[r"C:\Program Files\Tools\*", "/srv/data"],"expected_updated_at":approved["review"]["updatedAt"]});
    let (one, two) =
        tokio::join!(call(&h, "PUT", &path, Some(body.clone())), call(&h, "PUT", &path, Some(body.clone())));
    assert!(matches!(
        (one.status, two.status),
        (StatusCode::OK, StatusCode::CONFLICT) | (StatusCode::CONFLICT, StatusCode::OK)
    ));
    let saved = detail(&h, &id).await;
    assert_eq!(saved["whitelist"]["domains"], json!(["*.example.test", "api.example.test"]));
    assert_eq!(saved["decidedAt"], approved["decidedAt"]);
    for invalid in [
        json!({"domains":[]}),
        json!({"domains":["https://example.test"],"paths":[]}),
        json!({"domains":[],"paths":["../secret"]}),
        json!({"domains":[],"paths":["/srv/../secret"]}),
        json!({"domains":vec!["example.test";101],"paths":[]}),
    ] {
        assert_eq!(call(&h, "PUT", &path, Some(invalid)).await.status, StatusCode::BAD_REQUEST);
    }
    let conflict = call(
        &h,
        "POST",
        &format!("/api/v1/skills/{id}/status"),
        Some(json!({"to":"changing","status":"revoked","note":"ambiguous"})),
    )
    .await;
    assert_eq!(conflict.status, StatusCode::BAD_REQUEST);
    // An untrusted collector can neither forge the decision nor replace reviewed allowlists.
    let mut batch = agf_asset::discovery::DiscoveryBatch::new(h.tenant, DiscoverySource::AgentReport);
    let mut discovered = agf_asset::discovery::DiscoveredAsset::new(
        AssetKind::Skill,
        "Rediscovered",
        "skill-review".into(),
        DiscoverySource::AgentReport,
    );
    discovered.attributes = json!({"agf_governance":{"actor":"forged","lifecycle":"production"},
        "whitelist":{"domains":["attacker.test"],"paths":[]}});
    batch.assets.push(discovered);
    h.state.store.asset_ingest_durable(h.tenant, &batch).await.unwrap();
    let rediscovered = detail(&h, &id).await;
    assert_eq!(rediscovered["whitelist"], saved["whitelist"]);
    assert_eq!(rediscovered["decidedBy"], saved["decidedBy"]);
    let h = if let Some(db) = db {
        let mut other = h.clone();
        other.state.store = Arc::new(agf_api::store::ApiStore::with_database(db));
        other.app = build_router(other.state.clone());
        other
    } else {
        h
    };
    assert_eq!(detail(&h, &id).await, rediscovered);
    let changed = review(&h, &rediscovered, "changing").await.json();
    assert_eq!(changed["status"], "pending");
    assert!(changed["decidedAt"].is_null());
    let archived = review(&h, &changed, "archived").await.json();
    assert_eq!(archived["status"], "revoked");
    assert_eq!(review(&h, &archived, "production").await.status, StatusCode::CONFLICT);
    let denied = call(
        &h,
        "PUT",
        &path,
        Some(json!({"domains":[],"paths":[],
        "expected_updated_at":archived["review"]["updatedAt"]})),
    )
    .await;
    assert_eq!(denied.status, StatusCode::CONFLICT);
    assert_eq!(h.request("PUT", &path, Some(&h.viewer), Some(body)).await.status, StatusCode::FORBIDDEN);
    let untrusted = h
        .request_with(
            "GET",
            &format!("/api/v1/skills/{id}"),
            &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &TenantId::new().to_string())],
            None,
        )
        .await;
    assert_ne!(untrusted.status, StatusCode::OK);
}

#[tokio::test]
async fn skill_review_is_atomic_and_preserves_trusted_decisions() {
    verify(setup().await, None).await;
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn sql_skill_review_survives_another_instance() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let database =
        Database::from_pool(sqlx::postgres::PgPoolOptions::new().max_connections(6).connect(&url).await.unwrap());
    database.migrate().await.unwrap();
    let db = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
    let tenant =
        agf_api::tenant_directory::new(format!("skill-review-{}", Id::new()), "Skill review validation".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.tenant = tenant.id;
    h.app = build_router(h.state.clone());
    verify(h, Some(db)).await;
}
