//! Real isolated PostgreSQL validates alert commits, concurrent merge and complete history.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use common::*;

#[tokio::test]
#[ignore = "requires AGF_TEST_DATABASE_URL for an isolated agf_requirements_test_ database"]
async fn alerts_are_committed_and_visible_across_instances_including_closed_history() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap();
    let database = Database::from_pool(pool);
    database.migrate().await.unwrap();
    let database = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut first = setup().await;
    first.state.store = Arc::new(agf_api::store::ApiStore::with_database(database.clone()));
    let mut second = setup().await;
    second.state.store = Arc::new(agf_api::store::ApiStore::with_database(database.clone()));
    first.app = build_router(first.state.clone());
    second.app = build_router(second.state.clone());
    let title = format!("durable-alert-{}", agf_core::ids::Id::new());
    let body = json!({"title":title,"severity":"info","dedup_key":title});
    let (left, right) = tokio::join!(first.post("/api/v1/alerts", body.clone()), second.post("/api/v1/alerts", body));
    assert_eq!(left.status, StatusCode::CREATED, "{}", left.text);
    assert_eq!(right.status, StatusCode::CREATED, "{}", right.text);
    assert_eq!(left.json()["alert_id"], right.json()["alert_id"], "simultaneous creates must merge in SQL");
    let id = left.json()["alert_id"].as_str().unwrap().to_owned();
    let merged = first.post("/api/v1/alerts", json!({"title":title,"severity":"low","dedup_key":title})).await;
    assert_eq!(merged.status, StatusCode::CREATED, "{}", merged.text);
    let detail = second.get(&format!("/api/v1/alerts/{id}")).await;
    assert_eq!(detail.json()["alert"]["dedup_count"], 3);
    assert_eq!(detail.json()["alert"]["severity"], "low", "info must escalate to low severity");
    let alert_id = id.parse().unwrap();
    let due_at = Timestamp::now().offset_secs(600);
    first.state.store.alert_set_sla_durable(first.tenant, alert_id, Some(due_at), false, 2, None).await.unwrap();
    let refreshed = second.state.store.alert_get_durable(second.tenant, alert_id).await.unwrap().unwrap();
    assert_eq!(refreshed.escalation_level, 2);
    assert!((refreshed.sla_due_at.unwrap().as_datetime() - due_at.as_datetime()).num_milliseconds().abs() < 1);
    let closed =
        first.post(&format!("/api/v1/alerts/{id}/state"), json!({"state":"closed","assignee":"analyst"})).await;
    assert_eq!(closed.status, StatusCode::OK, "{}", closed.text);
    assert_eq!(second.get(&format!("/api/v1/alerts/{id}")).await.json()["alert"]["state"], "closed");
    let listed = second.get(&format!("/api/v1/alerts?q={title}&state=closed&page_size=1")).await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.text);
    assert_eq!(listed.json()["total"], 1);
    assert_eq!(listed.json()["items"][0]["id"], id);
    let active = second.get(&format!("/api/v1/alerts?q={title}&active=true")).await;
    assert_eq!(active.json()["total"], 0);
    let foreign = second
        .request_with(
            "GET",
            &format!("/api/v1/alerts/{id}"),
            &[
                ("authorization", &format!("Bearer {}", second.admin)),
                ("x-agf-tenant", &second.other_tenant.to_string()),
            ],
            None,
        )
        .await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND);

    let bad_link =
        first.post("/api/v1/alerts", json!({"title":"invalid-link", "asset_ids":[agf_core::ids::Id::new()]})).await;
    assert_eq!(bad_link.status, StatusCode::NOT_FOUND);
    database.db().pool().close().await;
    let failed_title = format!("uncommitted-{title}");
    let failed = first.post("/api/v1/alerts", json!({"title":failed_title})).await;
    assert!(failed.status.is_server_error(), "{}", failed.text);
    assert!(
        !first
            .state
            .store
            .alert_list(first.tenant, None, None)
            .unwrap()
            .iter()
            .any(|alert| alert.title == failed_title)
    );
}
