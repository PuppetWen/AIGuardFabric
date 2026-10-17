//! Missing assessments are distinct from measured zero, with tenant-scoped live finding counts.
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;
use agf_core::{
    asset::Asset,
    enums::{AssetKind, RiskDomain, Severity},
    ids::Id,
    risk::{Finding, FindingState},
};
use agf_storage::{AssetRepo, Database, Store, objectstore::MemoryObjectStore};
use common::*;

async fn call(h: &Harness, path: &str) -> Value {
    let response = h
        .request_with(
            "GET",
            path,
            &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &h.tenant.to_string())],
            None,
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    response.json()
}

async fn verify(h: Harness, db: Option<Arc<Store>>) {
    let mut unknown = Asset::new(h.tenant, AssetKind::Skill, "Unassessed", "unknown");
    unknown.exposure_score = 99; // A score cannot establish network reachability or the separate risk score.
    unknown.last_seen_at = None;
    unknown.attributes.insert("open_findings".into(), json!(99)); // Stale imported counters must not be used.
    let mut zero = Asset::new(h.tenant, AssetKind::McpServer, "Assessed zero", "zero");
    zero.risk_score = Some(0);
    zero.network_zone = Some("public".into());
    for asset in [&unknown, &zero] {
        if let Some(db) = &db {
            let asset = asset.clone();
            db.with_tenant(h.tenant, move |tx| Box::pin(async move { AssetRepo::upsert(tx, &asset).await }))
                .await
                .unwrap();
        } else {
            h.state.store.asset_upsert(asset).unwrap();
        }
    }
    let mut open_ids = Vec::new();
    for state in [
        FindingState::Pending,
        FindingState::CodeReviewed,
        FindingState::Verified,
        FindingState::Fixed,
        FindingState::FalsePositive,
    ] {
        let mut finding =
            Finding::new(h.tenant, RiskDomain::ToolAbuse, Severity::High, "fixture", "Finding", "Evidence", "Review");
        finding.asset_id = Some(unknown.id);
        finding.state = state;
        let id = h.state.store.finding_insert_durable(&finding).await.unwrap();
        if state == FindingState::Pending {
            open_ids.push(id);
        }
    }
    // This finding belongs to a different tenant even though it references the first asset ID.
    {
        let other_tenant = if db.is_some() {
            let tenant = agf_api::tenant_directory::new(
                format!("asset-count-foreign-{}", Id::new()),
                "Foreign count fixture".into(),
            );
            agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
            tenant.id
        } else {
            h.other_tenant
        };
        let mut other = Finding::new(
            other_tenant,
            RiskDomain::ToolAbuse,
            Severity::Critical,
            "fixture",
            "Foreign",
            "Evidence",
            "Review",
        );
        other.asset_id = Some(unknown.id);
        h.state.store.finding_insert_durable(&other).await.unwrap();
    }
    assert_eq!(h.state.store.platform_snapshot_durable(h.tenant).await.unwrap().findings_open, 3);
    let overview = call(&h, "/api/v1/overview").await;
    let observed =
        overview["top_risk_assets"].as_array().unwrap().iter().find(|a| a["id"] == unknown.id.to_string()).unwrap();
    assert_eq!(observed["open_findings"], 3);
    let findings = call(&h, "/api/v1/findings").await;
    assert!(
        findings["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["asset_name"] == "Unassessed" && row["can_read_asset"] == true)
    );
    let finding_path = format!("/api/v1/findings/{}", open_ids[0]);
    assert_eq!(call(&h, &finding_path).await["finding"]["asset_name"], "Unassessed");
    let projected = call(&h, "/api/v1/findings?fields=id").await;
    assert!(projected["items"].as_array().unwrap().iter().all(|row| row.as_object().unwrap().len() == 1));
    let finding_key = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("findings:read")],
        ..ApiKeyIssueRequest::named(h.tenant, "findings-only", Timestamp::now())
    });
    h.state.store.api_key_create_durable(&finding_key.record).await.unwrap();
    for uri in ["/api/v1/findings", finding_path.as_str()] {
        let response = h
            .request_with(
                "GET",
                uri,
                &[("x-agf-key", &finding_key.plaintext), ("x-agf-tenant", &h.tenant.to_string())],
                None,
            )
            .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text);
        let body = response.json();
        let row = if uri == "/api/v1/findings" { &body["items"][0] } else { &body["finding"] };
        assert!(row["asset_name"].is_null());
        assert_eq!(row["can_read_asset"], false);
    }
    for direction in ["risk_score", "-risk_score"] {
        let listed = call(&h, &format!("/api/v1/assets?sort={direction}")).await;
        assert_eq!(listed["items"][0]["id"], zero.id.to_string(), "unknown always sorts last");
        assert_eq!(listed["items"][0]["risk_score"], 0);
        assert_eq!(listed["items"][0]["exposure"], "public-internet");
        assert_eq!(listed["items"][0]["open_findings"], 0);
        assert_eq!(listed["items"][1]["exposure"], "unknown");
        assert!(listed["items"][1]["risk_score"].is_null());
        assert_eq!(listed["items"][1]["open_findings"], 3);
    }
    assert_eq!(call(&h, "/api/v1/assets?exposures=unknown").await["items"][0]["id"], unknown.id.to_string());
    assert_eq!(call(&h, "/api/v1/assets?exposures=public-internet").await["items"][0]["id"], zero.id.to_string());
    assert_eq!(call(&h, "/api/v1/assets?exposures=isolated").await["total"], 0);
    let projected = call(&h, "/api/v1/assets?exposures=unknown&fields=id,open_findings").await;
    assert_eq!(projected["items"][0].as_object().unwrap().len(), 2);
    assert_eq!(projected["items"][0]["open_findings"], 3);
    let path = format!("/api/v1/assets/{}", unknown.id);
    assert_eq!(call(&h, &path).await["asset"]["open_findings"], 3);
    h.state.store.finding_set_state_durable(h.tenant, open_ids[0], FindingState::Fixed, None, None).await.unwrap();
    assert_eq!(call(&h, &path).await["asset"]["open_findings"], 2);
    let issued = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("assets:read")],
        ..ApiKeyIssueRequest::named(h.tenant, "inventory-only", Timestamp::now())
    });
    h.state.store.api_key_create_durable(&issued.record).await.unwrap();
    let restricted = h
        .request_with(
            "GET",
            "/api/v1/overview",
            &[("x-agf-key", &issued.plaintext), ("x-agf-tenant", &h.tenant.to_string())],
            None,
        )
        .await;
    assert_eq!(restricted.status, StatusCode::OK, "{}", restricted.text);
    let overview = restricted.json();
    assert!(overview["access"].as_object().unwrap().values().all(|value| value == false));
    for key in ["risk_trend", "recent_alerts", "adapter_health"] {
        assert_eq!(overview[key], json!([]));
    }
    assert!(overview["top_risk_assets"].as_array().unwrap().iter().all(|a| a["open_findings"].is_null()));
    assert!(
        overview["domain_distribution"]
            .as_array()
            .unwrap()
            .iter()
            .all(|d| d["findings"].is_null() && d["critical"].is_null())
    );
    assert!(overview["kpis"].as_array().unwrap().iter().filter(|k| k["key"] != "assets").all(|k| k["value"].is_null()));
    for uri in ["/api/v1/assets", path.as_str()] {
        let response = h
            .request_with(
                "GET",
                uri,
                &[("x-agf-key", &issued.plaintext), ("x-agf-tenant", &h.tenant.to_string())],
                None,
            )
            .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text);
        let value = response.json();
        let row = if uri == "/api/v1/assets" { &value["items"][0] } else { &value["asset"] };
        assert!(row["open_findings"].is_null());
    }
}

#[tokio::test]
async fn offline_unknown_assessments_sort_filter_count_and_permissions() {
    verify(setup().await, None).await;
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn sql_unknown_assessments_sort_filter_count_and_permissions() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap();
    let database = Database::from_pool(pool);
    database.migrate().await.unwrap();
    let db = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
    let tenant =
        agf_api::tenant_directory::new(format!("asset-observations-{}", Id::new()), "Asset observations".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.tenant = tenant.id;
    h.app = build_router(h.state.clone());
    verify(h, Some(db)).await;
}
