//! Inventory writes must survive restart, preserve governance fields and fail atomically.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::ids::Id;
use agf_ingest::pipeline::SqlSink;
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use common::*;

async fn setup_sql() -> (Harness, Arc<Store>) {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap();
    let database = Database::from_pool(pool);
    database.migrate().await.unwrap();
    let db = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.state.ingest_sink = Arc::new(SqlSink::new(db.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
    let tenant = agf_api::tenant_directory::new(format!("asset-durability-{}", Id::new()), "Asset SQL checks".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.tenant = tenant.id;
    h.app = build_router(h.state.clone());
    (h, db)
}

async fn call(h: &Harness, method: &str, path: &str, body: Option<Value>) -> Resp {
    h.request_with(
        method,
        path,
        &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &h.tenant.to_string())],
        body,
    )
    .await
}

fn second_instance(h: &Harness, db: Arc<Store>) -> Harness {
    let mut next = h.clone();
    next.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    next.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db)));
    next.app = build_router(next.state.clone());
    next
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn discovery_commit_cross_instance_governance_and_failure_rollback() {
    let (h, db) = setup_sql().await;
    let h2 = second_instance(&h, db.clone());
    let body = json!({"assets":[{"kind":"mcp-server","name":"Operations MCP","fingerprint":"sql-mcp","endpoint":"stdio:fixture","version":"1","exposure_score":88},
        {"kind":"skill","name":"Report skill","fingerprint":"sql-skill","exposure_score":40},
        {"kind":"agent","name":"Offline Agent","fingerprint":"sql-agent","exposure_score":0}]});
    let (a, b) = tokio::join!(
        call(&h, "POST", "/api/v1/assets/discovery", Some(body.clone())),
        call(&h2, "POST", "/api/v1/assets/discovery", Some(body.clone()))
    );
    assert_eq!(a.status, StatusCode::OK, "{}", a.text);
    assert_eq!(b.status, StatusCode::OK, "{}", b.text);
    assert_eq!(a.json()["stats"]["created"].as_u64().unwrap() + b.json()["stats"]["created"].as_u64().unwrap(), 3);
    // Assessment/network metadata are explicit fixture facts, never inferred from exposure points.
    db.with_tenant(h.tenant, |tx| Box::pin(async move {
        sqlx::query("UPDATE assets SET risk_score=exposure_score,network_zone=CASE WHEN fingerprint='sql-mcp' THEN 'public' ELSE NULL END")
            .execute(&mut **tx).await.map_err(|e|agf_storage::map_sqlx_err("fixture_asset_assessment",&e))?;
        Ok(())
    })).await.unwrap();
    let listed = call(&h2, "GET", "/api/v1/assets?sort=-risk_score&page_size=1", None).await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.text);
    assert_eq!(listed.json()["total"], 3);
    let id = listed.json()["items"][0]["id"].as_str().unwrap().to_owned();
    assert_eq!(listed.json()["items"][0]["name"], "Operations MCP");
    let asset_uri = format!("/api/v1/assets/{id}");
    let initial = call(&h2, "GET", &asset_uri, None).await.json();
    assert_eq!(initial["changes"].as_array().unwrap().len(), 1);
    let transitioned=call(&h2,"POST",&format!("{asset_uri}/transition"),Some(json!({"to":"production","actor":"spoofed actor","owner":"alice","department":"Security Ops","data_class":"confidential","note":"Reviewed"}))).await;
    assert_eq!(transitioned.status, StatusCode::OK, "{}", transitioned.text);
    let detail = call(&h, "GET", &asset_uri, None).await.json();
    assert_eq!(detail["asset"]["lifecycle"], "production");
    assert!(!detail["changes"][0]["risk_note"].as_str().unwrap().contains("spoofed actor"));
    let mut changed = body;
    changed["assets"][0]["version"] = json!("2");
    assert_eq!(call(&h, "POST", "/api/v1/assets/discovery", Some(changed)).await.status, StatusCode::OK);
    let detail = call(&h2, "GET", &asset_uri, None).await.json();
    assert_eq!(detail["asset"]["lifecycle"], "production");
    assert_eq!(detail["asset"]["owner"], "alice");
    assert_eq!(detail["asset"]["data_class"], "confidential");
    assert_eq!(detail["asset"]["version"], "2");
    let stale = call(
        &h2,
        "POST",
        &format!("{asset_uri}/transition"),
        Some(json!({"to":"changing",
        "expected_updated_at":initial["governance"]["updated_at"],"note":"stale form"})),
    )
    .await;
    assert_eq!(stale.status, StatusCode::CONFLICT, "{}", stale.text);
    assert_eq!(call(&h, "GET", &asset_uri, None).await.json()["governance"]["lifecycle"], "production");
    let (other, _) = setup_sql().await;
    let duplicate = call(
        &other,
        "POST",
        "/api/v1/assets/discovery",
        Some(json!({"assets":[
        {"kind":"mcp-server","name":"Other organization","fingerprint":"sql-mcp"}]})),
    )
    .await;
    assert_eq!(duplicate.status, StatusCode::OK, "{}", duplicate.text);
    assert_ne!(call(&other, "GET", "/api/v1/assets", None).await.json()["items"][0]["id"], id);
    assert_eq!(call(&other, "GET", &asset_uri, None).await.status, StatusCode::NOT_FOUND);
    for uri in [
        "/api/v1/assets?lifecycles=active&page_size=1",
        "/api/v1/assets?classifications=confidential&departments=Security%20Ops&exposures=public-internet",
        "/api/v1/assets?q=alice",
    ] {
        let result = call(&h, "GET", uri, None).await;
        assert_eq!(result.status, StatusCode::OK, "{}", result.text);
        assert_eq!(result.json()["total"], 1);
        assert_eq!(result.json()["items"][0]["id"], id);
    }
    assert_eq!(call(&h, "GET", "/api/v1/assets?kinds=mcp,skill", None).await.json()["total"], 2);
    assert_eq!(call(&h, "GET", "/api/v1/assets?lifecycles=retired&page=2&page_size=1", None).await.json()["total"], 0);
    assert_eq!(call(&h, "GET", "/api/v1/assets?departments=Unknown", None).await.json()["total"], 0);
    assert_eq!(call(&h, "GET", "/api/v1/assets?exposures=invalid", None).await.status, StatusCode::BAD_REQUEST);
    let broken = call(
        &h,
        "POST",
        "/api/v1/assets/discovery",
        Some(json!({"assets":[
        {"kind":"agent","name":"Must roll back","fingerprint":"rollback-first"},
        {"kind":"agent","name":"Invalid SQL string\u{0000}","fingerprint":"rollback-second"}]})),
    )
    .await;
    assert!(broken.status.is_server_error(), "{}", broken.text);
    assert_eq!(call(&h2, "GET", "/api/v1/assets?q=rollback", None).await.json()["total"], 0);
    assert_eq!(h.state.store.asset_list_all(h.tenant).unwrap().len(), 3);
    let restored = second_instance(&h, db.clone());
    let stats = call(&restored, "GET", "/api/v1/assets/stats", None).await;
    assert_eq!(stats.status, StatusCode::OK, "{}", stats.text);
    assert_eq!(stats.json()["inventory"]["total"], 3);
    assert_eq!(stats.json()["platform"]["assets_production"], 1);
    assert_eq!(stats.json()["platform"]["shadow_mcps"], 0);
    assert_eq!(call(&restored, "GET", "/api/v1/search?q=Operations", None).await.json()[0]["id"], id);
    assert_eq!(call(&restored, "GET", "/api/v1/topology", None).await.json()["nodes"].as_array().unwrap().len(), 3);
    let overview = call(&restored, "GET", "/api/v1/overview", None).await.json();
    assert_eq!(overview["kpis"].as_array().unwrap().iter().find(|k| k["key"] == "assets").unwrap()["value"], 3.0);
    let graphql = call(
        &restored,
        "POST",
        "/graphql",
        Some(json!({"query":"{ assets { id name } platformStats { assets assetsProduction } }"})),
    )
    .await
    .json();
    assert!(graphql.get("errors").is_none(), "{graphql}");
    assert_eq!(graphql["data"]["assets"].as_array().unwrap().len(), 3);
    assert_eq!(graphql["data"]["platformStats"]["assetsProduction"], 1);
    let history = restored
        .state
        .store
        .asset_changes_in_range(h.tenant, &agf_core::time::TimeRange::last_secs(3600))
        .await
        .unwrap();
    assert!(history.len() >= 5);
    assert_eq!(call(&restored, "GET", "/api/v1/mcps", None).await.json()["total"], 1);
    assert_eq!(call(&restored, "GET", "/api/v1/agents", None).await.json()["total"], 1);
    assert_eq!(call(&restored, "GET", &asset_uri, None).await.json()["asset"]["lifecycle"], "production");
    // First-observation snapshots retain the original version/lifecycle despite repeated discovery.
    db.with_tenant(h.tenant, |tx| {
        Box::pin(async move {
            sqlx::query("UPDATE asset_snapshots SET snapshot_date='2020-02-02'::date")
                .execute(&mut **tx)
                .await
                .map_err(|e| agf_storage::map_sqlx_err("test_asset_baseline", &e))?;
            Ok(())
        })
    })
    .await
    .unwrap();
    let drift = call(&h2, "POST", "/api/v1/assets/drift", Some(json!({"baseline_date":"2020-02-02"}))).await;
    assert_eq!(drift.status, StatusCode::OK, "{}", drift.text);
    assert_eq!(drift.json()["report"]["summary"]["modified"], 1, "{}", drift.text);
    let repeat = call(&restored, "POST", "/api/v1/assets/drift", Some(json!({"baseline_date":"2020-02-02"}))).await;
    assert_eq!(repeat.json()["report"]["changes"][0]["id"], drift.json()["report"]["changes"][0]["id"]);
    let after = restored
        .state
        .store
        .asset_changes_in_range(h.tenant, &agf_core::time::TimeRange::last_secs(3600))
        .await
        .unwrap();
    assert_eq!(after.len(), history.len(), "Comparisons must not duplicate discovery/lifecycle events");
    for date in ["invalid", "9999-01-01", "2026-02-30"] {
        assert_eq!(
            call(&restored, "POST", "/api/v1/assets/drift", Some(json!({"baseline_date":date}))).await.status,
            StatusCode::BAD_REQUEST
        );
    }
    let reader = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("assets:read")],
        ..ApiKeyIssueRequest::named(h.tenant, "asset-reader", Timestamp::now())
    });
    h.state.store.api_key_create_durable(&reader.record).await.unwrap();
    assert_eq!(
        h.request_with("POST", "/api/v1/assets/drift", &[("x-agf-key", &reader.plaintext)], Some(json!({})))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        h.request_with(
            "GET",
            &asset_uri,
            &[("x-agf-key", &reader.plaintext), ("x-agf-tenant", &TenantId::default_tenant().to_string())],
            None
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn mcp_registry_and_inventory_projection_share_version_and_rollback() {
    let (h, db) = setup_sql().await;
    let h2 = second_instance(&h, db.clone());
    let input = json!({"expected_version":0,"name":"Atomic MCP","url":"http://127.0.0.1:1/mcp",
        "enabled":true,"idle_timeout_secs":5,"bearer_token":"fixture-secret"});
    let created = call(&h, "POST", "/api/v1/mcp/endpoints", Some(input.clone())).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    let id = created.json()["id"].as_str().unwrap().to_string();
    let mut update = input.clone();
    update["id"] = json!(id);
    update["expected_version"] = json!(1);
    update["name"] = json!("Renamed MCP");
    update["enabled"] = json!(false);
    let (a, b) = tokio::join!(
        call(&h, "POST", "/api/v1/mcp/endpoints", Some(update.clone())),
        call(&h2, "POST", "/api/v1/mcp/endpoints", Some(update.clone()))
    );
    assert_eq!([a.status, b.status].iter().filter(|status| **status == StatusCode::OK).count(), 1);
    assert_eq!([a.status, b.status].iter().filter(|status| **status == StatusCode::CONFLICT).count(), 1);
    let restored = second_instance(&h, db);
    let uri = format!("/api/v1/assets/{id}");
    let asset = call(&restored, "GET", &uri, None).await.json();
    assert_eq!(asset["asset"]["name"], "Renamed MCP");
    assert_eq!(asset["asset"]["attributes"]["enabled"], false);
    assert_eq!(
        call(&restored, "GET", "/api/v1/assets/stats", None).await.json()["inventory"]["with_plaintext_secret"],
        0
    );
    let mut invalid = update;
    invalid["name"] = json!("Fail\u{0000}");
    invalid["expected_version"] = json!(2);
    let rejected = call(&h, "POST", "/api/v1/mcp/endpoints", Some(invalid)).await;
    assert!(rejected.status.is_server_error(), "{}", rejected.text);
    let registry = call(&restored, "GET", "/api/v1/mcp/endpoints", None).await.json();
    assert_eq!(registry["items"][0]["version"], 2);
    assert_eq!(registry["items"][0]["name"], "Renamed MCP");
    assert_eq!(call(&restored, "GET", &uri, None).await.json()["asset"]["name"], "Renamed MCP");
    // A bound API key resolves an Agent created by a different process and rejects a deleted Agent.
    let added = call(
        &h,
        "POST",
        "/api/v1/assets/discovery",
        Some(json!({"assets":[{"kind":"agent","name":"Bound Agent","fingerprint":"bound-agent"}]})),
    )
    .await;
    assert_eq!(added.status, StatusCode::OK, "{}", added.text);
    let agents = call(&h, "GET", "/api/v1/agents", None).await.json();
    let agent_id = Id::parse(agents["items"][0]["id"].as_str().unwrap()).unwrap();
    let issued = h.state.api_keys.issue(ApiKeyIssueRequest {
        bound_agent_id: Some(agent_id),
        scopes: vec![Permission::from_raw("assets:read")],
        ..ApiKeyIssueRequest::named(h.tenant, "bound-inventory", Timestamp::now())
    });
    h.state.store.api_key_create_durable(&issued.record).await.unwrap();
    assert_eq!(
        restored.request_with("GET", "/api/v1/assets", &[("x-agf-key", &issued.plaintext)], None).await.status,
        StatusCode::OK
    );
    h.state
        .store
        .database()
        .unwrap()
        .with_tenant(h.tenant, move |tx| {
            Box::pin(async move {
                sqlx::query("UPDATE assets SET deleted_at=now() WHERE id=$1")
                    .bind(agent_id.as_uuid())
                    .execute(&mut **tx)
                    .await
                    .map_err(|e| agf_storage::map_sqlx_err("delete_fixture_agent", &e))?;
                Ok(())
            })
        })
        .await
        .unwrap();
    assert_eq!(
        restored.request_with("GET", "/api/v1/assets", &[("x-agf-key", &issued.plaintext)], None).await.status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn concurrent_skill_fields_and_model_projection_commit_together() {
    let (h, db) = setup_sql().await;
    let h2 = second_instance(&h, db.clone());
    let created = call(
        &h,
        "POST",
        "/api/v1/assets/discovery",
        Some(json!({"assets":[{"kind":"skill","name":"Governed skill","fingerprint":"governed-skill"}]})),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    let id = call(&h2, "GET", "/api/v1/skills", None).await.json()["items"][0]["id"].as_str().unwrap().to_owned();
    let status_uri = format!("/api/v1/skills/{id}/status");
    let whitelist_uri = format!("/api/v1/skills/{id}/whitelist");
    let (status, whitelist) = tokio::join!(
        call(
            &h,
            "POST",
            &status_uri,
            Some(json!({"status":"approved","owner":"Reviewer",
            "data_class":"internal","note":"Ownership and scope reviewed"}))
        ),
        call(&h2, "PUT", &whitelist_uri, Some(json!({"domains":["approved.example"],"paths":["/safe"]})))
    );
    assert_eq!(status.status, StatusCode::OK, "{}", status.text);
    assert_eq!(whitelist.status, StatusCode::OK, "{}", whitelist.text);
    let restored = second_instance(&h, db.clone());
    let asset = call(&restored, "GET", &format!("/api/v1/assets/{id}"), None).await.json();
    assert_eq!(asset["asset"]["lifecycle"], "production");
    assert_eq!(asset["asset"]["attributes"]["whitelist"]["domains"], json!(["approved.example"]));
    assert_eq!(asset["changes"].as_array().unwrap().len(), 3);
    let model=call(&h,"POST","/api/v1/gateway/endpoints",Some(json!({"name":"Atomic model","provider":"mock","model":"offline","base_url":"http://mock.invalid/v1","local_deployment":true}))).await;
    assert_eq!(model.status, StatusCode::CREATED, "{}", model.text);
    let model_id = model.json()["id"].as_str().unwrap().to_owned();
    assert_eq!(call(&h2, "GET", "/api/v1/models/endpoints", None).await.json()["total"], 1);
    let invalid=call(&h,"POST","/api/v1/gateway/endpoints",Some(json!({"name":"Must roll back\u{0000}","provider":"mock","model":"offline","base_url":"http://mock.invalid"}))).await;
    assert!(invalid.status.is_server_error(), "{}", invalid.text);
    assert_eq!(call(&h2, "GET", "/api/v1/gateway/endpoints", None).await.json()["items"].as_array().unwrap().len(), 1);
    assert_eq!(call(&h2, "GET", "/api/v1/assets?kinds=model", None).await.json()["total"], 1);
    assert_eq!(
        call(
            &h2,
            "DELETE",
            &format!("/api/v1/gateway/endpoints/{model_id}?expected_version={}", model.json()["version"]),
            None
        )
        .await
        .status,
        StatusCode::OK
    );
    assert_eq!(call(&h, "GET", "/api/v1/gateway/endpoints", None).await.json()["items"], json!([]));
    assert_eq!(
        call(&h, "GET", &format!("/api/v1/assets/{model_id}"), None).await.json()["asset"]["attributes"]["enabled"],
        false
    );
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn model_endpoint_versions_prevent_cross_instance_overwrite() {
    let (h, db) = setup_sql().await;
    let h2 = second_instance(&h, db);
    let created = call(
        &h,
        "POST",
        "/api/v1/gateway/endpoints",
        Some(json!({
            "name":"initial","provider":"mock","model":"offline","base_url":"http://mock.invalid/v1"
        })),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    let id = created.json()["id"].as_str().unwrap().to_string();
    let uri = format!("/api/v1/gateway/endpoints/{id}");
    let edit = |name: &str| {
        json!({"name":name,"provider":"mock","model":"offline",
        "base_url":"http://mock.invalid/v1","expected_version":1})
    };
    let (first, second) =
        tokio::join!(call(&h, "PUT", &uri, Some(edit("first"))), call(&h2, "PUT", &uri, Some(edit("second"))));
    assert_eq!(u8::from(first.status == StatusCode::OK) + u8::from(second.status == StatusCode::OK), 1);
    assert_eq!(u8::from(first.status == StatusCode::CONFLICT) + u8::from(second.status == StatusCode::CONFLICT), 1);
    let listed = call(&h2, "GET", "/api/v1/gateway/endpoints", None).await.json();
    assert_eq!(listed["items"][0]["version"], 2);
    let winner = listed["items"][0]["name"].as_str().unwrap();
    assert!(winner == "first" || winner == "second");
    let asset = call(&h, "GET", &format!("/api/v1/assets/{id}"), None).await.json();
    assert_eq!(asset["asset"]["name"], winner);
    assert_eq!(call(&h, "DELETE", &format!("{uri}?expected_version=1"), None).await.status, StatusCode::CONFLICT);
    assert_eq!(call(&h2, "DELETE", &format!("{uri}?expected_version=2"), None).await.status, StatusCode::OK);
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn model_route_versions_prevent_cross_instance_overwrite() {
    let (h, db) = setup_sql().await;
    let h2 = second_instance(&h, db);
    let endpoint = call(
        &h,
        "POST",
        "/api/v1/gateway/endpoints",
        Some(json!({
            "name":"route target","provider":"mock","model":"offline","base_url":"http://mock.invalid/v1"
        })),
    )
    .await;
    assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
    let created = call(
        &h,
        "POST",
        "/api/v1/models/route-policies",
        Some(json!({
            "name":"initial route","primaryEndpointId":endpoint.json()["id"],"enabled":true
        })),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    let id = created.json()["id"].as_str().unwrap().to_string();
    assert_eq!(created.json()["version"], 1);
    let uri = format!("/api/v1/models/route-policies/{id}");
    let (first, second) = tokio::join!(
        call(&h, "PUT", &uri, Some(json!({"expectedVersion":1,"name":"first route"}))),
        call(&h2, "PUT", &uri, Some(json!({"expectedVersion":1,"name":"second route"}))),
    );
    assert_eq!(u8::from(first.status == StatusCode::OK) + u8::from(second.status == StatusCode::OK), 1);
    assert_eq!(u8::from(first.status == StatusCode::CONFLICT) + u8::from(second.status == StatusCode::CONFLICT), 1);
    let listed = call(&h2, "GET", "/api/v1/models/route-policies", None).await.json();
    let row = listed.as_array().unwrap().iter().find(|item| item["id"] == id).unwrap();
    assert_eq!(row["version"], 2);
    assert!(row["name"] == "first route" || row["name"] == "second route");
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn gateway_quota_versions_prevent_cross_instance_overwrite() {
    let (h, db) = setup_sql().await;
    let h2 = second_instance(&h, db);
    let uri = "/api/v1/settings/quotas";
    let body = |version: u64, amount: u64| {
        json!({"expectedVersion":version,
        "tenantTokensPerDay":amount,"agentTokensPerHour":0,
        "sessionTokensPerTurn":100,"maxConcurrentSessions":2})
    };
    let created = call(&h, "PUT", uri, Some(body(0, 1000))).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    assert_eq!(created.json()["version"], 1);
    let (first, second) =
        tokio::join!(call(&h, "PUT", uri, Some(body(1, 2000))), call(&h2, "PUT", uri, Some(body(1, 3000))),);
    assert_eq!(u8::from(first.status == StatusCode::OK) + u8::from(second.status == StatusCode::OK), 1);
    assert_eq!(u8::from(first.status == StatusCode::CONFLICT) + u8::from(second.status == StatusCode::CONFLICT), 1);
    let current = agf_api::gateway_quota::limits(&h2.state, h.tenant).await.unwrap();
    assert_eq!(current.version, 2);
    assert!(current.tenant_tokens_per_day == 2000 || current.tenant_tokens_per_day == 3000);
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn tenant_profile_versions_prevent_cross_instance_overwrite() {
    let (h, db) = setup_sql().await;
    let h2 = second_instance(&h, db);
    let uri = "/api/v1/settings/tenant";
    let body = |version: u64, name: &str| {
        json!({"expectedVersion":version,
        "name":name,"plan":"enterprise","region":"local",
        "whiteLabel":{"productName":"AGF","logoText":"AGF","primaryColor":"#123abc"}})
    };
    let created = call(&h, "PUT", uri, Some(body(0, "initial"))).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    assert_eq!(created.json()["version"], 1);
    let (first, second) = tokio::join!(
        call(&h, "PUT", uri, Some(body(1, "first name"))),
        call(&h2, "PUT", uri, Some(body(1, "second name"))),
    );
    assert_eq!(u8::from(first.status == StatusCode::OK) + u8::from(second.status == StatusCode::OK), 1);
    assert_eq!(u8::from(first.status == StatusCode::CONFLICT) + u8::from(second.status == StatusCode::CONFLICT), 1);
    let saved: Value = h2
        .state
        .configurations
        .get(h.tenant, "tenant-profile", agf_api::model_routes::tenant_record_id(h.tenant))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(saved["version"], 2);
    assert!(saved["name"] == "first name" || saved["name"] == "second name");
}
