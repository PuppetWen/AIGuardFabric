//! Applications and daily immutable baselines, including restart and concurrent workers.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::asset_inventory::daily::run_for_date;
use agf_core::{ids::Id, time::Date};
use agf_storage::{AuditRepo, Database, Store, objectstore::MemoryObjectStore};
use common::*;

fn application() -> Value {
    json!({"request_id":Id::new(),"fingerprint":"reviewed-skill","kind":"skill","name":"Finance review",
        "owner":"alice","department":"Finance","data_class":"confidential","note":"Application for expense checks\nApproved data sources only",
        "endpoint":"stdio:finance","version":"1"})
}

#[tokio::test]
async fn terminal_asset_removal_requires_review_version_and_name_then_can_be_rediscovered() {
    let h = setup().await;
    let created = h.post("/api/v1/assets/register", application()).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    let id = created.json()["asset"]["id"].as_str().unwrap().to_owned();
    let path = format!("/api/v1/assets/{id}");
    let before = h.get(&path).await.json();
    let original = before["governance"]["updated_at"].as_str().unwrap();
    let body =
        json!({"expected_updated_at":original,"confirm_name":"Finance review","reason":"Retired inventory entry"});
    assert_eq!(h.request("DELETE", &path, Some(&h.viewer), Some(body.clone())).await.status, StatusCode::FORBIDDEN);
    assert_eq!(
        h.request("DELETE", &path, Some(&h.admin), Some(body.clone())).await.status,
        StatusCode::PRECONDITION_FAILED
    );
    let rejected = h
        .post(
            &format!("{path}/transition"),
            json!({"to":"rejected","note":"Application withdrawn","expected_updated_at":original}),
        )
        .await;
    assert_eq!(rejected.status, StatusCode::OK, "{}", rejected.text);
    let latest = h.get(&path).await.json();
    let version = latest["governance"]["updated_at"].as_str().unwrap();
    let mut stale = body.clone();
    stale["expected_updated_at"] = json!(original);
    assert_eq!(h.request("DELETE", &path, Some(&h.admin), Some(stale)).await.status, StatusCode::CONFLICT);
    let mut wrong = body.clone();
    wrong["expected_updated_at"] = json!(version);
    wrong["confirm_name"] = json!("Wrong asset");
    assert_eq!(h.request("DELETE", &path, Some(&h.admin), Some(wrong)).await.status, StatusCode::BAD_REQUEST);
    let removed = h
        .request(
            "DELETE",
            &path,
            Some(&h.admin),
            Some(json!({
                "expected_updated_at":version,"confirm_name":"Finance review","reason":"Retired inventory entry"
            })),
        )
        .await;
    assert_eq!(removed.status, StatusCode::OK, "{}", removed.text);
    assert_eq!(h.get(&path).await.status, StatusCode::NOT_FOUND);
    assert_eq!(h.get("/api/v1/assets").await.json()["total"], 0);
    assert_eq!(h.request("DELETE", &path, Some(&h.admin), Some(body)).await.status, StatusCode::NOT_FOUND);
    let observed = h
        .post(
            "/api/v1/assets/discovery",
            json!({"assets":[{
                "kind":"skill","name":"Finance review","fingerprint":"reviewed-skill"
            }]}),
        )
        .await;
    assert_eq!(observed.status, StatusCode::OK, "{}", observed.text);
    let returned = h.get(&path).await.json();
    assert_eq!(returned["asset"]["id"], id);
    assert!(returned["changes"].as_array().unwrap().iter().any(|change| change["change_kind"] == "removed"));
}

#[tokio::test]
async fn manual_application_validation_permissions_and_idempotency() {
    let h = setup().await;
    let body = application();
    let response = h.post("/api/v1/assets/register", body.clone()).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let id = response.json()["asset"]["id"].as_str().unwrap().to_string();
    assert_eq!(response.json()["asset"]["lifecycle"], "requested");
    assert!(response.json()["asset"]["last_seen_at"].is_null());
    assert_eq!(h.post("/api/v1/assets/register", body.clone()).await.json()["asset"]["id"], id);
    let detail = h.get(&format!("/api/v1/assets/{id}")).await.json();
    assert_eq!(detail["changes"].as_array().unwrap().len(), 1);
    assert_eq!(detail["governance"]["allowed_next"], json!(["under-review", "rejected"]));
    let mut duplicate = body.clone();
    duplicate["request_id"] = json!(Id::new());
    assert_eq!(h.post("/api/v1/assets/register", duplicate).await.status, StatusCode::CONFLICT);
    for patch in [
        json!({"name":" "}),
        json!({"owner":""}),
        json!({"endpoint":"https://a:secret@example.test"}),
        json!({"endpoint":"https://example.test?key=secret"}),
        json!({"kind":"unknown"}),
        json!({"data_class":"secret"}),
    ] {
        let mut invalid = body.clone();
        invalid.as_object_mut().unwrap().extend(patch.as_object().unwrap().clone());
        assert_eq!(h.post("/api/v1/assets/register", invalid).await.status, StatusCode::BAD_REQUEST);
    }
    assert_eq!(
        h.request("POST", "/api/v1/assets/register", Some(&h.viewer), Some(body)).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(h.get("/api/v1/assets/inventory").await.json()["automatic_enabled"], false);
    assert_eq!(h.post("/api/v1/assets/inventory", json!({})).await.status, StatusCode::PRECONDITION_FAILED);
    let spec = h.get("/openapi.json").await.json();
    assert!(spec["paths"]["/api/v1/assets/register"]["post"]["requestBody"].is_object());
}

#[tokio::test]
async fn asset_metadata_edit_requires_current_revision_and_preserves_identity() {
    let h = setup().await;
    let registered = h.post("/api/v1/assets/register", application()).await;
    assert_eq!(registered.status, StatusCode::OK, "{}", registered.text);
    let id = registered.json()["asset"]["id"].as_str().unwrap().to_owned();
    let path = format!("/api/v1/assets/{id}");
    let initial = h.get(&path).await.json();
    let revision = initial["governance"]["updated_at"].as_str().unwrap().to_owned();
    let edit = json!({"name":"Finance review v2","owner":"bob","department":"",
        "data_class":"restricted","expected_updated_at":revision,"reason":"Ownership review"});
    assert_eq!(h.request("PATCH", &path, Some(&h.viewer), Some(edit.clone())).await.status, StatusCode::FORBIDDEN);
    assert_eq!(
        h.request("PATCH", &format!("/api/v1/assets/{}", Id::new()), Some(&h.admin), Some(edit.clone())).await.status,
        StatusCode::NOT_FOUND
    );
    let mut invalid = edit.clone();
    invalid["owner"] = json!(" ");
    assert_eq!(h.request("PATCH", &path, Some(&h.admin), Some(invalid)).await.status, StatusCode::BAD_REQUEST);
    let saved = h.request("PATCH", &path, Some(&h.admin), Some(edit.clone())).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.json()["asset"]["id"], id);
    assert_eq!(saved.json()["asset"]["fingerprint"], "reviewed-skill");
    assert_eq!(saved.json()["asset"]["name"], "Finance review v2");
    assert_eq!(saved.json()["asset"]["data_class"], "restricted");
    assert_eq!(h.request("PATCH", &path, Some(&h.admin), Some(edit)).await.status, StatusCode::CONFLICT);
    let detail = h.get(&path).await.json();
    assert_eq!(detail["changes"].as_array().unwrap().len(), 2);
    assert!(detail["changes"].as_array().unwrap().iter().any(|change| change["field"] == "metadata"));
    assert_eq!(
        h.get("/openapi.json").await.json()["paths"]["/api/v1/assets/{id}"]["patch"]["operationId"],
        "updateAssetMetadata"
    );
}

async fn setup_sql() -> (Harness, Arc<Store>) {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let database =
        Database::from_pool(sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap());
    database.migrate().await.unwrap();
    let db = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::ApiStore::with_database(db.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
    let tenant =
        agf_api::tenant_directory::new(format!("daily-inventory-{}", Id::new()), "Daily inventory checks".into());
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
fn second(h: &Harness, db: Arc<Store>) -> Harness {
    let mut next = h.clone();
    next.state.store = Arc::new(agf_api::ApiStore::with_database(db));
    next.app = build_router(next.state.clone());
    next
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn asset_governance_and_success_audit_roll_back_together() {
    let (h, db) = setup_sql().await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&std::env::var("AGF_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let created = call(&h, "POST", "/api/v1/assets/register", Some(application())).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    let id = created.json()["asset"]["id"].as_str().unwrap().to_owned();
    let path = format!("/api/v1/assets/{id}");
    let before = call(&h, "GET", &path, None).await.json();
    let revision = before["governance"]["updated_at"].as_str().unwrap();
    let edit = json!({"name":"Reviewed name","owner":"bob","department":"Security",
        "data_class":"restricted","expected_updated_at":revision,"reason":"Annual ownership review"});
    let mut credential = application();
    credential["request_id"] = json!(Id::new());
    credential["fingerprint"] = json!("reviewed-credential");
    credential["kind"] = json!("credential");
    let registered_credential = call(&h, "POST", "/api/v1/assets/register", Some(credential)).await;
    assert_eq!(registered_credential.status, StatusCode::OK, "{}", registered_credential.text);
    let credential_id = registered_credential.json()["asset"]["id"].as_str().unwrap().to_owned();
    let credential_path = format!("/api/v1/assets/{credential_id}");
    let credential_before = call(&h, "GET", &credential_path, None).await.json();
    let credential_revision = credential_before["governance"]["updated_at"].as_str().unwrap();
    let mut tx = db.db().begin_tenant(h.tenant).await.unwrap();
    let chain = AuditRepo::chain_stats(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    let constraint = format!("agf_test_asset_audit_{}", Id::new().as_uuid().simple());
    sqlx::query(&format!(
        "ALTER TABLE audit_logs ADD CONSTRAINT {constraint} CHECK (tenant_id <> '{}'::uuid) NOT VALID",
        h.tenant
    ))
    .execute(&pool)
    .await
    .unwrap();
    let mut new_registration = application();
    new_registration["request_id"] = json!(Id::new());
    new_registration["fingerprint"] = json!("should-not-appear");
    for (method, target, body) in [
        ("POST", "/api/v1/assets/register".to_owned(), new_registration),
        (
            "POST",
            "/api/v1/assets/discovery".to_owned(),
            json!({"assets":[
                {"kind":"agent","name":"Should roll back","fingerprint":"discovery-rollback-test"}
            ]}),
        ),
        ("PATCH", path.clone(), edit.clone()),
        (
            "POST",
            format!("{path}/transition"),
            json!({"to":"under-review","note":"Reviewed owner","expected_updated_at":revision}),
        ),
        (
            "PUT",
            format!("{path}/edr-host"),
            json!({"host_id":"host-123","reason":"Reviewed host","expected_updated_at":revision}),
        ),
        (
            "PUT",
            format!("{credential_path}/scim-user"),
            json!({"user_id":"user-123","reason":"Reviewed identity","expected_updated_at":credential_revision}),
        ),
    ] {
        let failed = call(&h, method, &target, Some(body)).await;
        assert!(failed.status.is_server_error(), "{method} {target}: {}", failed.text);
        let other = second(&h, db.clone());
        let unchanged = call(&other, "GET", &path, None).await.json();
        assert_eq!(unchanged["asset"], before["asset"], "{method} {target} changed the asset");
        assert_eq!(unchanged["changes"], before["changes"]);
        let credential_now = call(&other, "GET", &credential_path, None).await.json();
        assert_eq!(credential_now["asset"], credential_before["asset"]);
        assert_eq!(credential_now["changes"], credential_before["changes"]);
        assert_eq!(call(&other, "GET", "/api/v1/assets", None).await.json()["total"], 2);
        let mut tx = db.db().begin_tenant(h.tenant).await.unwrap();
        assert_eq!(AuditRepo::chain_stats(&mut tx).await.unwrap(), chain);
        tx.commit().await.unwrap();
    }
    sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}")).execute(&pool).await.unwrap();
    let saved = call(&h, "PATCH", &path, Some(edit)).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let from_other = call(&second(&h, db), "GET", &path, None).await.json();
    assert_eq!(from_other["asset"]["name"], "Reviewed name");
    assert_eq!(from_other["changes"].as_array().unwrap().len(), 2);
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn immutable_daily_inventory_catches_skill_hash_endpoint_change_and_new_mcp() {
    let (h, db) = setup_sql().await;
    let other = second(&h, db.clone());
    let body = application();
    let (a, b) = tokio::join!(
        call(&h, "POST", "/api/v1/assets/register", Some(body.clone())),
        call(&other, "POST", "/api/v1/assets/register", Some(body.clone()))
    );
    assert_eq!(a.status, StatusCode::OK, "{}", a.text);
    assert_eq!(b.status, StatusCode::OK, "{}", b.text);
    let id = a.json()["asset"]["id"].as_str().unwrap().to_string();
    assert_eq!(a.json()["asset"]["id"], b.json()["asset"]["id"]);
    let persisted = call(&other, "GET", &format!("/api/v1/assets/{id}"), None).await.json();
    assert!(persisted["asset"]["last_seen_at"].is_null(), "Registration must not invent observed activity");
    assert_eq!(call(&h, "POST", "/api/v1/assets/register", Some(body)).await.status, StatusCode::OK);
    let retried = call(&other, "GET", &format!("/api/v1/assets/{id}"), None).await.json();
    assert_eq!(persisted["governance"]["updated_at"], retried["governance"]["updated_at"]);
    let observed = json!({"assets":[{"kind":"skill","name":"Finance review","fingerprint":"reviewed-skill","content_sha256":"a".repeat(64)},
        {"kind":"model-endpoint","name":"Model","fingerprint":"daily-model","endpoint":"https://model.example/v1"}]});
    assert_eq!(call(&h, "POST", "/api/v1/assets/discovery", Some(observed.clone())).await.status, StatusCode::OK);
    let yesterday =
        Date::parse(&(chrono::Utc::now() - chrono::Duration::days(1)).format("%Y-%m-%d").to_string()).unwrap();
    let first = run_for_date(&h.state, h.tenant, yesterday).await.unwrap();
    assert!(first.initial_baseline);
    assert_eq!(first.snapshot_count, 2);
    assert_eq!(first.summary.total, 0);
    let mut changed = observed;
    changed["assets"][0]["content_sha256"] = json!("b".repeat(64));
    changed["assets"][1]["endpoint"] = json!("https://changed.example/v1");
    changed["assets"]
        .as_array_mut()
        .unwrap()
        .push(json!({"kind":"mcp-server","name":"Shadow MCP","fingerprint":"shadow"}));
    assert_eq!(call(&h, "POST", "/api/v1/assets/discovery", Some(changed)).await.status, StatusCode::OK);
    let (a, b) = tokio::join!(
        run_for_date(&h.state, h.tenant, Date::today()),
        run_for_date(&other.state, h.tenant, Date::today())
    );
    let run = a.unwrap();
    assert_eq!(run.id, b.unwrap().id);
    assert_eq!(run.summary.added, 1);
    assert_eq!(run.summary.modified, 2);
    assert_eq!(run.summary.risky, 3);
    let history = call(&other, "GET", "/api/v1/assets/inventory", None).await.json();
    assert_eq!(history["total"], 2);
    let uri = format!("/api/v1/assets/inventory/{}/changes", run.id);
    let details = call(&other, "GET", &uri, None).await.json();
    assert_eq!(details["total"], 3);
    assert!(
        details["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["field"] == "content_sha256" && c["old_value"] == "a".repeat(64))
    );
    let after = call(&other, "GET", &format!("/api/v1/assets/{id}"), None).await.json();
    assert_eq!(after["asset"]["lifecycle"], "requested");
    assert_eq!(after["asset"]["owner"], "alice");
    assert_eq!(after["asset"]["data_class"], "confidential");
    let resumed = second(&h, db);
    assert_eq!(call(&resumed, "POST", "/api/v1/assets/inventory", None).await.json()["id"], run.id.to_string());
    let (foreign, _) = setup_sql().await;
    assert_eq!(call(&foreign, "GET", &uri, None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(call(&h, "GET", "/api/v1/assets/inventory?page=0", None).await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn empty_baseline_is_retained_and_catchup_uses_last_completed_run() {
    let (h, _) = setup_sql().await;
    let old = Date::parse(&(chrono::Utc::now() - chrono::Duration::days(3)).format("%Y-%m-%d").to_string()).unwrap();
    let first = run_for_date(&h.state, h.tenant, old).await.unwrap();
    assert_eq!(first.snapshot_count, 0);
    assert_eq!(call(&h, "POST", "/api/v1/assets/register", Some(application())).await.status, StatusCode::OK);
    let current = run_for_date(&h.state, h.tenant, Date::today()).await.unwrap();
    assert_eq!(current.baseline_date, Some(first.date));
    assert_eq!(current.summary.added, 1);
    let middle = Date::parse(&(chrono::Utc::now() - chrono::Duration::days(2)).format("%Y-%m-%d").to_string()).unwrap();
    assert!(run_for_date(&h.state, h.tenant, middle).await.is_err());
    assert_eq!(call(&h, "GET", "/api/v1/assets/inventory", None).await.json()["total"], 2);
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn removed_asset_rolls_back_with_audit_and_rediscovery_restores_stable_id() {
    let (h, db) = setup_sql().await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&std::env::var("AGF_TEST_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let created = call(&h, "POST", "/api/v1/assets/register", Some(application())).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    let id = created.json()["asset"]["id"].as_str().unwrap().to_owned();
    let path = format!("/api/v1/assets/{id}");
    let first = call(&h, "GET", &path, None).await.json();
    let reviewed = call(
        &h,
        "POST",
        &format!("{path}/transition"),
        Some(json!({
            "to":"rejected","note":"Application withdrawn",
            "expected_updated_at":first["governance"]["updated_at"]
        })),
    )
    .await;
    assert_eq!(reviewed.status, StatusCode::OK, "{}", reviewed.text);
    let before = call(&h, "GET", &path, None).await.json();
    let body = json!({"expected_updated_at":before["governance"]["updated_at"],
        "confirm_name":"Finance review","reason":"Retired inventory entry"});
    let (foreign, _) = setup_sql().await;
    assert_eq!(call(&foreign, "DELETE", &path, Some(body.clone())).await.status, StatusCode::NOT_FOUND);
    let mut tx = db.db().begin_tenant(h.tenant).await.unwrap();
    let chain = AuditRepo::chain_stats(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    let constraint = format!("agf_test_remove_audit_{}", Id::new().as_uuid().simple());
    sqlx::query(&format!(
        "ALTER TABLE audit_logs ADD CONSTRAINT {constraint} CHECK (tenant_id <> '{}'::uuid) NOT VALID",
        h.tenant
    ))
    .execute(&pool)
    .await
    .unwrap();
    let failed = call(&h, "DELETE", &path, Some(body.clone())).await;
    assert!(failed.status.is_server_error(), "{}", failed.text);
    let other = second(&h, db.clone());
    let unchanged = call(&other, "GET", &path, None).await.json();
    assert_eq!(unchanged["asset"], before["asset"]);
    assert_eq!(unchanged["changes"], before["changes"]);
    assert_eq!(call(&other, "GET", "/api/v1/assets", None).await.json()["total"], 1);
    let mut tx = db.db().begin_tenant(h.tenant).await.unwrap();
    assert_eq!(AuditRepo::chain_stats(&mut tx).await.unwrap(), chain);
    tx.commit().await.unwrap();
    sqlx::query(&format!("ALTER TABLE audit_logs DROP CONSTRAINT {constraint}")).execute(&pool).await.unwrap();
    let removed = call(&h, "DELETE", &path, Some(body)).await;
    assert_eq!(removed.status, StatusCode::OK, "{}", removed.text);
    assert_eq!(call(&other, "GET", &path, None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(call(&other, "GET", "/api/v1/assets", None).await.json()["total"], 0);
    let revived = call(
        &other,
        "POST",
        "/api/v1/assets/discovery",
        Some(json!({"assets":[{
            "kind":"skill","name":"Finance review","fingerprint":"reviewed-skill"
        }]})),
    )
    .await;
    assert_eq!(revived.status, StatusCode::OK, "{}", revived.text);
    let restored = call(&second(&h, db), "GET", &path, None).await.json();
    assert_eq!(restored["asset"]["id"], id);
    assert!(restored["changes"].as_array().unwrap().iter().any(|change| change["change_kind"] == "removed"));
    pool.close().await;
}
