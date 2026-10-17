//! Automatic response uses real route contracts and an optional isolated SQL database.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::{
    soar_automation::{self as automation, Automation, Delivery},
    soar_workflow::{self as workflow, Run, Status},
};
use agf_core::ids::Id;
use common::*;

const ROOT: &str = "/api/v1/soar/automations";
fn definition() -> Value {
    json!({"enabled":true,"reason":"Reviewed automatic trigger and fixed target","playbook":{
        "key":"auto-domain","name":"Automatic domain response","trigger":{"min_severity":"high"},
        "require_approval":true,"steps":[{"name":"Block domain","action":"block-domain","params":{"domain":"automatic.example"}}]}})
}
async fn save(h: &Harness, input: Value) -> Automation {
    let response = h.post(ROOT, input).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    serde_json::from_value(response.json()["automation"].clone()).unwrap()
}
async fn update(h: &Harness, row: &Automation, enabled: bool) -> Resp {
    let mut body = definition();
    body["enabled"] = json!(enabled);
    body["expected_version"] = json!(row.version);
    h.request("PUT", &format!("{ROOT}/{}", row.id), Some(&h.admin), Some(body)).await
}
async fn records(h: &Harness, id: Id) -> Vec<Delivery> {
    let response = h.get(&format!("{ROOT}/{id}/deliveries?page_size=100")).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    serde_json::from_value(response.json()["items"].clone()).unwrap()
}
fn scope(h: &mut Harness) {
    let tenant = h.tenant.to_string();
    h.app = build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
        request.headers_mut().insert("x-agf-tenant", tenant.parse().unwrap());
        async move { request }
    }));
}

#[tokio::test]
async fn offline_automatic_response_is_explicit_and_permission_scoped() {
    Box::pin(exercise(setup().await, None)).await;
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn sql_automatic_response_commits_case_run_receipt_and_recovers_late_commits() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(12).connect(&url).await.unwrap();
    let database = agf_storage::Database::from_pool(pool);
    database.migrate().await.unwrap();
    let db =
        Arc::new(agf_storage::Store::new(database, None, Arc::new(agf_storage::objectstore::MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
    let tenant =
        agf_api::tenant_directory::new(format!("soar-automation-{}", Id::new()), "SOAR automation test".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.tenant = tenant.id;
    scope(&mut h);
    Box::pin(exercise(h, Some(db))).await;
}

async fn exercise(mut h: Harness, db: Option<Arc<agf_storage::Store>>) {
    let old = create_alert_for_soc(&h, "Before enablement", "high", "old-auto").await;
    let template = save(&h, definition()).await;
    assert_eq!(template.version, 1);
    let high = create_alert_for_soc(&h, "Automatic high", "high", "new-auto").await;
    let low = create_alert_for_soc(&h, "Automatic low", "low", "low-auto").await;
    let stopped = create_alert_for_soc(&h, "Suppressed alert", "high", "suppressed-auto").await;
    h.state
        .store
        .alert_set_state_durable(h.tenant, Id::parse(&stopped).unwrap(), agf_core::enums::AlertState::Suppressed, None)
        .await
        .unwrap();
    let mut preview = definition();
    preview["alert_id"] = json!(high);
    let checked = h.post(&format!("{ROOT}/preview"), preview).await;
    assert_eq!(checked.status, StatusCode::OK, "{}", checked.text);
    assert_eq!(checked.json()["matches"], true);
    assert!(h.state.store.case_list_durable(h.tenant).await.unwrap().is_empty(), "preview has no effects");
    assert_eq!(h.request("POST", ROOT, Some(&h.viewer), Some(definition())).await.status, StatusCode::FORBIDDEN);
    let readonly = h.request("GET", ROOT, Some(&h.viewer), None).await;
    if db.is_none() {
        assert_eq!(readonly.json()["can_manage"], false);
    } else {
        assert_eq!(readonly.status, StatusCode::FORBIDDEN, "viewer cannot cross identity tenants");
    }
    let mut second = h.state.clone();
    if let Some(db) = &db {
        second = AppState::with_database((*h.state.config).clone(), db.clone()).unwrap();
        second.auth_backend = h.state.auth_backend.clone();
    }
    let (first, other) = tokio::join!(automation::tick(&h.state), automation::tick(&second));
    first.unwrap();
    other.unwrap();
    let rows = records(&h, template.id).await;
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|row| row.alert_id.to_string() != old));
    assert_eq!(rows.iter().find(|row| row.alert_id.to_string() == low).unwrap().status, "skipped");
    assert_eq!(rows.iter().find(|row| row.alert_id.to_string() == stopped).unwrap().status, "skipped");
    let submitted = rows.iter().find(|row| row.alert_id.to_string() == high).unwrap();
    let run_id = submitted.run_id.unwrap();
    let mut run = workflow::get(&h.state, h.tenant, run_id).await.unwrap();
    assert_eq!(run.status, Status::Approval);
    assert_eq!(h.state.store.case_list_durable(h.tenant).await.unwrap().len(), 1);
    assert!(agf_api::containment::list(&h.state, h.tenant).await.unwrap().is_empty());
    let duplicate = create_alert_for_soc(&h, "Automatic high", "high", "new-auto").await;
    assert_eq!(duplicate, high);
    automation::tick(&h.state).await.unwrap();
    assert_eq!(records(&h, template.id).await.len(), 3);
    let path = format!("/api/v1/cases/{}/playbook-runs/{}/decision", run.case_id, run.id);
    let approved = h
        .post(&path, json!({"expected_version":run.version,"action":"approve","reason":"Reviewed the matching alert"}))
        .await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.text);
    run = workflow::advance(&h.state, h.tenant, run_id, Timestamp::now()).await.unwrap();
    assert_eq!(run.status, Status::Completed);
    assert_eq!(agf_api::containment::list(&h.state, h.tenant).await.unwrap().len(), 1);
    let paused = update(&h, &template, false).await;
    assert_eq!(paused.status, StatusCode::OK, "{}", paused.text);
    let paused: Automation = serde_json::from_value(paused.json()["automation"].clone()).unwrap();
    assert_eq!(update(&h, &template, true).await.status, StatusCode::CONFLICT, "stale edits rejected");
    let gap = create_alert_for_soc(&h, "While disabled", "high", "disabled-auto").await;
    automation::tick(&h.state).await.unwrap();
    let enabled = update(&h, &paused, true).await;
    assert_eq!(enabled.status, StatusCode::OK, "{}", enabled.text);
    let enabled: Automation = serde_json::from_value(enabled.json()["automation"].clone()).unwrap();
    let next = create_alert_for_soc(&h, "After restart", "high", "restart-auto").await;
    if let Some(db) = &db {
        h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
        h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
        scope(&mut h);
    }
    automation::tick(&h.state).await.unwrap();
    let rows = records(&h, template.id).await;
    assert_eq!(rows.len(), 4);
    assert!(rows.iter().all(|row| row.alert_id.to_string() != gap));
    assert_eq!(rows.iter().find(|row| row.alert_id.to_string() == next).unwrap().automation_version, 3);
    assert_eq!(workflow::get(&h.state, h.tenant, run_id).await.unwrap().status, Status::Completed);
    let paged = h.get(&format!("{ROOT}/{}/deliveries?page_size=1&q=After%20restart", template.id)).await;
    assert_eq!(paged.json()["total"], 1);
    assert_eq!(paged.json()["items"].as_array().unwrap().len(), 1);
    assert_eq!(enabled.history.len(), 3);
    // Two automations share one case; a resolved case is never silently reopened.
    let other = save(&h, definition()).await;
    let shared = create_alert_for_soc(&h, "Shared auto case", "high", "shared-auto").await;
    automation::tick(&h.state).await.unwrap();
    let a = records(&h, template.id).await.into_iter().find(|row| row.alert_id.to_string() == shared).unwrap();
    let b = records(&h, other.id).await.into_iter().find(|row| row.alert_id.to_string() == shared).unwrap();
    assert_eq!(a.case_id, b.case_id);
    assert_ne!(a.run_id, b.run_id);
    if let Some(db) = &db {
        let mut tx = db.db().begin_tenant(h.tenant).await.unwrap();
        let (late, _) = agf_storage::AlertRepo::upsert_dedup(
            &mut tx,
            "late-commit-auto",
            "Late transaction",
            "Late committed alert",
            agf_core::enums::Severity::High,
            None,
            &[],
            &[],
            None,
        )
        .await
        .unwrap();
        automation::tick(&h.state).await.unwrap();
        tx.commit().await.unwrap();
        automation::tick(&h.state).await.unwrap();
        assert!(records(&h, other.id).await.iter().any(|row| row.alert_id == late && row.status == "submitted"));
        let independent = agf_storage::configuration::ConfigStore::new(Some(db.clone()));
        let (a, b) = tokio::join!(
            h.state.configurations.mutate_bounded::<Option<Value>, _>(
                h.tenant,
                "soar-limit-test",
                Id::new(),
                Some(1),
                |row| {
                    *row = Some(json!({"source":"a"}));
                    Ok(())
                }
            ),
            independent.mutate_bounded::<Option<Value>, _>(h.tenant, "soar-limit-test", Id::new(), Some(1), |row| {
                *row = Some(json!({"source":"b"}));
                Ok(())
            })
        );
        assert_ne!(a.is_ok(), b.is_ok(), "cross-instance configuration limit is atomic");
        let source = setup().await;
        seed_ai_assets(&source).await;
        let mut asset = source
            .state
            .store
            .asset_list_all(source.tenant)
            .unwrap()
            .into_iter()
            .find(|asset| asset.kind == agf_core::enums::AssetKind::Agent)
            .unwrap();
        asset.tenant_id = h.tenant;
        let id = asset.id;
        db.with_tenant(h.tenant, move |tx| Box::pin(async move { agf_storage::AssetRepo::upsert(tx, &asset).await }))
            .await
            .unwrap();
        assert!(h.state.store.asset_get(h.tenant, id).unwrap().is_none());
        assert!(h.state.store.asset_get_durable(h.tenant, id).await.unwrap().is_some());
        db.with_tenant(h.tenant, move |tx| {
            Box::pin(async move {
                sqlx::query("UPDATE assets SET deleted_at=now() WHERE id=$1")
                    .bind(id.as_uuid())
                    .execute(&mut **tx)
                    .await
                    .unwrap();
                Ok(())
            })
        })
        .await
        .unwrap();
        assert!(h.state.store.asset_get_durable(h.tenant, id).await.unwrap().is_none());
        assert!(h.state.store.asset_get(h.tenant, id).unwrap().is_none(), "deleted target evicts stale cache");
    }
    let mut foreign_harness = h.clone();
    foreign_harness.app = build_router(h.state.clone());
    let foreign = foreign_harness
        .request_with(
            "GET",
            &format!("{ROOT}/{}/deliveries", template.id),
            &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &h.other_tenant.to_string())],
            None,
        )
        .await;
    assert!(matches!(foreign.status, StatusCode::NOT_FOUND | StatusCode::FORBIDDEN));
}

#[tokio::test]
async fn publisher_revocation_and_failed_trigger_retry_do_not_preserve_old_permissions() {
    let h = setup().await;
    let viewer = h
        .state
        .auth_backend
        .list_users(h.tenant)
        .await
        .unwrap()
        .into_iter()
        .find(|row| row.username == "viewer")
        .unwrap();
    h.state.auth_backend.save_account(&viewer, None, &[agf_core::rbac::builtin::TENANT_ADMIN.into()]).await.unwrap();
    let response = h.request("POST", ROOT, Some(&h.viewer), Some(definition())).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    let template: Automation = serde_json::from_value(response.json()["automation"].clone()).unwrap();
    let viewer = h.state.auth_backend.find_user(h.tenant, viewer.id).await.unwrap().unwrap();
    h.state.auth_backend.save_account(&viewer, None, &[agf_core::rbac::builtin::VIEWER.into()]).await.unwrap();
    create_alert_for_soc(&h, "Revoked publisher", "high", "revoked-publisher").await;
    automation::tick(&h.state).await.unwrap();
    let row = records(&h, template.id).await.remove(0);
    assert_eq!(row.status, "failed");
    assert!(row.run_id.is_none());
    assert!(h.state.store.case_list_durable(h.tenant).await.unwrap().is_empty());
    let url = format!("{ROOT}/{}/deliveries/{}/retry", template.id, row.id);
    assert_eq!(
        h.request("POST", &url, Some(&h.viewer), Some(json!({"expected_version":1}))).await.status,
        StatusCode::FORBIDDEN
    );
    let viewer = h.state.auth_backend.find_user(h.tenant, viewer.id).await.unwrap().unwrap();
    h.state.auth_backend.save_account(&viewer, None, &[agf_core::rbac::builtin::TENANT_ADMIN.into()]).await.unwrap();
    assert_eq!(h.post(&url, json!({"expected_version":1})).await.status, StatusCode::OK);
    automation::tick(&h.state).await.unwrap();
    let row = records(&h, template.id).await.remove(0);
    assert_eq!(row.status, "submitted");
    assert_eq!(row.attempts, 2);
    assert_eq!(
        row.history.iter().map(|entry| entry.status.as_str()).collect::<Vec<_>>(),
        vec!["failed", "pending", "submitted"]
    );
    assert_eq!(h.post(&url, json!({"expected_version":1})).await.status, StatusCode::CONFLICT);
    assert_eq!(h.state.configurations.list::<Run>(h.tenant, workflow::KIND).await.unwrap().len(), 1);
    let service = h.post("/api/v1/settings/api-keys", json!({"name":"Service","scopes":["*"]})).await;
    let key = service.json()["plaintext"].as_str().unwrap().to_owned();
    assert_eq!(h.request("POST", ROOT, Some(&key), Some(definition())).await.status, StatusCode::FORBIDDEN);
    let mut missing = definition();
    missing["playbook"]["steps"][0]["params"]["domain"] = json!("");
    assert_eq!(h.post(ROOT, missing).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(h.get(&format!("{ROOT}/templates")).await.json()["items"].as_array().unwrap().len(), 6);
}

#[tokio::test]
async fn automatic_isolation_selects_the_unique_agent_among_mixed_assets() {
    let h = setup().await;
    assert!(seed_ai_assets(&h).await.status.is_success());
    let rows = h.get("/api/v1/assets?page_size=100").await.json();
    let assets = rows["items"].as_array().unwrap();
    let agent = assets.iter().find(|row| row["kind"] == "agent").unwrap()["id"].as_str().unwrap();
    let mcp = assets.iter().find(|row| row["kind"] == "mcp-server").unwrap()["id"].as_str().unwrap();
    let templates = h.get(&format!("{ROOT}/templates")).await.json();
    let book = templates["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["key"] == "review-agent-isolation")
        .unwrap()["playbook"]
        .clone();
    let template = save(&h, json!({"playbook":book,"enabled":true,"reason":"Mixed assets target test"})).await;
    let response =
        h.post("/api/v1/alerts", json!({"title":"Mixed asset alert","severity":"high","asset_ids":[mcp,agent]})).await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
    automation::tick(&h.state).await.unwrap();
    let delivery = records(&h, template.id).await.remove(0);
    let run = workflow::get(&h.state, h.tenant, delivery.run_id.unwrap()).await.unwrap();
    let approved = h
        .post(
            &format!("/api/v1/cases/{}/playbook-runs/{}/decision", run.case_id, run.id),
            json!({"expected_version":run.version,"action":"approve","reason":"Only the linked Agent"}),
        )
        .await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.text);
    let finished = workflow::advance(&h.state, h.tenant, run.id, Timestamp::now()).await.unwrap();
    assert_eq!(finished.status, Status::Completed, "{:?}", finished.trace);
    let controls = agf_api::containment::list(&h.state, h.tenant).await.unwrap();
    assert_eq!(controls.len(), 1);
    assert_eq!(controls[0].target, agent);
}

#[tokio::test]
async fn automatic_scim_alert_creates_approval_run_for_bound_identity() {
    let h = setup().await;
    let asset = h
        .post(
            "/api/v1/assets/register",
            json!({
                "request_id":Id::new().to_string(),"fingerprint":format!("auto-scim-{}",Id::new()),
                "kind":"credential","name":"Test identity","owner":"soc","data_class":"internal",
                "note":"Automatic SCIM test","scim_user_id":"user-42"
            }),
        )
        .await;
    assert_eq!(asset.status, StatusCode::OK, "{}", asset.text);
    let asset_id = asset.json()["asset"]["id"].as_str().unwrap().to_string();
    let configured = h
        .request(
            "PUT",
            "/api/v1/integrations/adapters/iam-scim/configuration",
            Some(&h.admin),
            Some(json!({"expected_version":0,"enabled":true,"mock":true,"settings":{},"secrets":{}})),
        )
        .await;
    assert_eq!(configured.status, StatusCode::OK, "{}", configured.text);
    let templates = h.get(&format!("{ROOT}/templates")).await.json();
    let mut book = templates["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["key"] == "review-scim-deactivation")
        .unwrap()["playbook"]
        .clone();
    book["steps"][0]["params"] = json!({"asset_id":asset_id,"user_id":"user-42",
        "configuration_version":1,"reason":"Confirmed identity compromise"});
    let mut invalid = book.clone();
    invalid["steps"][0]["params"]["user_id"] = json!("user-43");
    assert_eq!(
        h.post(ROOT, json!({"playbook":invalid,"enabled":true,"reason":"Wrong target"})).await.status,
        StatusCode::BAD_REQUEST
    );
    let mut stale = book.clone();
    stale["steps"][0]["params"]["configuration_version"] = json!(0);
    assert_eq!(
        h.post(ROOT, json!({"playbook":stale,"enabled":true,"reason":"Wrong version"})).await.status,
        StatusCode::BAD_REQUEST
    );
    let saved = save(&h, json!({"playbook":book,"enabled":true,"reason":"Reviewed bound identity"})).await;
    let other = h
        .post(
            "/api/v1/assets/register",
            json!({
                "request_id":Id::new().to_string(),"fingerprint":format!("other-scim-{}",Id::new()),
                "kind":"credential","name":"Other identity","owner":"soc","data_class":"internal",
                "note":"Unrelated identity"
            }),
        )
        .await;
    assert_eq!(other.status, StatusCode::OK, "{}", other.text);
    let other_id = other.json()["asset"]["id"].as_str().unwrap().to_string();
    let unrelated = h
        .post(
            "/api/v1/alerts",
            json!({
                "title":"Other compromised identity","severity":"high","asset_ids":[other_id]
            }),
        )
        .await;
    assert_eq!(unrelated.status, StatusCode::CREATED, "{}", unrelated.text);
    let unrelated_id = unrelated.json()["alert"]["id"].as_str().unwrap().to_string();
    let alert = h
        .post(
            "/api/v1/alerts",
            json!({
                "title":"Compromised identity","severity":"high","asset_ids":[asset_id]
            }),
        )
        .await;
    assert_eq!(alert.status, StatusCode::CREATED, "{}", alert.text);
    automation::tick(&h.state).await.unwrap();
    let deliveries = records(&h, saved.id).await;
    assert_eq!(deliveries.len(), 2);
    let skipped = deliveries.iter().find(|row| row.alert_id.to_string() == unrelated_id).unwrap();
    assert_eq!(skipped.status, "skipped");
    assert!(skipped.run_id.is_none());
    let delivery = deliveries.into_iter().find(|row| row.status == "submitted").unwrap();
    assert_eq!(delivery.status, "submitted");
    let run = workflow::get(&h.state, h.tenant, delivery.run_id.unwrap()).await.unwrap();
    assert_eq!(run.status, Status::Approval);
    assert!(agf_api::integration_runtime::history(&h.state, h.tenant, "iam-scim").await.unwrap().is_empty());
    let decision = h
        .post(
            &format!("/api/v1/cases/{}/playbook-runs/{}/decision", run.case_id, run.id),
            json!({"expected_version":run.version,"action":"approve","reason":"Reviewed exact identity"}),
        )
        .await;
    assert_eq!(decision.status, StatusCode::OK, "{}", decision.text);
    let finished = workflow::advance(&h.state, h.tenant, run.id, Timestamp::now()).await.unwrap();
    assert_eq!(finished.status, Status::Completed, "{:?}", finished.reason);
    let receipts = agf_api::integration_runtime::history(&h.state, h.tenant, "iam-scim").await.unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["mocked"], true);
}

#[tokio::test]
async fn automatic_edr_alert_creates_approval_run_for_bound_host() {
    let h = setup().await;
    let asset = h
        .post(
            "/api/v1/assets/register",
            json!({
                "request_id":Id::new().to_string(),"fingerprint":format!("auto-edr-{}",Id::new()),
                "kind":"compute-node","name":"Test host","owner":"soc","data_class":"internal",
                "note":"Automatic EDR test","edr_host_id":"host-42"
            }),
        )
        .await;
    assert_eq!(asset.status, StatusCode::OK, "{}", asset.text);
    let asset_id = asset.json()["asset"]["id"].as_str().unwrap().to_string();
    let configured = h
        .request(
            "PUT",
            "/api/v1/integrations/adapters/edr-isolation/configuration",
            Some(&h.admin),
            Some(json!({"expected_version":0,"enabled":true,"mock":true,"settings":{},"secrets":{}})),
        )
        .await;
    assert_eq!(configured.status, StatusCode::OK, "{}", configured.text);
    let templates = h.get(&format!("{ROOT}/templates")).await.json();
    let mut book = templates["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["key"] == "review-edr-isolation")
        .unwrap()["playbook"]
        .clone();
    book["steps"][0]["params"] = json!({"asset_id":asset_id,"host_id":"host-42",
        "configuration_version":1,"reason":"Confirmed malicious activity"});
    let saved = save(&h, json!({"playbook":book,"enabled":true,"reason":"Reviewed bound host"})).await;
    let alert =
        h.post("/api/v1/alerts", json!({"title":"Malicious host","severity":"high","asset_ids":[asset_id]})).await;
    assert_eq!(alert.status, StatusCode::CREATED, "{}", alert.text);
    automation::tick(&h.state).await.unwrap();
    let delivery = records(&h, saved.id).await.remove(0);
    assert_eq!(delivery.status, "submitted");
    let run = workflow::get(&h.state, h.tenant, delivery.run_id.unwrap()).await.unwrap();
    assert_eq!(run.status, Status::Approval);
    assert!(agf_api::integration_runtime::history(&h.state, h.tenant, "edr-isolation").await.unwrap().is_empty());
    let decision = h
        .post(
            &format!("/api/v1/cases/{}/playbook-runs/{}/decision", run.case_id, run.id),
            json!({"expected_version":run.version,"action":"approve","reason":"Reviewed exact host"}),
        )
        .await;
    assert_eq!(decision.status, StatusCode::OK, "{}", decision.text);
    let finished = workflow::advance(&h.state, h.tenant, run.id, Timestamp::now()).await.unwrap();
    assert_eq!(finished.status, Status::Completed, "{:?}", finished.reason);
    let receipts = agf_api::integration_runtime::history(&h.state, h.tenant, "edr-isolation").await.unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["mocked"], true);
}
