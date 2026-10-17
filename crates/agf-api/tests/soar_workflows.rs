//! Durable approvals, waiting, concurrent workers and recovery use real route contracts.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::soar_workflow::{self as workflow, Run, Status};
use agf_core::ids::Id;
use common::*;

fn book() -> Value {
    json!({"playbook":{"key":"durable-containment","name":"Durable containment","trigger":{},
        "require_approval":true,"timeout_secs":7200,"steps":[
        {"name":"Block first domain","action":"block-domain","params":{"domain":"first.example"}},
        {"name":"Wait an hour","params":{"wait_secs":3600}},
        {"name":"Second review","params":{"require_approval":true}},
        {"name":"Block second domain","action":"block-domain","params":{"domain":"second.example"}}
    ]}})
}
async fn run(h: &Harness, path: &str, id: Id) -> Run {
    let response = h.get(&format!("{path}/{id}")).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    serde_json::from_value(response.json()["run"].clone()).unwrap()
}
async fn decision(h: &Harness, path: &str, run: &Run, action: &str) -> Resp {
    h.post(
        &format!("{path}/{}/decision", run.id),
        json!({"expected_version":run.version,"action":action,"reason":"Reviewed the exact saved targets"}),
    )
    .await
}

#[tokio::test]
async fn approval_waits_and_recovery_preserve_targets_and_do_not_replay_actions() {
    let h = setup().await;
    exercise(h, None).await;
}

#[tokio::test]
#[ignore = "requires an isolated AGF_TEST_DATABASE_URL"]
async fn sql_workflow_resumes_with_fresh_stores_and_competing_workers() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(12).connect(&url).await.unwrap();
    let db = agf_storage::Database::from_pool(pool);
    db.migrate().await.unwrap();
    let db = Arc::new(agf_storage::Store::new(db, None, Arc::new(agf_storage::objectstore::MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
    let tenant =
        agf_api::tenant_directory::new(format!("soar-workflow-{}", Id::new()), "SOAR workflow SQL test".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    // Issue a fresh superadmin token scoped to the isolated tenant; the actor stays in the original identity tenant.
    h.tenant = tenant.id;
    h.app = build_router(h.state.clone());
    exercise(h, Some(db)).await;
}

async fn exercise(mut h: Harness, db: Option<Arc<agf_storage::Store>>) {
    // Header middleware is applied to every request by a scoped router, including subsequent reads.
    if db.is_some() {
        let tenant = h.tenant.to_string();
        h.app = h.app.layer(axum::middleware::map_request(move |mut request: Request<Body>| {
            request.headers_mut().insert("x-agf-tenant", tenant.parse().unwrap());
            async move { request }
        }));
    }
    let case = create_case_for_soc(&h, "Durable run case", "high").await;
    let path = format!("/api/v1/cases/{case}/playbook-runs");
    let response = h.post(&path, book()).await;
    assert_eq!(response.status, StatusCode::ACCEPTED, "{}", response.text);
    let mut current: Run = serde_json::from_value(response.json()["run"].clone()).unwrap();
    assert_eq!(current.status, Status::Approval);
    assert!(agf_api::containment::list(&h.state, h.tenant).await.unwrap().is_empty());
    assert_eq!(
        workflow::advance(&h.state, h.tenant, current.id, Timestamp::now()).await.unwrap().status,
        Status::Approval
    );
    let url = format!("{path}/{}/decision", current.id);
    let body = json!({"expected_version":current.version,"action":"approve","reason":"reviewed"});
    assert_eq!(h.request("POST", &url, Some(&h.viewer), Some(body.clone())).await.status, StatusCode::FORBIDDEN);
    assert_eq!(
        h.post(&url, json!({"expected_version":0,"action":"approve","reason":"stale"})).await.status,
        StatusCode::CONFLICT
    );
    let (first, duplicate) = tokio::join!(h.post(&url, body.clone()), h.post(&url, body));
    assert!(matches!(
        (first.status, duplicate.status),
        (StatusCode::OK, StatusCode::CONFLICT) | (StatusCode::CONFLICT, StatusCode::OK)
    ));
    let now = Timestamp::now();
    let (a, b) = tokio::join!(
        workflow::advance(&h.state, h.tenant, current.id, now),
        workflow::advance(&h.state, h.tenant, current.id, now)
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(agf_api::containment::list(&h.state, h.tenant).await.unwrap().len(), 1);
    current = workflow::advance(&h.state, h.tenant, current.id, now).await.unwrap();
    assert_eq!(current.status, Status::Waiting);
    let wake = current.wake_at.unwrap();
    if let Some(db) = db {
        h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
        h.state.store = Arc::new(agf_api::store::ApiStore::with_database(db));
        h.app = build_router(h.state.clone());
        let tenant = h.tenant.to_string();
        h.app = h.app.layer(axum::middleware::map_request(move |mut request: Request<Body>| {
            request.headers_mut().insert("x-agf-tenant", tenant.parse().unwrap());
            async move { request }
        }));
        current = run(&h, &path, current.id).await;
        assert_eq!(current.status, Status::Waiting);
    }
    assert_eq!(
        workflow::advance(&h.state, h.tenant, current.id, wake.offset_secs(-1)).await.unwrap().status,
        Status::Waiting
    );
    current = workflow::advance(&h.state, h.tenant, current.id, wake).await.unwrap();
    assert_eq!(current.next_step, 2);
    current = workflow::advance(&h.state, h.tenant, current.id, wake).await.unwrap();
    assert_eq!(current.status, Status::Approval, "an explicit gate requires a new decision");
    assert_eq!(decision(&h, &path, &current, "approve").await.status, StatusCode::OK);
    current = workflow::advance(&h.state, h.tenant, current.id, wake).await.unwrap();
    assert_eq!(current.status, Status::Completed);
    assert_eq!(current.trace.len(), 4);
    assert_eq!(agf_api::containment::list(&h.state, h.tenant).await.unwrap().len(), 2);
    workflow::advance(&h.state, h.tenant, current.id, wake).await.unwrap();
    assert_eq!(agf_api::containment::list(&h.state, h.tenant).await.unwrap().len(), 2);
    let events = h.state.store.case_events_durable(h.tenant, current.case_id).await.unwrap();
    assert_eq!(events.iter().filter(|event| event.kind == agf_core::case::CaseEventKind::PlaybookRun).count(), 1);
    let recorded: Vec<agf_api::store::SoarRunRecord> = h.state.configurations.list(h.tenant, "soar-run").await.unwrap();
    assert_eq!(recorded.len(), 1);
    assert!(current.history.iter().any(|entry| entry.action == "approve" && entry.actor.starts_with("user:")));

    let mut crash: Run = serde_json::from_value(h.post(&path, book()).await.json()["run"].clone()).unwrap();
    crash.status = Status::Running;
    crash.initial_approval = false;
    crash.lease_token = Some(Id::new());
    crash.lease_until = Some(Timestamp::now().offset_secs(-1));
    h.state.configurations.put(h.tenant, workflow::KIND, crash.id, &crash).await.unwrap();
    crash = workflow::advance(&h.state, h.tenant, crash.id, Timestamp::now()).await.unwrap();
    assert_eq!(crash.status, Status::Review);
    assert_eq!(
        agf_api::containment::list(&h.state, h.tenant).await.unwrap().len(),
        2,
        "uncertain actions are not replayed"
    );
    assert_eq!(decision(&h, &path, &crash, "abort").await.status, StatusCode::OK);
    let queued = h
        .post(
            &path,
            json!({"playbook":{"key":"select-queued","name":"Selected worker job",
        "trigger":{},"timeout_secs":60,"steps":[{"name":"Condition","params":{"condition":"true"}}]}}),
        )
        .await;
    assert_eq!(queued.status, StatusCode::ACCEPTED, "{}", queued.text);
    let queued_id = Id::parse(queued.json()["run"]["id"].as_str().unwrap()).unwrap();
    workflow::tick(&h.state, Timestamp::now()).await.unwrap();
    assert_eq!(run(&h, &path, queued_id).await.status, Status::Completed);
    let first_page = h.get(&format!("{path}?page=1&page_size=1")).await;
    assert_eq!(first_page.status, StatusCode::OK, "{}", first_page.text);
    assert_eq!(first_page.json()["total"], 3);
    assert_eq!(first_page.json()["items"].as_array().unwrap().len(), 1);
    assert_eq!(first_page.json()["items"][0]["id"], queued_id.to_string());
    let filtered = h.get(&format!("{path}?q=select-queued")).await;
    assert_eq!(filtered.json()["total"], 1);
}

#[tokio::test]
async fn two_person_review_revocation_and_expiry_are_enforced() {
    let h = setup().await;
    let case = create_case_for_soc(&h, "Separated duties", "high").await;
    let path = format!("/api/v1/cases/{case}/playbook-runs");
    let mut body = book();
    body["separate_approver"] = json!(true);
    let response = h.post(&path, body).await;
    let current: Run = serde_json::from_value(response.json()["run"].clone()).unwrap();
    assert_eq!(decision(&h, &path, &current, "approve").await.status, StatusCode::FORBIDDEN);
    let viewer = h
        .state
        .auth_backend
        .list_users(h.tenant)
        .await
        .unwrap()
        .into_iter()
        .find(|user| user.username == "viewer")
        .unwrap();
    h.state.auth_backend.save_account(&viewer, None, &[agf_core::rbac::builtin::TENANT_ADMIN.into()]).await.unwrap();
    let approved = h
        .request(
            "POST",
            &format!("{path}/{}/decision", current.id),
            Some(&h.viewer),
            Some(json!({"expected_version":current.version,"action":"approve","reason":"Independent review"})),
        )
        .await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.text);
    // The saved approval must not preserve a role removed before the action runs.
    let viewer = h.state.auth_backend.find_user(h.tenant, viewer.id).await.unwrap().unwrap();
    h.state.auth_backend.save_account(&viewer, None, &[agf_core::rbac::builtin::VIEWER.into()]).await.unwrap();
    let stopped = workflow::advance(&h.state, h.tenant, current.id, Timestamp::now()).await.unwrap();
    assert_eq!(stopped.status, Status::Aborted);
    assert!(agf_api::containment::list(&h.state, h.tenant).await.unwrap().is_empty());
    let expired: Run = serde_json::from_value(h.post(&path, book()).await.json()["run"].clone()).unwrap();
    let stopped = workflow::advance(&h.state, h.tenant, expired.id, expired.wake_at.unwrap()).await.unwrap();
    assert_eq!(stopped.status, Status::Aborted);
    assert_eq!(decision(&h, &path, &stopped, "approve").await.status, StatusCode::CONFLICT);
    let foreign = h
        .request_with(
            "GET",
            &format!("{path}/{}", current.id),
            &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &h.other_tenant.to_string())],
            None,
        )
        .await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND);
    let service = h.post("/api/v1/settings/api-keys", json!({"name":"No human approval","scopes":["*"]})).await;
    let key = service.json()["plaintext"].as_str().unwrap().to_owned();
    let pending: Run = serde_json::from_value(h.post(&path, book()).await.json()["run"].clone()).unwrap();
    let service_approval = h
        .request(
            "POST",
            &format!("{path}/{}/decision", pending.id),
            Some(&key),
            Some(json!({"expected_version":pending.version,"action":"approve","reason":"Service cannot approve"})),
        )
        .await;
    assert_eq!(service_approval.status, StatusCode::FORBIDDEN);
    let mut automatic = book();
    automatic["playbook"]["require_approval"] = json!(false);
    let mut switched: Run = serde_json::from_value(h.post(&path, automatic).await.json()["run"].clone()).unwrap();
    switched.mock_mode = !h.state.config.mock_mode;
    h.state.configurations.put(h.tenant, workflow::KIND, switched.id, &switched).await.unwrap();
    let stopped = workflow::advance(&h.state, h.tenant, switched.id, Timestamp::now()).await.unwrap();
    assert_eq!(stopped.status, Status::Aborted);
    assert!(agf_api::containment::list(&h.state, h.tenant).await.unwrap().is_empty());
}
