//! Immutable campaign inputs, truthful simulation and restart-safe terminal evidence.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_api::{ApiStore, store::CampaignRecord};
use agf_core::{
    enums::{EvidenceLevel, Severity},
    ids::Id,
    redteam::{AttackCategory, AttackTurn, CampaignState, ExecutionMode, RedteamCase},
};
use agf_scan::redteam::CaseLibrary;
use agf_storage::{Database, Store, objectstore::MemoryObjectStore};
use common::*;

fn cases() -> Vec<RedteamCase> {
    [Severity::High, Severity::Low]
        .into_iter()
        .enumerate()
        .map(|(index, severity)| RedteamCase {
            key: format!("LOCAL-{index}"),
            title: format!("Local contract {index}"),
            category: AttackCategory::DirectInjection,
            severity,
            mode: ExecutionMode::SingleTurn,
            turns: vec![AttackTurn { role: "user".into(), content: "Local marker".into(), expect: vec![] }],
            applies_to: vec![],
            success_signals: vec!["marker_echo".into()],
            required_tools: vec![],
            tags: vec![],
            references: vec![],
            public_poc: false,
            remediation: "Review local fixture".into(),
            author: "test".into(),
            version: 7,
        })
        .collect()
}

async fn req(h: &Harness, method: &str, path: &str, body: Option<Value>) -> Resp {
    h.request_with(
        method,
        path,
        &[("authorization", &format!("Bearer {}", h.admin)), ("x-agf-tenant", &h.tenant.to_string())],
        body,
    )
    .await
}

async fn launch(h: &Harness, body: Value) -> Id {
    let response = req(h, "POST", "/api/v1/redteam/campaigns", Some(body)).await;
    assert_eq!(response.status, StatusCode::ACCEPTED, "{}", response.text);
    assert_eq!(response.json()["campaign"]["state"], "queued");
    response.json()["task_id"].as_str().unwrap().parse().unwrap()
}

async fn wait(h: &Harness, id: Id) -> CampaignRecord {
    for _ in 0..100 {
        let record = h.state.store.campaign_get_durable(h.tenant, id).await.unwrap().unwrap();
        if record.terminal() {
            assert_eq!(record.campaign.state, CampaignState::Completed, "{:?}", record.error);
            return record;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("Campaign did not finish");
}

fn queued(done: &CampaignRecord) -> CampaignRecord {
    let mut r = done.clone();
    r.campaign.id = Id::new();
    r.campaign.state = CampaignState::Queued;
    r.campaign.executed_cases = 0;
    r.campaign.succeeded_cases = 0;
    r.campaign.started_at = None;
    r.campaign.finished_at = None;
    r.campaign.created_at = Timestamp::now();
    r.results.clear();
    r.report = None;
    r.comparison = None;
    r.retest_of = None;
    r
}

async fn verify(mut h: Harness, db: Option<Arc<Store>>) {
    h.state.redteam_cases = Arc::new(CaseLibrary::from_cases(cases()));
    h.app = build_router(h.state.clone());
    for body in [
        json!({"name":"bad","categories":["prompt-injection"]}),
        json!({"name":"bad","targets":[Id::new()]}),
        json!({"name":"bad","execution_mode":"live"}),
        json!({"name":"bad","max_cases":0}),
        json!({"name":"bad","guard_strength":101}),
        json!({"name":"bad","case_keys":["missing"]}),
        json!({"name":"bad","severity_threshold":"banana"}),
    ] {
        let response = req(&h, "POST", "/api/v1/redteam/campaigns", Some(body)).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{}", response.text);
    }
    let before = h.state.store.finding_list_all_durable(h.tenant).await.unwrap().len();
    let id =
        launch(&h, json!({"name":"Durable high gate","guard_strength":0,"ci_gate":true,"severity_threshold":"high"}))
            .await;
    let completed = wait(&h, id).await;
    assert_eq!(completed.campaign.succeeded_cases, 2);
    assert!(!completed.report.as_ref().unwrap().ci_passed);
    assert!(completed.report.as_ref().unwrap().markdown.contains("- 模拟目标: local-simulator"));
    assert!(!completed.report.as_ref().unwrap().markdown.contains("<未指定>"));
    assert_eq!(completed.cases[0].version, 7);
    assert_eq!(h.state.store.finding_list_all_durable(h.tenant).await.unwrap().len(), before);
    assert!(h.state.store.alert_list(h.tenant, None, None).unwrap().is_empty());
    assert!(completed.campaign.target_agent_ids.is_empty());
    assert!(completed.results.iter().all(|r| r.mocked
        && r.finding_id.is_none()
        && !r.transcript.is_empty()
        && !r.evidence_refs.is_empty()
        && r.evidence_level == EvidenceLevel::Unknown));
    assert!(h.state.store.campaign_get_durable(h.other_tenant, id).await.unwrap().is_none());
    let page = req(
        &h,
        "GET",
        "/api/v1/redteam/campaigns?state=completed&page_size=1&q=Durable&fields=id,execution_mode,ci_passed",
        None,
    )
    .await;
    assert_eq!(page.json()["total"], 1);
    assert_eq!(page.json()["items"][0]["execution_mode"], "simulator");
    assert_eq!(page.json()["items"][0].as_object().unwrap().len(), 3);
    let projected = req(&h, "GET", &format!("/api/v1/redteam/campaigns/{id}/results"), None).await;
    assert_eq!(projected.json()[0]["severity"], "high");
    assert_eq!(projected.json()[0]["mocked"], true);
    let evidence = req(&h, "GET", &format!("/api/v1/redteam/campaigns/{id}/evidence"), None).await;
    assert_eq!(evidence.json()["record"]["cases"][0]["version"], 7);
    let crit =
        launch(&h, json!({"name":"Critical only","guard_strength":0,"ci_gate":true,"severity_threshold":"critical"}))
            .await;
    assert!(wait(&h, crit).await.report.unwrap().ci_passed);
    let disabled = launch(&h, json!({"name":"Disabled gate","guard_strength":0,"ci_gate":false})).await;
    assert!(wait(&h, disabled).await.report.unwrap().markdown.contains("CI 卡点: 未启用"));
    let disabled_report = req(&h, "GET", &format!("/api/v1/redteam/campaigns/{disabled}/report"), None).await;
    assert!(disabled_report.json()["ci_passed"].is_null());
    // Unsupported evaluations must not appear as blocked, or as a CI pass, even at guard=100.
    let mut unsupported_cases = cases();
    for case in &mut unsupported_cases {
        case.required_tools = vec!["never-available".into()];
    }
    h.state.redteam_cases = Arc::new(CaseLibrary::from_cases(unsupported_cases));
    h.app = build_router(h.state.clone());
    let incomplete = launch(&h, json!({"name":"Incomplete coverage", "guard_strength":100, "ci_gate":true})).await;
    let incomplete_record = wait(&h, incomplete).await;
    assert_eq!(incomplete_record.report.as_ref().unwrap().inconclusive_cases, 2);
    assert!(!incomplete_record.report.as_ref().unwrap().ci_passed);
    let view = req(&h, "GET", &format!("/api/v1/redteam/campaigns/{incomplete}"), None).await.json();
    assert_eq!(view["campaign"]["evaluated_cases"], 0);
    assert!(view["campaign"]["success_rate"].is_null());
    assert!(view["campaign"]["blocked"].is_null());
    let results = req(&h, "GET", &format!("/api/v1/redteam/campaigns/{incomplete}/results"), None).await.json();
    assert_eq!(results[0]["outcome"], "inconclusive");
    assert!(results[0]["evaluationNote"].as_str().is_some_and(|v| v.contains("required tool")));
    // The next deploy changes the library: retest must still use the immutable original cases.
    h.state.redteam_cases = Arc::new(CaseLibrary::from_cases(vec![]));
    h.app = build_router(h.state.clone());
    let retest = req(
        &h,
        "POST",
        &format!("/api/v1/redteam/campaigns/{id}/retest"),
        Some(json!({"name":"Retest","guard_strength":100})),
    )
    .await;
    assert_eq!(retest.status, StatusCode::ACCEPTED, "{}", retest.text);
    let retest_id: Id = retest.json()["task_id"].as_str().unwrap().parse().unwrap();
    let retested = wait(&h, retest_id).await;
    assert_eq!(retested.cases[0].version, 7);
    assert_eq!(retested.campaign.succeeded_cases, 0);
    assert!(retested.report.as_ref().unwrap().ci_passed);
    assert_eq!(retested.comparison.as_ref().unwrap()["resolved"].as_array().unwrap().len(), 2);
    assert_eq!(h.state.store.campaign_get_durable(h.tenant, id).await.unwrap().unwrap().campaign.succeeded_cases, 2);
    let reader = h.state.api_keys.issue(ApiKeyIssueRequest {
        scopes: vec![Permission::from_raw("redteam:read")],
        ..ApiKeyIssueRequest::named(h.tenant, "redteam-reader", Timestamp::now())
    });
    h.state.store.api_key_create_durable(&reader.record).await.unwrap();
    let response = h
        .request_with(
            "POST",
            &format!("/api/v1/redteam/campaigns/{id}/retest"),
            &[("x-agf-key", &reader.plaintext), ("x-agf-tenant", &h.tenant.to_string())],
            Some(json!({"name":"forbidden"})),
        )
        .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    let store = &h.state.store;
    let cancelled = queued(&completed);
    store.campaign_insert_durable(&cancelled).await.unwrap();
    let running =
        store.campaign_transition_durable(h.tenant, cancelled.campaign.id, CampaignState::Running, None).await.unwrap();
    let mut candidate = completed.clone();
    candidate.campaign = running.campaign.clone();
    candidate.campaign.state = CampaignState::Completed;
    candidate.campaign.executed_cases = 2;
    candidate.campaign.succeeded_cases = 2;
    candidate.campaign.finished_at = Some(Timestamp::now());
    for result in &mut candidate.results {
        result.campaign_id = candidate.campaign.id;
        result.id = Id::new();
    }
    candidate.report.as_mut().unwrap().campaign_id = candidate.campaign.id;
    store.campaign_transition_durable(h.tenant, cancelled.campaign.id, CampaignState::Cancelled, None).await.unwrap();
    let winner = store.campaign_complete_durable(&candidate).await.unwrap();
    assert_eq!(winner.campaign.state, CampaignState::Cancelled);
    assert!(winner.results.is_empty());
    assert!(winner.report.is_none());
    let mut expired = queued(&completed);
    expired.campaign.created_at = Timestamp::now().offset_secs(-601);
    store.campaign_insert_durable(&expired).await.unwrap();
    assert_eq!(
        store.campaign_get_durable(h.tenant, expired.campaign.id).await.unwrap().unwrap().campaign.state,
        CampaignState::Failed
    );
    // Completed evidence is immutable under retries or late cancellation.
    store.campaign_complete_durable(&completed).await.unwrap();
    store.campaign_transition_durable(h.tenant, id, CampaignState::Cancelled, None).await.unwrap();
    assert_eq!(store.campaign_get_durable(h.tenant, id).await.unwrap().unwrap().results[0].id, completed.results[0].id);
    if let Some(db) = db {
        let other = ApiStore::with_database(db);
        let recovered = other.campaign_get_durable(h.tenant, id).await.unwrap().unwrap();
        assert_eq!(serde_json::to_value(recovered).unwrap(), serde_json::to_value(completed).unwrap());
        assert_eq!(
            other.campaign_get_durable(h.tenant, retest_id).await.unwrap().unwrap().comparison,
            retested.comparison
        );
        let started = queued(&candidate);
        store.campaign_insert_durable(&started).await.unwrap();
        let running = store
            .campaign_transition_durable(h.tenant, started.campaign.id, CampaignState::Running, None)
            .await
            .unwrap();
        candidate.campaign.id = running.campaign.id;
        candidate.campaign.created_at = running.campaign.created_at;
        candidate.campaign.started_at = running.campaign.started_at;
        candidate.report.as_mut().unwrap().campaign_id = running.campaign.id;
        for result in &mut candidate.results {
            result.id = Id::new();
            result.campaign_id = running.campaign.id;
        }
        let (completed, cancelled) = tokio::join!(
            store.campaign_complete_durable(&candidate),
            other.campaign_transition_durable(h.tenant, running.campaign.id, CampaignState::Cancelled, None)
        );
        assert_eq!(completed.unwrap().campaign.state, cancelled.unwrap().campaign.state);
        let after = other.campaign_get_durable(h.tenant, running.campaign.id).await.unwrap().unwrap();
        assert_eq!(after.results.len(), if after.campaign.state == CampaignState::Completed { 2 } else { 0 });
        let mut submission = queued(&candidate);
        submission.request_fingerprint = Some(Id::new().to_string());
        let (first, second) =
            tokio::join!(store.campaign_submit_durable(&submission), other.campaign_submit_durable(&submission));
        let (first, created_first) = first.unwrap();
        let (second, created_second) = second.unwrap();
        assert_ne!(created_first, created_second, "Exactly one instance inserts the immutable task");
        assert_eq!(serde_json::to_value(first).unwrap(), serde_json::to_value(second).unwrap());
    }
    verify_submission(&mut h).await;
}

async fn submit(h: &Harness, key: &str, body: Value) -> Resp {
    h.request_with(
        "POST",
        "/api/v1/redteam/campaigns",
        &[
            ("authorization", &format!("Bearer {}", h.admin)),
            ("x-agf-tenant", &h.tenant.to_string()),
            ("idempotency-key", key),
        ],
        Some(body),
    )
    .await
}

async fn verify_submission(h: &mut Harness) {
    h.state.redteam_cases = Arc::new(CaseLibrary::from_cases(cases()));
    h.app = build_router(h.state.clone());
    let input = json!({"name":"durable retry","execution_mode":"simulator","scheduled":true,"guard_strength":100});
    let key = Id::new().to_string();
    let (first, second) = tokio::join!(submit(h, &key, input.clone()), submit(h, &key, input.clone()));
    assert_eq!(first.status, StatusCode::ACCEPTED, "{}", first.text);
    assert_eq!(second.status, StatusCode::ACCEPTED, "{}", second.text);
    assert_eq!(first.json()["task_id"], second.json()["task_id"]);
    let id = first.json()["task_id"].as_str().unwrap().parse().unwrap();
    let done = wait(h, id).await;
    assert!(done.campaign.scheduled);
    assert!(done.request_fingerprint.is_some());
    let forbidden = h
        .request_with(
            "POST",
            "/api/v1/redteam/campaigns",
            &[
                ("authorization", &format!("Bearer {}", h.viewer)),
                ("x-agf-tenant", &h.tenant.to_string()),
                ("idempotency-key", &key),
            ],
            Some(input.clone()),
        )
        .await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);
    let conflict = submit(h, &key, json!({"name":"changed"})).await;
    assert_eq!(conflict.status, StatusCode::CONFLICT);
    h.state.redteam_cases = Arc::new(CaseLibrary::from_cases(vec![]));
    h.app = build_router(h.state.clone());
    let retry = submit(h, &key, input).await;
    assert_eq!(retry.status, StatusCode::ACCEPTED, "{}", retry.text);
    assert_eq!(retry.json()["task_id"], id.to_string());
    assert_eq!(serde_json::to_value(wait(h, id).await).unwrap(), serde_json::to_value(done).unwrap());
    h.state.redteam_cases = Arc::new(CaseLibrary::from_cases(cases()));
    h.app = build_router(h.state.clone());
    let mut selected = std::collections::BTreeSet::new();
    let mut skipped = 0;
    for index in 0..4 {
        let response = submit(
            h,
            &format!("{key}-shard-{index}"),
            json!({"name":"partitioned","scheduled":true,"partition":{"index":index,"total":4}}),
        )
        .await;
        if response.status == StatusCode::OK {
            assert_eq!(response.json()["skipped"], true);
            skipped += 1;
        } else {
            assert_eq!(response.status, StatusCode::ACCEPTED, "{}", response.text);
            let id = response.json()["task_id"].as_str().unwrap().parse().unwrap();
            for case in wait(h, id).await.cases {
                assert!(selected.insert(case.key));
            }
        }
    }
    assert_eq!(selected.len(), 2);
    assert!(skipped >= 2);
    let invalid = submit(h, &format!("{key}-bad"), json!({"name":"bad shard","partition":{"index":1,"total":1}})).await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
    let capped = submit(h, &format!("{key}-cap"), json!({"name":"too small","scheduled":true,"max_cases":1})).await;
    assert_eq!(capped.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn offline_campaign_workflow() {
    Box::pin(verify(setup().await, None)).await;
}

#[tokio::test]
#[ignore = "requires isolated AGF_TEST_DATABASE_URL"]
async fn postgres_campaign_workflow() {
    let url = std::env::var("AGF_TEST_DATABASE_URL").unwrap();
    assert!(url::Url::parse(&url).unwrap().path().starts_with("/agf_requirements_test_"));
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap();
    let database = Database::from_pool(pool);
    database.migrate().await.unwrap();
    let db = Arc::new(Store::new(database, None, Arc::new(MemoryObjectStore::new())));
    let mut h = setup().await;
    h.state.store = Arc::new(ApiStore::with_database(db.clone()));
    h.state.configurations = Arc::new(agf_storage::configuration::ConfigStore::new(Some(db.clone())));
    let tenant = agf_api::tenant_directory::new(format!("campaign-{}", Id::new()), "Campaign durability".into());
    agf_api::tenant_directory::save(&h.state, tenant.clone(), true).await.unwrap();
    h.tenant = tenant.id;
    Box::pin(verify(h, Some(db))).await;
}
