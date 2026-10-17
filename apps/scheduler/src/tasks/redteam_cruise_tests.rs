use super::*;
use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone)]
struct Fixture {
    id: Id,
    tenant: TenantId,
    submitted: Arc<Mutex<Vec<String>>>,
    polls: Arc<AtomicU64>,
    evidence: Arc<Mutex<Value>>,
}
fn evidence(id: Id, tenant: TenantId) -> Value {
    json!({"format":"agf-redteam-evidence-v1","record":{
        "campaign":{"id":id,"tenant_id":tenant,"state":"completed","scheduled":true,"ci_gate":false,"total_cases":1,"executed_cases":1},
        "execution_mode":"simulator","results":[{"case_key":"CASE-1"}],
        "report":{"campaign_id":id,"tenant_id":tenant,"executed":1,"markdown":"# Saved simulated campaign"}
    }})
}
async fn fixture() -> (CruiseConfig, Fixture, tokio::task::JoinHandle<()>) {
    let id = Id::new();
    let tenant = TenantId::default_tenant();
    let fixture = Fixture {
        id,
        tenant,
        submitted: Arc::new(Mutex::new(vec![])),
        polls: Arc::new(AtomicU64::new(0)),
        evidence: Arc::new(Mutex::new(evidence(id, tenant))),
    };
    let app = Router::new()
        .route(
            "/api/v1/redteam/campaigns",
            post(|State(f): State<Fixture>, headers: HeaderMap, Json(payload): Json<Value>| async move {
                assert_eq!(headers["x-agf-key"], "service-test-key");
                assert_eq!(headers["x-agf-tenant"], f.tenant.to_string());
                assert_eq!(payload["execution_mode"], "simulator");
                assert_eq!(payload["partition"], json!({"index":1,"total":2}));
                f.submitted.lock().unwrap().push(headers["idempotency-key"].to_str().unwrap().into());
                Json(json!({"task_id":f.id}))
            }),
        )
        .route(
            "/api/v1/redteam/campaigns/{id}",
            get(|State(f): State<Fixture>, headers: HeaderMap| async move {
                assert_eq!(headers["x-agf-key"], "service-test-key");
                let first = f.polls.fetch_add(1, Ordering::SeqCst) == 0;
                Json(json!({"campaign":{"id":f.id,"state":if first {"queued"}else{"completed"}}}))
            }),
        )
        .route(
            "/api/v1/redteam/campaigns/{id}/evidence",
            get(|State(f): State<Fixture>| async move { Json(f.evidence.lock().unwrap().clone()) }),
        )
        .with_state(fixture.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (
        CruiseConfig {
            server,
            auth: Some(ApiAuth::ApiKey("service-test-key".into())),
            tenant,
            output: std::env::temp_dir().join(format!("agf-cruise-test-{id}")),
            guard: 30,
        },
        fixture,
        task,
    )
}

#[tokio::test]
async fn retries_use_same_platform_task_and_preserve_evidence() {
    let (config, fixture, server) = fixture().await;
    let client = reqwest::Client::new();
    for _ in 0..2 {
        let outcome = crate::dispatch::EXECUTION_ID
            .scope(
                "cloud:app:job:run".into(),
                run_redteam_cruise(&client, &config, crate::Partition { index: 1, total: 2 }),
            )
            .await;
        assert!(outcome.ok, "{}", outcome.note);
        assert_eq!(outcome.artifacts.len(), 2);
        assert!(outcome.note.contains("未启用 CI"));
    }
    let keys = fixture.submitted.lock().unwrap().clone();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], keys[1]);
    let path = config.output.join(format!("redteam-cruise-{}.json", fixture.id));
    let saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(saved, *fixture.evidence.lock().unwrap());
    // A retry must not overwrite an existing artifact whose contents have changed.
    std::fs::write(&path, b"changed outside this run").unwrap();
    let outcome =
        run(&client, &config, crate::Partition { index: 1, total: 2 }, "cloud:app:job:run").await.unwrap_err();
    assert!(outcome.to_string().contains("停止覆盖"));
    assert_eq!(std::fs::read(&path).unwrap(), b"changed outside this run");
    server.abort();
    std::fs::remove_dir_all(config.output).unwrap();
}

#[tokio::test]
async fn unknown_identity_or_incomplete_evidence_never_succeeds() {
    let (mut config, fixture, server) = fixture().await;
    let client = reqwest::Client::new();
    assert!(!run_redteam_cruise(&client, &config, crate::Partition::default()).await.ok);
    let mut invalid = evidence(fixture.id, fixture.tenant);
    invalid["record"]["campaign"]["executed_cases"] = 0.into();
    assert!(archive(&config, fixture.id, &invalid).is_err());
    invalid = evidence(fixture.id, fixture.tenant);
    invalid["record"]["campaign"]["tenant_id"] = Id::new().to_string().into();
    assert!(archive(&config, fixture.id, &invalid).is_err());
    assert!(!config.output.exists());
    config.auth = None;
    assert!(
        run(&client, &config, crate::Partition::default(), "local:1")
            .await
            .unwrap_err()
            .to_string()
            .contains("API Key")
    );
    assert!(fixture.submitted.lock().unwrap().is_empty());
    server.abort();
}
