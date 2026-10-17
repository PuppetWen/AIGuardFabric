//! New and historical APIG carriers have the same public projection; no real cloud is contacted.
mod common;
use agf_api::integration_receipts::Run;
use agf_core::{
    audit::{AuditAction, AuditActor, AuditLog, AuditOutcome, AuditTarget},
    error::{DomainError, DomainResult},
    ids::{Id, deterministic_id},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use common::*;
use secrecy::ExposeSecret;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header_exists, method, path},
};

const BASE: &str = "/api/v1/alicloud/connections/alicloud-apig";
const RUNS: &str = "integration-operation";
const PENDING: &str = "integration-completion";
const PRIVATE: &str = "INDEPENDENT-APIG-PLUGIN-SECRET";

fn provider() -> Value {
    json!({"code":"Success","success":true,"requestId":"owned-apig-provider",
        "data":{"totalCount":1,"items":[{"pluginAttachmentId":"pa-owned","pluginClassName":"ai-security-guard",
            "pluginVersion":"1.0.0","enabled":true,
            "pluginConfig":STANDARD.encode(json!({"accessKey":"INDEPENDENT-APIG-PLUGIN-ID","secretKey":PRIVATE,"checkRequest":true}).to_string()),
            "config":json!({"arbitraryPolicySecret":PRIVATE}).to_string(),
            "authConfig":{"unknown":PRIVATE},"unknownCarrier":{"unknown":PRIVATE}}]}})
}
fn body() -> Value {
    json!({"request_id":Id::new(),"configuration_version":1,"action":"ListPluginAttachments",
        "parameters":{"pageNumber":1,"pageSize":50},"confirm_live":true})
}
fn safe(receipt: &Value) {
    let row = &receipt["response"]["data"]["items"][0];
    assert_eq!(row["pluginAttachmentId"], "pa-owned");
    assert_eq!(row["pluginClassName"], "ai-security-guard");
    assert_eq!(row["enabled"], true);
    assert_eq!(receipt["response"]["data"]["totalCount"], 1);
    for field in ["pluginConfig", "config", "authConfig"] {
        assert_eq!(row[field]["opaque"], true);
        assert_eq!(row[field]["present"], true);
        assert_eq!(row[field]["sha256"].as_str().map(str::len), Some(64));
    }
    assert!(row.get("unknownCarrier").is_none());
    let encoded = provider()["data"]["items"][0]["pluginConfig"].as_str().map(str::to_owned).unwrap_or_default();
    let text = receipt.to_string();
    assert!(!text.contains(PRIVATE));
    assert!(!text.contains(&encoded));
    assert!(!text.contains("OWNED-APIG-SOURCE-SECRET"));
}
async fn live(endpoint: &str) -> DomainResult<Harness> {
    let mut h = setup().await;
    Arc::make_mut(&mut h.state.config).mock_mode = false;
    let tenant = h.tenant;
    h.app = build_router(h.state.clone()).layer(axum::middleware::map_request(move |mut request: Request<Body>| {
        if !request.headers().contains_key("x-agf-tenant") {
            if let Ok(value) = tenant.to_string().parse() {
                request.headers_mut().insert("x-agf-tenant", value);
            }
        }
        async move { request }
    }));
    let response = h
        .request(
            "PUT",
            BASE,
            Some(&h.admin),
            Some(json!({"expected_version":0,"enabled":true,"mock":false,
        "settings":{"endpoint":endpoint,"region_id":"cn-hangzhou"},
        "secrets":{"access_key_id":"OWNED-APIG-SOURCE-ID","access_key_secret":"OWNED-APIG-SOURCE-SECRET"}})),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    Ok(h)
}
async fn snapshot(h: &Harness) -> DomainResult<Value> {
    Ok(json!({"runs":h.state.configurations.list::<Value>(h.tenant,RUNS).await?,
        "pending":h.state.configurations.list::<Value>(h.tenant,PENDING).await?,
        "cloud":h.state.configurations.list::<Value>(h.tenant,"cloud-integration").await?,
        "audit":h.state.store.audit_chain_durable(h.tenant,0,i64::MAX).await?}))
}
fn audit(h: &Harness, run: &Run) -> AuditLog {
    let mut audit = AppState::audit_entry(
        h.tenant,
        AuditAction::Execute,
        AuditOutcome::Success,
        AuditActor::system("owned-apig-original"),
        AuditTarget::new(RUNS, Some(run.id.to_string()), Some(run.adapter.clone())),
        "Owned original APIG completion",
    );
    audit.id = deterministic_id("agf.integration.completion.audit", &format!("{}:{}", h.tenant, run.id));
    audit.request_id = Some(run.request_id.to_string());
    audit.after =
        Some(json!({"run_id":run.id,"request_id":run.request_id,"adapter":run.adapter,"operation":run.operation,
        "configuration_version":run.configuration_version,"mocked":run.mocked,"status":run.status}));
    audit
}
async fn old(h: &Harness, pending: bool) -> DomainResult<Run> {
    let request_id = Id::new();
    let mut run = Run {
        id: deterministic_id("agf.integration.run", &format!("{}:alicloud-apig:{request_id}", h.tenant)),
        request_id,
        adapter: "alicloud-apig".into(),
        operation: "ListPluginAttachments".into(),
        configuration_version: 1,
        request_hash: "a".repeat(64),
        actor: "owned-apig-original".into(),
        started_at: Timestamp::now(),
        finished_at: None,
        status: "started".into(),
        mocked: false,
        result: None,
    };
    let initial = run.clone();
    run.status = "succeeded".into();
    run.finished_at = Some(Timestamp::now());
    run.result =
        Some(agf_api::model_gateway::encrypt(&h.state, h.tenant, run.id, json!({"response":provider()}).to_string())?);
    h.state.configurations.put(h.tenant, RUNS, run.id, if pending { &initial } else { &run }).await?;
    if pending {
        h.state.configurations.put(h.tenant, PENDING, run.id, &json!({"run":run,"audit":audit(h,&run)})).await?;
    }
    Ok(run)
}
async fn decrypted(h: &Harness, id: Id) -> DomainResult<Value> {
    let run = h
        .state
        .configurations
        .get::<Run>(h.tenant, RUNS, id)
        .await?
        .ok_or_else(|| DomainError::Internal("Owned APIG receipt missing".into()))?;
    let secret = run.result.as_ref().ok_or_else(|| DomainError::Internal("Owned APIG receipt unsealed".into()))?;
    let text = agf_api::model_gateway::cipher(&h.state)?.decrypt(secret)?;
    Ok(serde_json::from_str(text.expose_secret())?)
}
#[tokio::test]
async fn actual_signed_list_attachment_projects_before_sealing_and_original_uuid_never_calls_provider_again()
-> DomainResult<()> {
    let server = MockServer::start().await;
    let h = live(&server.uri()).await?;
    Mock::given(method("GET"))
        .and(path("/v1/plugin-attachments"))
        .and(header_exists("authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(provider()))
        .expect(1)
        .mount(&server)
        .await;
    let request = body();
    let first = h.post(&format!("{BASE}/operations"), request.clone()).await;
    assert_eq!(first.status, StatusCode::OK);
    let value = first.json();
    assert_eq!(value["status"], "succeeded");
    assert_eq!(value["completion_state"], "complete");
    safe(&value["receipt"]);
    let id: Id = serde_json::from_value(value["id"].clone())?;
    assert_eq!(decrypted(&h, id).await?, value["receipt"]);
    let before = snapshot(&h).await?;
    assert_eq!(h.post(&format!("{BASE}/operations"), request).await.json(), value);
    assert_eq!(h.get(&format!("{BASE}/operations/{id}")).await.json(), value);
    assert_eq!(snapshot(&h).await?, before);
    assert_eq!(server.received_requests().await.map_or(0, |rows| rows.len()), 1);
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    Ok(())
}
#[tokio::test]
async fn historical_completed_get_and_history_hide_raw_carriers_without_mutating_encrypted_records() -> DomainResult<()>
{
    let h = setup().await;
    let run = old(&h, false).await?;
    let before = snapshot(&h).await?;
    let raw = decrypted(&h, run.id).await?;
    assert!(raw.to_string().contains(PRIVATE));
    for _ in 0..2 {
        let reply = h.get(&format!("{BASE}/operations/{}", run.id)).await;
        assert_eq!(reply.status, StatusCode::OK);
        safe(&reply.json()["receipt"]);
        let history = h.get(&format!("{BASE}/operations")).await;
        assert!(!history.text.contains(PRIVATE));
        assert!(history.json()["items"][0].get("receipt").is_none());
    }
    assert_eq!(snapshot(&h).await?, before);
    assert_eq!(decrypted(&h, run.id).await?, raw);
    Ok(())
}
#[tokio::test]
async fn historical_pending_get_is_pure_and_disabled_source_local_recovery_has_one_original_audit() -> DomainResult<()>
{
    let h = setup().await;
    let run = old(&h, true).await?;
    let endpoint = format!("{BASE}/operations/{}", run.id);
    let before = snapshot(&h).await?;
    let pending = h.get(&endpoint).await;
    assert_eq!(pending.status, StatusCode::OK);
    assert_eq!(pending.json()["completion_state"], "pending_audit");
    assert_eq!(pending.json()["provider_status"], "succeeded");
    safe(&pending.json()["receipt"]);
    assert_eq!(snapshot(&h).await?, before);
    let result = h.request("POST", &format!("{endpoint}/recover"), Some(&h.admin), None).await;
    assert_eq!(result.status, StatusCode::OK);
    assert_eq!(result.json()["completion_state"], "complete");
    assert_eq!(result.json()["status"], "succeeded");
    safe(&result.json()["receipt"]);
    assert!(h.state.configurations.list::<Value>(h.tenant, PENDING).await?.is_empty());
    let after = snapshot(&h).await?;
    assert_eq!(h.request("POST", &format!("{endpoint}/recover"), Some(&h.admin), None).await.json(), result.json());
    assert_eq!(h.get(&endpoint).await.json(), result.json());
    assert_eq!(snapshot(&h).await?, after);
    assert_eq!(
        h.state
            .store
            .audit_chain_durable(h.tenant, 0, i64::MAX)
            .await?
            .iter()
            .filter(|entry| entry.target.kind == RUNS && entry.target.id == Some(run.id.to_string()))
            .count(),
        1
    );
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    Ok(())
}
#[tokio::test]
async fn provider_failure_stays_failed_while_independent_diagnostics_are_omitted() -> DomainResult<()> {
    let server = MockServer::start().await;
    let h = live(&server.uri()).await?;
    Mock::given(method("GET"))
        .and(path("/v1/plugin-attachments"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"Code":"InvalidParameter","Message":PRIVATE})))
        .expect(1)
        .mount(&server)
        .await;
    let response = h.post(&format!("{BASE}/operations"), body()).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json()["status"], "failed");
    assert_eq!(response.json()["completion_state"], "complete");
    assert_eq!(response.json()["receipt"]["error"], "APIG configuration and provider diagnostics were omitted");
    assert!(!response.text.contains(PRIVATE));
    assert_eq!(server.received_requests().await.map_or(0, |rows| rows.len()), 1);
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    Ok(())
}

#[tokio::test]
async fn historical_independent_error_code_is_omitted_without_upgrading_failed_status() -> DomainResult<()> {
    let h = setup().await;
    let mut run = old(&h, false).await?;
    run.status = "failed".into();
    run.result = Some(agf_api::model_gateway::encrypt(
        &h.state,
        h.tenant,
        run.id,
        json!({"response":{"Code":PRIVATE,"Success":false,"Message":PRIVATE}}).to_string(),
    )?);
    h.state.configurations.put(h.tenant, RUNS, run.id, &run).await?;
    let before = snapshot(&h).await?;
    let result = h.get(&format!("{BASE}/operations/{}", run.id)).await;
    assert_eq!(result.status, StatusCode::OK);
    assert_eq!(result.json()["status"], "failed");
    assert_eq!(result.json()["receipt"]["response"]["Code"], "omitted");
    assert_eq!(result.json()["receipt"]["response"]["Success"], false);
    assert!(!result.text.contains(PRIVATE));
    assert_eq!(snapshot(&h).await?, before);
    Ok(())
}
