//! Missing cloud keys use the actual Mock adapter with a durable zero-cost, explicitly mocked receipt.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod configuration_audit_support;
mod gateway_no_key_database_support;
use agf_core::{audit::AuditOutcome, error::DomainResult, ids::Id};
use common::*;
use gateway_no_key_database_support::*;
use wiremock::MockServer;

async fn endpoint(h: &Harness, provider: &str, model: &str, origin: &str, key: Option<&str>) -> Value {
    let mut body = json!({"expected_version":0,"name":"owned-no-key","provider":provider,"model":model,
        "base_url":origin,"pricing":{"prompt_micro_per_1k":2000,"completion_micro_per_1k":8000,"cached_prompt_micro_per_1k":500}});
    if let Some(key) = key {
        body["api_key"] = json!(key);
    }
    let response = h.post("/api/v1/gateway/endpoints", body).await;
    assert_eq!(response.status, StatusCode::CREATED);
    response.json()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned AGF_NO_KEY_DATABASE_OWNER and AGF_TEST_DATABASE_URL"]
async fn no_key_mock_commits_zero_cost_usage_both_ledgers_and_mock_audit_then_restart_is_pure() -> DomainResult<()> {
    let owned = Owned::open("no-key-atomic").await?;
    let h = owned.live_instance(false).await?;
    let server = MockServer::start().await;
    endpoint(&h, "anthropic", "owned-no-key", &server.uri(), None).await;
    let issued = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":"no-key-original-client",
        "scopes":["models:read","models:write"],"expires_in_secs":3600}),
        )
        .await;
    assert_eq!(issued.status, StatusCode::CREATED);
    let token = issued.json()["plaintext"].as_str().unwrap().to_string();
    let response = h
        .request(
            "POST",
            "/v1/messages",
            Some(&token),
            Some(json!({"model":"owned-no-key","temperature":1,"max_tokens":32,
        "messages":[{"role":"user","content":"hello no key"}]})),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.header("x-agf-mocked"), "true");
    let id = Id::parse(&response.header("x-agf-attempt-id"))?;
    let path = format!("/api/v1/gateway/attempts/{id}");
    let receipt = h.request("GET", &path, Some(&token), None).await.json();
    assert_eq!(receipt["state"], "settled");
    // Existing evidence names describe adapter completion; mocked=true and the listener prove no cloud transport.
    assert_eq!(receipt["outcomeEvidence"], "sent-usage-known");
    assert_eq!(receipt["chargeState"], "actual");
    assert_eq!(receipt["mayExecute"], false);
    let rows: Vec<agf_core::model::UsageRecord> =
        h.state.configurations.list(h.tenant, agf_api::gateway_quota::USAGE).await?;
    assert_eq!(rows.len(), 1);
    assert!(rows[0].mocked);
    assert_eq!(rows[0].cost_micro, 0);
    assert!(rows[0].total_tokens() > 0);
    let key = agf_api::model_routes::tenant_record_id(h.tenant);
    let gateway: Value = h.state.configurations.get(h.tenant, "gateway-ledger", key).await?.unwrap();
    assert_eq!(gateway["totals"]["cost"], 0);
    assert!(gateway["reservations"].as_object().unwrap().is_empty());
    let runtime: Value = h.state.configurations.get(h.tenant, "runtime-quota-ledger", key).await?.unwrap();
    assert!(runtime["reservations"].as_object().unwrap().is_empty());
    let terminal = owned.terminal(&h, id).await?;
    assert_eq!(terminal.len(), 1);
    assert_eq!(terminal[0].outcome, AuditOutcome::Success);
    assert_eq!(terminal[0].after.as_ref().unwrap()["mocked"], true);
    assert_eq!(terminal[0].after.as_ref().unwrap()["usageId"], json!(rows[0].id));
    let before = owned.rows(&h).await?;
    let audits = h.state.store.audit_stats_durable(h.tenant).await?;
    let second = owned.live_instance(true).await?;
    assert!(
        second.request("GET", &path, Some(&token), None).await.json() == receipt,
        "Restart must retain the original receipt"
    );
    assert!(
        second.request("POST", &format!("{path}/recover"), Some(&token), Some(json!({}))).await.json() == receipt,
        "Local recovery must not replace committed evidence"
    );
    assert!(owned.rows(&h).await? == before, "Receipt GET/recovery must not write rows");
    assert_eq!(h.state.store.audit_stats_durable(h.tenant).await?, audits);
    assert!(server.received_requests().await.unwrap().is_empty());
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    owned.verify().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact-owned AGF_NO_KEY_DATABASE_OWNER and AGF_TEST_DATABASE_URL"]
async fn encrypted_credential_failure_commits_not_sent_failure_without_mock_usage_or_provider() -> DomainResult<()> {
    let owned = Owned::open("no-key-corrupt").await?;
    let h = owned.live_instance(false).await?;
    let server = MockServer::start().await;
    let endpoint = endpoint(&h, "openai", "owned-corrupt", &server.uri(), Some("synthetic-private-key")).await;
    let endpoint_id = Id::parse(endpoint["id"].as_str().unwrap())?;
    let mut row: agf_api::model_gateway::StoredEndpoint =
        h.state.configurations.get(h.tenant, agf_api::model_gateway::ENDPOINT_KIND, endpoint_id).await?.unwrap();
    row.secret.as_mut().unwrap().aad = Some("wrong-authenticated-binding".into());
    h.state.configurations.put(h.tenant, agf_api::model_gateway::ENDPOINT_KIND, endpoint_id, &row).await?;
    let response = h
        .post(
            "/v1/chat/completions",
            json!({"model":"owned-corrupt","temperature":1,"max_tokens":32,
        "messages":[{"role":"user","content":"hello no key"}]}),
        )
        .await;
    assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response.header("x-agf-mocked"), "");
    assert!(!response.text.contains("synthetic-private-key"));
    let id = Id::parse(&response.header("x-agf-attempt-id"))?;
    let receipt = h.get(&format!("/api/v1/gateway/attempts/{id}")).await.json();
    assert_eq!(receipt["state"], "settled");
    assert_eq!(receipt["outcomeEvidence"], "not-sent");
    let terminal = owned.terminal(&h, id).await?;
    assert_eq!(terminal.len(), 1);
    assert_eq!(terminal[0].outcome, AuditOutcome::Failure);
    assert!(terminal[0].after.as_ref().unwrap()["mocked"].is_null());
    let rows: Vec<agf_core::model::UsageRecord> =
        h.state.configurations.list(h.tenant, agf_api::gateway_quota::USAGE).await?;
    assert!(rows.is_empty());
    assert!(server.received_requests().await.unwrap().is_empty());
    assert!(h.state.store.audit_verify_durable(h.tenant).await?.passed);
    owned.verify().await
}
