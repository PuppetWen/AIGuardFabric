//! Real action effects through authenticated API calls, including dry-run, release and tenant boundaries.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{enums::AssetKind, ids::Id};
use common::*;

async fn case(h: &Harness) -> (String, Id) {
    seed_ai_assets(h).await;
    let agent = asset_id_of(h, AssetKind::Agent);
    let created = h.post("/api/v1/cases", json!({"title":"真实处置测试","asset_ids":[agent]})).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text);
    (created.json()["case"]["id"].as_str().unwrap().into(), agent)
}
async fn bound_key(h: &Harness, agent: Id) -> (String, String) {
    let response = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":"soar-agent", "bound_agent_id":agent,
        "scopes":["policies:read","models:write"]}),
        )
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.text);
    (response.json()["api_key"]["id"].as_str().unwrap().into(), response.json()["plaintext"].as_str().unwrap().into())
}
fn book(action: &str, params: Value, approved: bool, dry_run: bool) -> Value {
    json!({"approve":approved,"dry_run":dry_run,"playbook":{"key":"test-real-action","name":"真实处置",
        "trigger":{},"steps":[{"name":"执行处置","action":action,"params":params}]}})
}
async fn check(h: &Harness, key: &str, text: &str) -> Resp {
    h.request(
        "POST",
        "/api/v1/runtime/mcp/check",
        Some(key),
        Some(json!({"session_id":"soar-session",
        "frame":{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"url":text}}}})),
    )
    .await
}
#[tokio::test]
async fn isolate_has_real_effect_dry_run_does_not_and_release_restores_access() {
    let h = setup().await;
    let (case, agent) = case(&h).await;
    let (_, key) = bound_key(&h, agent).await;
    let path = format!("/api/v1/cases/{case}/playbook");
    let params = json!({"asset_id":agent,"reason":"确认异常调用"});
    let dry = h.post(&path, book("isolate-agent", params.clone(), false, true)).await;
    assert_eq!(dry.json()["dry_run"], true, "{}", dry.text);
    assert_eq!(check(&h, &key, "safe").await.status, StatusCode::OK);
    let run = h.post(&path, book("isolate-agent", params, false, false)).await;
    assert_eq!(run.json()["has_failure"], false, "{}", run.text);
    assert_eq!(check(&h, &key, "safe").await.status, StatusCode::FORBIDDEN);
    let gateway = h
        .request(
            "POST",
            "/v1/chat/completions",
            Some(&key),
            Some(json!({"model":"irrelevant",
        "messages":[{"role":"user","content":"hello"}]})),
        )
        .await;
    assert_eq!(gateway.status, StatusCode::FORBIDDEN, "{}", gateway.text);
    let audit: Vec<agf_runtime::audit::InterceptionRecord> =
        h.state.configurations.list(h.tenant, "runtime-interception").await.unwrap();
    let denied: Vec<_> = audit
        .iter()
        .filter(|row| row.policy_name.as_deref().is_some_and(|name| name.starts_with("case-containment:")))
        .collect();
    assert_eq!(denied.len(), 2);
    assert!(
        denied
            .iter()
            .all(|row| row.agent_id == Some(agent) && row.verdict == agf_runtime::audit::InterceptionVerdict::Blocked)
    );
    let rows = h.get(&format!("/api/v1/cases/{case}/containments")).await.json();
    let control = rows["items"][0]["id"].as_str().unwrap();
    let release = format!("/api/v1/cases/{case}/containments/{control}/release");
    assert_eq!(h.request("POST", &release, Some(&h.viewer), Some(json!({}))).await.status, StatusCode::FORBIDDEN);
    assert_eq!(h.post(&release, json!({})).await.status, StatusCode::OK);
    assert_eq!(check(&h, &key, "safe").await.status, StatusCode::OK);
    let records: Vec<agf_api::store::SoarRunRecord> = h.state.configurations.list(h.tenant, "soar-run").await.unwrap();
    assert_eq!(records.len(), 2);
}
#[tokio::test]
async fn credential_revocation_requires_human_approval_and_invalidates_authentication() {
    let h = setup().await;
    let (case, agent) = case(&h).await;
    let (key_id, key) = bound_key(&h, agent).await;
    let path = format!("/api/v1/cases/{case}/playbook");
    let params = json!({"api_key_id":key_id});
    let denied = h.post(&path, book("revoke-credential", params.clone(), false, false)).await;
    assert_eq!(denied.json()["outcome"], "not-started");
    assert_eq!(check(&h, &key, "safe").await.status, StatusCode::OK);
    let service = h.post("/api/v1/settings/api-keys", json!({"name":"service","scopes":["*"]})).await;
    let service_key = service.json()["plaintext"].as_str().unwrap().to_owned();
    let fake_approval = h
        .request("POST", &path, Some(&service_key), Some(book("revoke-credential", params.clone(), true, false)))
        .await;
    assert_eq!(fake_approval.status, StatusCode::FORBIDDEN);
    let revoked = h.post(&path, book("revoke-credential", params, true, false)).await;
    assert_eq!(revoked.json()["has_failure"], false, "{}", revoked.text);
    assert_eq!(check(&h, &key, "safe").await.status, StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn domain_block_uses_step_arguments_and_does_not_match_unrelated_hosts() {
    let h = setup().await;
    let (case, agent) = case(&h).await;
    let (_, key) = bound_key(&h, agent).await;
    let run = h
        .post(
            &format!("/api/v1/cases/{case}/playbook"),
            book("block-domain", json!({"domain":"blocked.example"}), true, false),
        )
        .await;
    assert_eq!(run.json()["has_failure"], false, "{}", run.text);
    for url in ["https://blocked.example/data", "https://sub.blocked.example/path"] {
        assert_eq!(check(&h, &key, url).await.status, StatusCode::FORBIDDEN);
    }
    assert_eq!(check(&h, &key, "https://notblocked.example/path").await.status, StatusCode::OK);
    let foreign = h
        .request_with(
            "POST",
            &format!("/api/v1/cases/{case}/playbook"),
            &[("Authorization", &format!("Bearer {}", h.admin)), ("X-AGF-Tenant", &h.other_tenant.to_string())],
            Some(book("block-domain", json!({"domain":"elsewhere.example"}), true, false)),
        )
        .await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND);
}
#[tokio::test]
async fn missing_targets_and_unconfigured_notifications_are_recorded_as_failures() {
    let h = setup().await;
    let (case, _) = case(&h).await;
    for (action, params) in [
        ("revoke-credential", json!({"api_key_id":Id::new()})),
        ("isolate-agent", json!({"asset_id":Id::new()})),
        ("notify-owner", json!({"channel":"webhook"})),
    ] {
        let run = h.post(&format!("/api/v1/cases/{case}/playbook"), book(action, params, true, false)).await;
        assert_eq!(run.status, StatusCode::OK, "{}", run.text);
        assert_eq!(run.json()["has_failure"], true, "{}", run.text);
        assert!(run.json()["steps"][0]["error"].as_str().is_some_and(|error| !error.is_empty()));
    }
}

#[tokio::test]
async fn local_model_control_cannot_fall_back_to_cloud_or_survive_endpoint_removal() {
    let h = setup().await;
    let (case, agent) = case(&h).await;
    let (_, key) = bound_key(&h, agent).await;
    let endpoint = h
        .post(
            "/api/v1/gateway/endpoints",
            json!({"name":"local", "provider":"mock",
        "model":"local-model", "base_url":"http://localhost:18190/v1", "local_deployment":true}),
        )
        .await;
    assert_eq!(endpoint.status, StatusCode::CREATED, "{}", endpoint.text);
    let id = endpoint.json()["id"].as_str().unwrap().to_owned();
    let run = h
        .post(
            &format!("/api/v1/cases/{case}/playbook"),
            book("force-local-model", json!({"asset_id":agent,"endpoint_id":id}), false, false),
        )
        .await;
    assert_eq!(run.json()["has_failure"], false, "{}", run.text);
    let request = json!({"model":"unconfigured-cloud", "messages":[{"role":"user","content":"hello"}]});
    let response = h.request("POST", "/v1/chat/completions", Some(&key), Some(request.clone())).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text);
    assert_eq!(response.json()["model"], "local-model");
    let removed = h
        .request(
            "DELETE",
            &format!("/api/v1/gateway/endpoints/{id}?expected_version={}", endpoint.json()["version"]),
            Some(&h.admin),
            None,
        )
        .await;
    assert_eq!(removed.status, StatusCode::OK);
    assert_eq!(
        h.request("POST", "/v1/chat/completions", Some(&key), Some(request)).await.status,
        StatusCode::PRECONDITION_FAILED
    );
}

#[tokio::test]
async fn mcp_and_skill_inventory_controls_block_tools_and_kill_session_blocks_responses() {
    let h = setup().await;
    let (_, agent) = case(&h).await;
    let (_, key) = bound_key(&h, agent).await;
    for (kind, action) in [(AssetKind::McpServer, "disable-mcp-server"), (AssetKind::Skill, "revoke-skill")] {
        let id = asset_id_of(&h, kind);
        let mut asset = h.state.store.asset_get(h.tenant, id).unwrap().unwrap();
        asset.attributes.insert("tools".into(), json!([{"name":"echo"}]));
        h.state.store.asset_upsert(&asset).unwrap();
        let created = h.post("/api/v1/cases", json!({"title":"工具处置","asset_ids":[id]})).await;
        let case = created.json()["case"]["id"].as_str().unwrap().to_owned();
        let run =
            h.post(&format!("/api/v1/cases/{case}/playbook"), book(action, json!({"asset_id":id}), true, false)).await;
        assert_eq!(run.json()["has_failure"], false, "{}", run.text);
        assert_eq!(check(&h, &key, "safe").await.status, StatusCode::FORBIDDEN);
        let controls = h.get(&format!("/api/v1/cases/{case}/containments")).await.json();
        let control = controls["items"][0]["id"].as_str().unwrap();
        assert_eq!(
            h.post(&format!("/api/v1/cases/{case}/containments/{control}/release"), json!({})).await.status,
            StatusCode::OK
        );
        assert_eq!(check(&h, &key, "safe").await.status, StatusCode::OK);
        let run = h
            .post(
                &format!("/api/v1/cases/{case}/playbook"),
                book("kill-session", json!({"session_id":"stopped-session"}), false, false),
            )
            .await;
        assert_eq!(run.json()["has_failure"], false, "{}", run.text);
        let response = h
            .request(
                "POST",
                "/api/v1/runtime/mcp/check",
                Some(&key),
                Some(json!({"session_id":"stopped-session",
            "response":true, "frame":{"jsonrpc":"2.0","id":1,"result":{"data":"private"}}})),
            )
            .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN);
    }
}

#[tokio::test]
async fn blocked_response_releases_its_concurrency_reservation() {
    let h = setup().await;
    let (case, agent) = case(&h).await;
    let (_, key) = bound_key(&h, agent).await;
    let quota = h
        .post(
            "/api/v1/quotas",
            json!({"name":"one-in-flight","scope":"agent","dimension":"concurrency","window":"total","limit":1}),
        )
        .await;
    assert!(quota.status.is_success(), "{}", quota.text);
    let request = check(&h, &key, "safe").await;
    assert_eq!(request.status, StatusCode::OK);
    let lease = request.json()["lease_id"].clone();
    assert_eq!(check(&h, &key, "safe").await.status, StatusCode::TOO_MANY_REQUESTS);
    let run = h
        .post(&format!("/api/v1/cases/{case}/playbook"), book("isolate-agent", json!({"asset_id":agent}), false, false))
        .await;
    assert_eq!(run.json()["has_failure"], false, "{}", run.text);
    let response = h
        .request(
            "POST",
            "/api/v1/runtime/mcp/check",
            Some(&key),
            Some(json!({"session_id":"soar-session", "lease_id":lease,
        "response":true,"frame":{"jsonrpc":"2.0","id":1,"result":{"text":"safe"}}})),
        )
        .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN, "{}", response.text);
    let usage = h.get("/api/v1/runtime/mcp/usage").await.json();
    assert_eq!(usage["items"][0]["failed"], 1);
    assert_eq!(usage["items"][0]["inflight"], 0);
    let controls = h.get(&format!("/api/v1/cases/{case}/containments")).await.json();
    let id = controls["items"][0]["id"].as_str().unwrap();
    assert_eq!(
        h.post(&format!("/api/v1/cases/{case}/containments/{id}/release"), json!({})).await.status,
        StatusCode::OK
    );
    assert_eq!(check(&h, &key, "safe").await.status, StatusCode::OK);
}
