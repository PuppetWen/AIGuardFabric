//! 真实 HTTP 路由、绑定 Key、租户隔离、已签策略和离线脱敏审计；不启动宿主进程。
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use agf_core::{
    enums::AssetKind,
    ids::Id,
    process_hook::{ProcessMode, ProcessRequest, ProcessSource},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use common::*;
async fn fixture() -> (Harness, Id, String) {
    let h = setup().await;
    assert_eq!(seed_ai_assets(&h).await.status, StatusCode::OK);
    let agent = asset_id_of(&h, AssetKind::Agent);
    let key = h
        .post(
            "/api/v1/settings/api-keys",
            json!({"name":"owned-process-agent","scopes":["policies:read"],"bound_agent_id":agent}),
        )
        .await;
    assert_eq!(key.status, StatusCode::CREATED, "{}", key.text);
    let key = key.json()["plaintext"].as_str().unwrap().to_owned();
    (h, agent, key)
}
fn body(agent: Id, mode: ProcessMode) -> ProcessRequest {
    ProcessRequest {
        request_id: Id::new(),
        agent_id: agent,
        mode,
        source: if mode == ProcessMode::Launch {
            ProcessSource::ManagedLauncher
        } else {
            ProcessSource::LinuxSchedExec
        },
        executable_b64: STANDARD.encode(b"/owned/private/process-secret"),
        arguments: if mode == ProcessMode::Launch {
            vec!["--api-key=owned-credential-must-not-be-audited".into()]
        } else {
            Vec::new()
        },
        executable_sha256: if mode == ProcessMode::Launch { Some("a".repeat(64)) } else { None },
        pid: if mode == ProcessMode::Observe { Some(77) } else { None },
        uid: None,
        monotonic_ns: None,
        truncated: false,
        lost: 0,
    }
}
async fn send(h: &Harness, key: &str, body: &ProcessRequest) -> Resp {
    h.request_with(
        "POST",
        "/api/v1/runtime/process/check",
        &[("X-AGF-Key", key)],
        Some(serde_json::to_value(body).unwrap()),
    )
    .await
}
#[tokio::test]
async fn bound_agent_key_tenant_and_original_nonce_are_required_and_observation_never_admits_launch() {
    let (h, agent, key) = fixture().await;
    let request = body(agent, ProcessMode::Launch);
    assert_eq!(
        h.post("/api/v1/runtime/process/check", serde_json::to_value(&request).unwrap()).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(send(&h, &h.api_key, &request).await.status, StatusCode::FORBIDDEN);
    let mut wrong = request.clone();
    wrong.agent_id = Id::new();
    assert_eq!(send(&h, &key, &wrong).await.status, StatusCode::FORBIDDEN);
    let other = h.other_tenant.to_string();
    assert_eq!(
        h.request_with(
            "POST",
            "/api/v1/runtime/process/check",
            &[("X-AGF-Key", &key), ("X-AGF-Tenant", &other)],
            Some(serde_json::to_value(&request).unwrap())
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    let mut spoof = serde_json::to_value(&request).unwrap();
    spoof["tenant_id"] = json!(h.other_tenant);
    assert_eq!(
        h.request_with("POST", "/api/v1/runtime/process/check", &[("X-AGF-Key", &key)], Some(spoof)).await.status,
        StatusCode::BAD_REQUEST
    );
    let admitted = send(&h, &key, &request).await;
    assert_eq!(admitted.status, StatusCode::OK, "{}", admitted.text);
    assert_eq!(admitted.json()["launch_allowed"], true);
    assert_eq!(admitted.json()["request_sha256"], request.digest().unwrap());
    assert_eq!(admitted.json()["audit_committed"], true);
    assert_eq!(admitted.json()["enforced"], false);
    assert_eq!(send(&h, &key, &request).await.status, StatusCode::CONFLICT);
    let observed = send(&h, &key, &body(agent, ProcessMode::Observe)).await;
    assert_eq!(observed.status, StatusCode::OK, "{}", observed.text);
    assert_eq!(observed.json()["launch_allowed"], false);
    assert_eq!(observed.json()["enforced"], false);
}
#[tokio::test]
async fn current_signed_process_policy_blocks_and_both_audit_stores_omit_original_path_arguments_and_reason() {
    let (h, agent, key) = fixture().await;
    let policy=h.post("/api/v1/policies",json!({"name":"owned-private-process-policy","language":"cel",
        "source":"{\"action\":\"deny\",\"reason\":\"owned-credential-must-not-be-audited\"}","action":"deny","enabled":true,"intercept_points":["process-hook"]})).await;
    assert_eq!(policy.status, StatusCode::CREATED, "{}", policy.text);
    let request = body(agent, ProcessMode::Launch);
    let denied = send(&h, &key, &request).await;
    assert_eq!(denied.status, StatusCode::OK, "{}", denied.text);
    assert_eq!(denied.json()["launch_allowed"], false);
    assert_eq!(denied.json()["action"], "deny");
    assert_eq!(denied.json()["audit_committed"], true);
    let rows: Vec<Value> = h.state.configurations.list(h.tenant, "runtime-interception").await.unwrap();
    assert!(rows.iter().any(|r| r["intercept_point"] == "process-hook" && r["agent_id"] == agent.to_string()));
    let persisted = serde_json::to_string(&rows).unwrap();
    let runtime = h.get("/api/v1/runtime/events").await;
    assert_eq!(runtime.status, StatusCode::OK, "{}", runtime.text);
    assert!(runtime.json().as_array().unwrap().iter().any(|row| row["id"] == denied.json()["audit_id"]));
    for text in [&persisted, &runtime.text, &denied.text] {
        assert!(!text.contains("/owned/private/process-secret"));
        assert!(!text.contains("owned-credential-must-not-be-audited"));
        assert!(!text.contains(&request.executable_b64));
        assert!(!text.contains(&key));
    }
    let audits = h.get("/api/v1/audit?action=execute").await;
    assert_eq!(audits.status, StatusCode::OK, "{}", audits.text);
    assert!(
        !audits.text.contains("/owned/private/process-secret")
            && !audits.text.contains("owned-credential-must-not-be-audited")
    );
}
#[tokio::test]
async fn malformed_and_lost_process_events_cannot_forge_launch_authority_or_unbounded_work() {
    let (h, agent, key) = fixture().await;
    let mut bad = body(agent, ProcessMode::Observe);
    bad.arguments.push("invented-argv".into());
    assert_eq!(send(&h, &key, &bad).await.status, StatusCode::BAD_REQUEST);
    let mut bad = body(agent, ProcessMode::Launch);
    bad.arguments = vec!["x".repeat(4097)];
    assert_eq!(send(&h, &key, &bad).await.status, StatusCode::BAD_REQUEST);
    let mut lost = body(agent, ProcessMode::Observe);
    lost.mode = ProcessMode::Loss;
    lost.executable_b64.clear();
    lost.pid = None;
    lost.lost = 9;
    let reported = send(&h, &key, &lost).await;
    assert_eq!(reported.status, StatusCode::OK, "{}", reported.text);
    assert_eq!(reported.json()["launch_allowed"], false);
    assert_eq!(reported.json()["enforced"], false);
}

#[tokio::test]
async fn published_process_schema_grants_match_real_bound_route_and_closed_receipt() {
    let (h, agent, key) = fixture().await;
    let response = h.get("/api/v1/openapi.json").await;
    assert_eq!(response.status, StatusCode::OK);
    let document = response.json();
    let operation = &document["paths"]["/api/v1/runtime/process/check"]["post"];
    assert_eq!(operation["security"], json!([{"apiKey":[]}]));
    assert_eq!(operation["x-required-permissions"], json!(["policies:read"]));
    assert_eq!(operation["x-required-agent-binding"], true);
    assert_eq!(operation["x-deadline-ms"], 3000);
    let description = operation["description"].as_str().unwrap();
    for boundary in ["enforced=false", "offline", "三秒", "未知 ACK", "原路径/参数", "事后观察"] {
        assert!(description.contains(boundary));
    }
    for status in ["200", "400", "401", "403", "409", "412", "500", "503", "504"] {
        assert!(operation["responses"].get(status).is_some());
    }
    let request = &document["components"]["schemas"]["ProcessRequest"];
    assert_eq!(request["oneOf"].as_array().unwrap().len(), 3);
    assert_eq!(request["discriminator"]["propertyName"], "mode");
    let schemas = request["oneOf"].as_array().unwrap();
    for (mode, schema) in ["launch", "observe", "loss"].into_iter().zip(schemas) {
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["mode"]["enum"], json!([mode]));
        assert!(schema["properties"].get("tenant_id").is_none());
    }
    assert_eq!(schemas[0]["properties"]["arguments"]["maxItems"], 64);
    assert_eq!(schemas[0]["properties"]["arguments"]["x-max-total-utf8-bytes"], 16384);
    assert_eq!(schemas[1]["properties"]["arguments"]["maxItems"], 0);
    assert_eq!(schemas[2]["properties"]["lost"]["minimum"], 1);
    let actual = send(&h, &key, &body(agent, ProcessMode::Launch)).await;
    assert_eq!(actual.status, StatusCode::OK, "{}", actual.text);
    let actual = actual.json();
    let receipt = &document["components"]["schemas"]["ProcessReceipt"];
    assert_eq!(receipt["additionalProperties"], false);
    let properties = receipt["properties"].as_object().unwrap();
    assert_eq!(actual.as_object().unwrap().len(), properties.len());
    for field in receipt["required"].as_array().unwrap() {
        assert!(actual.get(field.as_str().unwrap()).is_some());
    }
    for (key, value) in actual.as_object().unwrap() {
        let rule = properties.get(key).unwrap();
        if let Some(variants) = rule["enum"].as_array() {
            assert!(variants.contains(value));
        }
    }
    let unauth = h
        .request_with(
            "POST",
            "/api/v1/runtime/process/check",
            &[],
            Some(serde_json::to_value(body(agent, ProcessMode::Launch)).unwrap()),
        )
        .await;
    assert_eq!(unauth.status, StatusCode::UNAUTHORIZED);
}
