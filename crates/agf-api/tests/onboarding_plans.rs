//! Plans must match published artifacts, shells and permissions.
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;
use common::*;
use sha2::{Digest, Sha256};

#[tokio::test]
async fn onboarding_checks_publication_platforms_and_origin() {
    let mut h = setup().await;
    let root = std::path::PathBuf::from(&h.state.config.data_dir).join("onboarding-artifact-fixture");
    Arc::make_mut(&mut h.state.config).project_root = root.to_string_lossy().into();
    h.app = build_router(h.state.clone());
    let path = "/api/v1/agents/onboarding-plan";
    for platform in ["windows-amd64", "linux-amd64", "macos-arm64"] {
        let result = h
            .post(path, json!({"platform":platform,"locale":"en-US","publicBase":"https://console.example.test:8443"}))
            .await;
        assert_eq!(result.status, StatusCode::OK, "{}", result.text);
        let body = result.json();
        assert!(body["artifact_url"].is_null());
        assert!(body["estimated_downtime_sec"].is_null());
        assert!(body["steps"][0]["command"].as_str().unwrap().contains("cargo build"));
        assert_eq!(body["endpoint"], "https://console.example.test:8443/api/v1/ingest/agent");
        let env = body["env_snippet"].as_str().unwrap();
        assert_eq!(env.contains("$env:"), platform == "windows-amd64");
        assert_eq!(env.contains("export AGF_"), platform != "windows-amd64");
        assert!(env.contains("AGF_AGENT_PROJECT_ROOTS="), "项目 MCP 发现步骤应出现在采集计划中");
        assert!(!result.text.contains("agf-sidecar"));
    }
    tokio::fs::create_dir_all(root.join("dist/windows")).await.unwrap();
    let bytes = b"published artifact fixture, never executed";
    tokio::fs::write(root.join("dist/windows/agf-agent.exe"), bytes).await.unwrap();
    let published = h.post(path, json!({"platform":"windows-amd64"})).await.json();
    assert_eq!(published["artifact_url"], "/downloads/agents/windows-amd64");
    let digest = hex::encode(Sha256::digest(bytes));
    assert_eq!(published["artifact_sha256"], digest);
    assert!(published["steps"][0]["command"].as_str().unwrap().contains(&digest));
    assert_eq!(h.get("/downloads/agents/windows-amd64").await.bytes, bytes);
    for mode in ["sdk-inject", "gateway-register"] {
        let result = h.post(path, json!({"mode":mode,"platform":"linux-amd64","locale":"en-US"})).await;
        assert_eq!(result.status, StatusCode::OK, "{}", result.text);
        assert!(result.json()["artifact_url"].is_null());
        assert!(result.json()["estimated_downtime_sec"].is_null());
        assert_eq!(result.json()["rollout"], "manual");
        assert_eq!(result.json()["ready"], false);
        assert_eq!(result.json()["target"], if mode == "sdk-inject" { "python-startup" } else { "model-openai" });
        assert!(!result.text.contains("chat/completions"));
        assert!(!result.text.contains("agf-agent"));
    }
    for invalid in [
        json!({"platform":"../secret"}),
        json!({"kind":"mcp"}),
        json!({"locale":"bad"}),
        json!({"publicBase":"https://user:secret@example.test"}),
        json!({"publicBase":"https://example.test/path"}),
        json!({"publicBase":"file:///tmp"}),
        json!({"publicBase":"https://example.test/?command=rm"}),
    ] {
        assert_eq!(h.post(path, invalid).await.status, StatusCode::BAD_REQUEST);
    }
    assert_eq!(h.request("POST", path, None, Some(json!({}))).await.status, StatusCode::UNAUTHORIZED);
    for (scope, status) in [("assets:read", StatusCode::FORBIDDEN), ("agents:read", StatusCode::OK)] {
        let key = h
            .post(
                "/api/v1/settings/api-keys",
                json!({"name":"onboarding-scope",
            "scopes":[scope],"expires_in_secs":3600}),
            )
            .await
            .json();
        // Plan generation is read-only; execution uses a separately scoped key.
        assert_eq!(h.request("POST", path, key["plaintext"].as_str(), Some(json!({}))).await.status, status);
    }
}
