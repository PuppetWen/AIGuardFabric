//! 由 `discovery.rs` 拆分：`report` 等 18 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn report() -> AgentReport {
    AgentReport {
        collector_id: "collector-1".into(),
        collected_at: Timestamp::now(),
        hostname: "dev-pc".into(),
        os: "windows".into(),
        os_user: Some("alice".into()),
        agents: vec![DetectedAgent {
            flavor: AgentFlavor::ClaudeCode,
            version: Some("1.9.0".into()),
            binary_path: Some("C:/Users/alice/AppData/Local/claude/claude.exe".into()),
            config_dir: Some("C:/Users/alice/.claude".into()),
            config_hash: Some("abc123".into()),
        }],
        mcp_configs: vec![
            DetectedMcp {
                source_file: "C:/Users/alice/.claude.json".into(),
                server_name: "filesystem".into(),
                transport: "stdio".into(),
                command: Some("npx".into()),
                args: vec!["-y".into(), "@modelcontextprotocol/server-filesystem".into()],
                url: None,
                env_keys: vec![],
                has_plaintext_secret: false,
                auth_configured: false,
            },
            DetectedMcp {
                source_file: "C:/Users/alice/.claude.json".into(),
                server_name: "remote-mcp".into(),
                transport: "http".into(),
                command: None,
                args: vec![],
                url: Some("http://8.8.8.8:8091/mcp".into()),
                env_keys: vec!["MCP_TOKEN".into()],
                has_plaintext_secret: true,
                auth_configured: false,
            },
        ],
        credential_hits: vec![DetectedCredential {
            source_file: "C:/Users/alice/.claude.json".into(),
            line: 12,
            kind: "openai_key".into(),
            masked: "sk-p***cdef".into(),
            context: None,
            confidence: 0.95,
        }],
        scan_scope: vec!["%USERPROFILE%\\.claude.json".into()],
        agent_version: "0.1.0".into(),
    }
}

#[test]
pub(crate) fn agent_report_conversion_produces_expected_assets() {
    let batch = DiscoveryBatch::from_agent_report(TenantId::default_tenant(), &report());
    // 1 Agent + 2 MCP
    assert_eq!(batch.assets.len(), 3);
    assert_eq!(batch.source, Some(DiscoverySource::AgentReport));
    assert_eq!(batch.credentials.len(), 1);
    let agent = batch.assets.iter().find(|a| a.kind == AssetKind::Agent);
    assert!(agent.is_some());
    let Some(agent) = agent else { return };
    assert!(agent.fingerprint.starts_with("agent|claude-code|dev-pc|alice"));
    assert_eq!(agent.host.as_deref(), Some("dev-pc"));
    assert_eq!(agent.owner.as_deref(), Some("alice"));
}

#[test]
pub(crate) fn remote_mcp_with_token_gets_exposure_but_reduced_unauthenticated() {
    let batch = DiscoveryBatch::from_agent_report(TenantId::default_tenant(), &report());
    let remote = batch.assets.iter().find(|a| a.name == "remote-mcp");
    assert!(remote.is_some());
    let Some(remote) = remote else { return };
    assert!(remote.requires_auth, "env 中含 TOKEN 视为需要认证");
    assert!(remote.has_plaintext_secret);
    assert!(remote.exposure_score >= 25, "公网地址应有暴露面得分: {}", remote.exposure_score);
    assert!(remote.exposure_items.iter().any(|(k, _)| k == "publicly_reachable"));
}

#[test]
pub(crate) fn stdio_mcp_endpoint_encodes_command() {
    let batch = DiscoveryBatch::from_agent_report(TenantId::default_tenant(), &report());
    let fs = batch.assets.iter().find(|a| a.name == "filesystem");
    let Some(fs) = fs else { return };
    let ep = fs.endpoint.clone().unwrap_or_default();
    assert!(ep.starts_with("stdio:npx"), "{ep}");
    assert!(ep.contains("server-filesystem"));
}

#[test]
pub(crate) fn report_warnings_flag_plaintext_secret() {
    let batch = DiscoveryBatch::from_agent_report(TenantId::default_tenant(), &report());
    assert!(batch.warnings.iter().any(|w| w.contains("明文凭据")));
}

#[test]
pub(crate) fn header_auth_from_agent_is_not_scored_as_unauthenticated() {
    let mut sample = report();
    let remote = &mut sample.mcp_configs[1];
    remote.env_keys.clear();
    remote.auth_configured = true;
    let batch = DiscoveryBatch::from_agent_report(TenantId::default_tenant(), &sample);
    let asset = batch.assets.iter().find(|a| a.name == "remote-mcp");
    assert!(asset.is_some(), "MCP asset must be discovered");
    let Some(asset) = asset else { return };
    assert!(asset.requires_auth);
    assert!(!asset.exposure_items.iter().any(|(item, _)| item == "unauthenticated"));
    assert!(batch.warnings.iter().all(|warning| !warning.contains("env 键")));
}

#[test]
pub(crate) fn legacy_agent_report_is_sanitized_before_asset_persistence() {
    let mut sample = report();
    let remote = &mut sample.mcp_configs[1];
    remote.url = Some("https://user:private-url@mcp.example.invalid/mcp?token=private-query".into());
    remote.env_keys.clear();
    remote.auth_configured = false;
    remote.has_plaintext_secret = false;
    let local = &mut sample.mcp_configs[0];
    local.args = vec!["--api-key".into(), "private-argument".into()];
    let batch = DiscoveryBatch::from_agent_report(TenantId::default_tenant(), &sample);
    let remote = batch.assets.iter().find(|asset| asset.name == "remote-mcp");
    assert!(remote.is_some());
    let Some(remote) = remote else { return };
    assert_eq!(remote.endpoint.as_deref(), Some("https://mcp.example.invalid/mcp"));
    assert!(remote.requires_auth);
    assert!(remote.has_plaintext_secret);
    let serialized = serde_json::to_string(&batch).unwrap_or_default();
    for secret in ["private-url", "private-query", "private-argument"] {
        assert!(!serialized.contains(secret), "旧版 Agent 上报也不得把原始凭据写入资产");
    }
}

#[test]
pub(crate) fn mcp_config_parsing_handles_wrapped_and_bare_shapes() {
    let wrapped = r#"{"mcpServers":{"fs":{"command":"npx","args":["-y","x"],"env":{"API_KEY":"sk-x"}}}}"#;
    let parsed = parse_mcp_config(wrapped);
    assert!(parsed.is_ok());
    let Ok(list) = parsed else { return };
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].0, "fs");
    assert_eq!(list[0].1, McpTransport::Stdio);
    assert_eq!(list[0].5, vec!["API_KEY".to_string()]);

    let bare = r#"{"srv":{"url":"https://x/mcp"}}"#;
    let Ok(list2) = parse_mcp_config(bare) else { return };
    assert_eq!(list2.len(), 1);
    assert_eq!(list2[0].1, McpTransport::Http);
}

#[test]
pub(crate) fn mcp_config_parsing_detects_sse_and_invalid() {
    let sse = r#"{"mcpServers":{"s":{"url":"https://x/sse"}}}"#;
    let Ok(list) = parse_mcp_config(sse) else { return };
    assert_eq!(list[0].1, McpTransport::Sse);
    assert!(parse_mcp_config("{not json").is_err());
    assert!(parse_mcp_config(r#"{"other":1}"#).is_err());
}

#[test]
pub(crate) fn config_file_kind_detection() {
    assert_eq!(ConfigFileKind::detect(Path::new("claude_desktop_config.json")), ConfigFileKind::ClaudeDesktop);
    assert_eq!(ConfigFileKind::detect(Path::new(".mcp.json")), ConfigFileKind::McpJson);
    assert_eq!(ConfigFileKind::detect(Path::new(".env")), ConfigFileKind::DotEnv);
    assert_eq!(ConfigFileKind::detect(Path::new("config.yaml")), ConfigFileKind::GenericJson);
    assert_eq!(ConfigFileKind::detect(Path::new("main.rs")), ConfigFileKind::SourceCode);
    assert!(ConfigFileKind::McpJson.is_config());
    assert!(!ConfigFileKind::SourceCode.is_config());
}

#[test]
pub(crate) fn git_scanner_finds_mcp_and_credentials_in_local_dir() {
    let dir = std::env::temp_dir().join(format!("agf-git-scan-{}", uuid::Uuid::new_v4()));
    assert!(std::fs::create_dir_all(&dir).is_ok());
    let mcp_path = dir.join(".mcp.json");
    assert!(
        std::fs::write(&mcp_path, r#"{"mcpServers":{"filesystem":{"command":"npx","args":["-y","@mcp/fs"]}}}"#).is_ok()
    );
    let code_path = dir.join("config.py");
    assert!(std::fs::write(&code_path, "OPENAI_API_KEY = \"sk-proj-AbCdEfGhIjKlMnOpQrStUvWx\"\n").is_ok());
    let noise_dir = dir.join("node_modules");
    assert!(std::fs::create_dir_all(&noise_dir).is_ok());
    assert!(std::fs::write(noise_dir.join(".mcp.json"), r#"{"mcpServers":{"skip":{"command":"x"}}}"#).is_ok());

    let scanner = GitScanner::new();
    let batch = scanner.scan_local(TenantId::default_tenant(), &dir);
    assert!(batch.is_ok(), "{:?}", batch.err().map(|e| e.to_string()));
    let Ok(batch) = batch else { return };
    assert_eq!(batch.assets.len(), 1, "应只发现 1 个 MCP（node_modules 被跳过）");
    assert_eq!(batch.assets[0].name, "filesystem");
    assert_eq!(batch.assets[0].discovery_source, DiscoverySource::GitScan);
    assert!(
        batch.credentials.iter().any(|c| c.pattern == "openai_key"),
        "应检出硬编码 OpenAI Key: {:?}",
        batch.credentials
    );
    assert!(batch.warnings.iter().any(|w| w.contains("疑似")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
pub(crate) fn git_scan_never_persists_mcp_url_header_or_argument_secrets() {
    let content = r#"{"mcpServers":{
        "remote":{"url":"https://user:private-url@mcp.example.invalid/mcp?token=private-query",
                  "headers":{"Authorization":"Bearer private-header"}},
        "local":{"command":"node","args":["tool.js","--api-key","private-argument"],
                 "env":{"API_KEY":"sk-abcdefghijklmnopqrstuvwxyz012345"}}
    }}"#;
    let mut batch = DiscoveryBatch::new(TenantId::default_tenant(), DiscoverySource::GitScan);
    GitScanner::new().scan_content(&mut batch, Path::new(".mcp.json"), content);
    assert_eq!(batch.assets.len(), 2);
    let remote = batch.assets.iter().find(|asset| asset.name == "remote");
    assert!(remote.is_some());
    let Some(remote) = remote else { return };
    assert_eq!(remote.endpoint.as_deref(), Some("https://mcp.example.invalid/mcp"));
    assert!(remote.requires_auth);
    assert!(remote.has_plaintext_secret);
    let serialized = serde_json::to_string(&batch).unwrap_or_default();
    for secret in
        ["private-url", "private-query", "private-header", "private-argument", "sk-abcdefghijklmnopqrstuvwxyz012345"]
    {
        assert!(!serialized.contains(secret), "发现批次不得包含原始凭据");
    }
}

#[test]
pub(crate) fn git_scanner_rejects_missing_directory() {
    let scanner = GitScanner::new();
    let res = scanner.scan_local(TenantId::default_tenant(), "Z:/definitely/missing/dir");
    assert!(res.is_err());
}

#[tokio::test]
pub(crate) async fn network_scanner_mock_is_deterministic() {
    let scanner = NetworkScanner::new(true, 100);
    assert!(scanner.is_mock());
    let target = NetworkScanTarget::new("10.0.0.10", vec![11434, 8080, 19530]);
    let a = scanner.probe(TenantId::default_tenant(), &target).await;
    let b = scanner.probe(TenantId::default_tenant(), &target).await;
    assert_eq!(a.assets.len(), b.assets.len(), "Mock 结果必须可复现");
    for asset in &a.assets {
        assert_eq!(asset.discovery_source, DiscoverySource::NetworkScan);
        assert!(asset.endpoint.is_some());
        assert!(!asset.exposure_items.is_empty());
    }
    assert!(!scanner.common_ports().is_empty());
}

#[tokio::test]
pub(crate) async fn network_scanner_real_probe_to_closed_port_is_false() {
    let scanner = NetworkScanner::new(false, 200);
    // 127.0.0.1 上一个几乎不可能监听的端口
    assert!(!scanner.tcp_probe("127.0.0.1", 6_499).await);
}

#[test]
pub(crate) fn port_inference() {
    assert_eq!(infer_kind_for_port(11434), AssetKind::ModelEndpoint);
    assert_eq!(infer_kind_for_port(19530), AssetKind::VectorStore);
    assert_eq!(infer_kind_for_port(8091), AssetKind::McpServer);
    assert_eq!(infer_kind_for_port(12345), AssetKind::Other);
}

#[test]
pub(crate) fn merge_batches_dedupes_by_fingerprint() {
    let tenant = TenantId::default_tenant();
    let mut b1 = DiscoveryBatch::new(tenant, DiscoverySource::AgentReport);
    let mut a1 = DiscoveredAsset::new(AssetKind::McpServer, "fs", "fp-1".into(), DiscoverySource::AgentReport);
    a1.exposure_score = 30;
    let mut a2 = a1.clone();
    a2.exposure_score = 70; // 信息量更大的一条
    b1.assets = vec![a1];
    let mut b2 = DiscoveryBatch::new(tenant, DiscoverySource::GitScan);
    b2.assets = vec![a2];
    let merged = merge_batches(&[b1, b2]);
    assert_eq!(merged.assets.len(), 1);
    assert_eq!(merged.assets[0].exposure_score, 70, "应保留信息量更大的观测");
}

#[test]
pub(crate) fn to_asset_conversion_preserves_identity_and_sets_trial() {
    let tenant = TenantId::default_tenant();
    let mut d = DiscoveredAsset::new(AssetKind::McpServer, "fs", "fp-x".into(), DiscoverySource::GitScan);
    d.endpoint = Some("stdio:npx".into());
    d.vendor = Some("mcp".into());
    d.attributes = serde_json::json!({"k": "v"});
    let a = to_asset(&d, tenant);
    assert_eq!(a.id, to_asset(&d, tenant).id);
    assert_ne!(a.id, to_asset(&d, TenantId::new()).id);
    assert_eq!(a.fingerprint, "fp-x");
    assert_eq!(a.kind, AssetKind::McpServer);
    assert_eq!(a.lifecycle, agf_core::enums::LifecycleState::Trial);
    assert_eq!(a.tenant_id, tenant);
    assert_eq!(a.attributes.get("k"), Some(&serde_json::json!("v")));
}

#[test]
pub(crate) fn batch_to_assets_converts_all() {
    let batch = DiscoveryBatch::from_agent_report(TenantId::default_tenant(), &report());
    let assets = batch_to_assets(&batch, TenantId::default_tenant());
    assert_eq!(assets.len(), batch.assets.len());
}

#[test]
pub(crate) fn model_endpoint_discovered_shape() {
    let d = model_endpoint_discovered("openai", "https://api.openai.com/v1", "gpt-4o", false, DiscoverySource::Manual);
    assert_eq!(d.kind, AssetKind::ModelEndpoint);
    assert!(d.requires_auth);
    assert!(d.exposure_score > 0);
    let local =
        model_endpoint_discovered("ollama", "http://127.0.0.1:11434/v1", "llama3", true, DiscoverySource::Manual);
    assert!(!local.requires_auth);
    assert!(local.exposure_score < d.exposure_score, "本地模型暴露面应更低");
    let private = model_endpoint_discovered(
        "openai",
        "https://user:private-password@api.example.invalid/v1?api_key=private-query",
        "gpt-test",
        false,
        DiscoverySource::Manual,
    );
    assert_eq!(private.endpoint.as_deref(), Some("https://api.example.invalid/v1"));
    assert!(private.has_plaintext_secret);
    let serialized = serde_json::to_string(&private).unwrap_or_default();
    assert!(!serialized.contains("private-password"));
    assert!(!serialized.contains("private-query"));
}

#[test]
pub(crate) fn default_skip_dirs_nonempty() {
    assert!(!default_skip_dirs().is_empty());
}
