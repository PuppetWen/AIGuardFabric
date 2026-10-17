#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
//! 集成测试：终端采集 → 上报（Mock / 断线积压补传）→ 增量 的端到端链路（**完全不触网**）。
//!
//! 全程只使用 crate 的公开 API，并用**临时目录造样本**替代真实用户目录，
//! 不依赖本机是否装有 Cursor / Claude / VS Code。

use std::path::Path;
use std::sync::Arc;

use agf_agent::{
    AgentClient, AgentIdentity, AgentTransport, ClientConfig, ClientMode, CollectContext, CollectionExtras,
    CollectorOutcome, Envelope, HttpTransportNotImplemented, PayloadKind, QueueConfig, ReleaseManifest, SupportLevel,
    UpdatePlan, collect_all, collector_roster, compute_diff, parse_version, plan_update, platform, selfupdate,
    verify_checksum,
};
use agf_core::adapter::RetryConfig;
use agf_core::agent::{AgentFlavor, DetectedAgent};
use agf_core::error::{DomainError, DomainResult};

/// 造一个"像真终端"的用户目录样本。
fn sample_home() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("临时目录");
    let home = dir.path();

    // ① Cursor MCP 配置（含明文密钥）
    let cursor = home.join(".cursor");
    std::fs::create_dir_all(&cursor).expect("建 .cursor");
    std::fs::write(
        cursor.join("mcp.json"),
        r#"{"mcpServers":{"fs":{"command":"npx","args":["-y","mcp-fs","/data"],
            "env":{"OPENAI_API_KEY":"sk-proj-abcdefghijklmnopqrstuvwxyz0123456789","OPENAI_BASE_URL":"https://api.openai.com/v1"}},
            "remote":{"url":"https://mcp.example.invalid/sse"}}}"#,
    )
    .expect("写 mcp.json");

    // ② Claude Desktop 配置（按当前平台的真实用户目录布局）
    let claude_relative = match platform::current() {
        platform::HostPlatform::Windows => "AppData/Roaming/Claude",
        platform::HostPlatform::Linux => ".config/Claude",
        platform::HostPlatform::MacOs => "Library/Application Support/Claude",
        platform::HostPlatform::Other => "AppData/Roaming/Claude",
    };
    let claude = home.join(claude_relative);
    std::fs::create_dir_all(&claude).expect("建 Claude 目录");
    std::fs::write(
        claude.join("claude_desktop_config.json"),
        r#"{"mcpServers":{"files":{"command":"python","args":["-m","mcp_files"]}}}"#,
    )
    .expect("写 claude 配置");

    // ③ 环境文件（硬编码密钥）
    std::fs::write(home.join(".env"), "SERVICE_TOKEN=abcdef0123456789abcdef0123456789\nPATH=/usr/bin\n")
        .expect("写 .env");

    // ④ IDE 插件目录
    let ext = home.join(".vscode/extensions/anthropic.claude-code-2.0.0");
    std::fs::create_dir_all(&ext).expect("建插件目录");
    std::fs::write(ext.join("package.json"), r#"{"name":"claude-code","version":"2.0.0"}"#).expect("写 package.json");

    // ⑤ Skill 目录
    let skill = home.join(".claude/skills/audit");
    std::fs::create_dir_all(&skill).expect("建 skill 目录");
    std::fs::write(skill.join("SKILL.md"), "# audit skill").expect("写 SKILL.md");

    dir
}

fn context(home: &Path) -> CollectContext {
    CollectContext::for_current_user().with_home(home).without_system_probes()
}

fn identity() -> AgentIdentity {
    AgentIdentity::generate().with_agent_id("agent-it-1").with_hostname("host-it")
}

/// 测试传输：恒定成功（模拟服务端可用），记录收到的正文。
#[derive(Debug, Default)]
struct AlwaysOkTransport {
    seen: std::sync::Mutex<Vec<String>>,
}

impl AgentTransport for AlwaysOkTransport {
    fn name(&self) -> &'static str {
        "test-ok"
    }

    fn requires_network(&self) -> bool {
        false
    }

    fn send(&self, endpoint: &str, body: &str) -> DomainResult<()> {
        if !endpoint.starts_with("https://") {
            return Err(DomainError::Config(format!("测试传输只接受 https：{endpoint}")));
        }
        self.seen.lock().map_err(|e| DomainError::Internal(e.to_string()))?.push(body.to_string());
        Ok(())
    }
}

fn live_config(queue_path: &Path) -> ClientConfig {
    ClientConfig::default()
        .with_server_url("https://agf.example.invalid")
        .with_retry(RetryConfig {
            max_attempts: 2,
            initial_backoff_ms: 1,
            multiplier: 1.0,
            max_backoff_ms: 1,
            jitter: false,
        })
        .with_queue(QueueConfig::default().with_path(queue_path))
}

#[tokio::test]
async fn collect_from_sample_home_yields_expected_facts() {
    let home = sample_home();
    let snapshot = collect_all(&identity(), &context(home.path()));

    assert_eq!(snapshot.payload.report.collector_id, "agent-it-1");
    assert_eq!(snapshot.payload.report.mcp_configs.len(), 3, "三个 MCP 服务器定义都应解析出来");
    assert!(
        snapshot.payload.report.mcp_configs.iter().any(|m| m.has_plaintext_secret),
        "含 sk- 明文密钥的 MCP 配置必须被标记"
    );
    assert!(snapshot.payload.report.mcp_configs.iter().any(|m| m.transport == "sse"));
    assert!(
        snapshot.payload.report.credential_hits.iter().any(|c| c.source_file.ends_with(".env")),
        "环境文件中的硬编码密钥必须被发现"
    );
    assert!(
        snapshot.payload.report.agents.iter().any(|a| a.flavor == AgentFlavor::ClaudeCode),
        "插件目录应产出 Agent 资产"
    );
    assert!(!snapshot.payload.extras.skills.is_empty(), "Skill 目录应被采集");
    assert!(snapshot.payload.report.scan_scope.iter().any(|s| s.contains(".cursor")));
    assert_eq!(snapshot.statuses.len(), 7);
    assert!(snapshot.total_items() > 5, "样本目录应产出多条事实，实际 {}", snapshot.total_items());
    assert!(snapshot.failed_collectors().is_empty(), "{:?}", snapshot.failed_collectors());
}

#[tokio::test]
async fn envelope_matches_server_contract_and_is_reproducible() {
    let home = sample_home();
    let snapshot = collect_all(&identity(), &context(home.path()));
    let envelope = Envelope::new(&identity(), PayloadKind::Snapshot, snapshot.payload.clone()).expect("信封");
    let json = envelope.to_json().expect("序列化");
    assert!(json.contains("\"schema\":\"agf.agent.v1\""));
    assert!(json.contains("\"kind\":\"snapshot\""));
    assert!(json.contains("\"agent_version\""));
    assert!(json.contains("\"tenant_id\""));
    assert_eq!(envelope.idempotency_key.len(), 32);

    // 同一载荷重复构造信封 → 幂等键恒定（服务端可据此去重）
    let again = Envelope::new(&identity(), PayloadKind::Snapshot, snapshot.payload.clone()).expect("信封");
    assert_eq!(again.idempotency_key, envelope.idempotency_key);

    // 内层 AgentReport 可被服务端既有解码逻辑消费（json → AgentReport）
    let value: serde_json::Value = serde_json::from_str(&json).expect("json");
    let report: agf_core::agent::AgentReport =
        serde_json::from_value(value["payload"]["report"].clone()).expect("AgentReport 解码");
    assert_eq!(report.collector_id, "agent-it-1");
    assert_eq!(report.mcp_configs.len(), 3);
}

#[tokio::test]
async fn mock_mode_reports_without_network_and_is_deterministic() {
    let home = sample_home();
    let snapshot = collect_all(&identity(), &context(home.path()));
    let mut client = AgentClient::new(identity(), ClientConfig::mock());
    assert_eq!(client.mode(), ClientMode::Mock);

    let first = client
        .send_snapshot(snapshot.payload.report.clone(), snapshot.payload.extras.clone())
        .await
        .expect("Mock 上报");
    let second = client
        .send_snapshot(snapshot.payload.report.clone(), snapshot.payload.extras.clone())
        .await
        .expect("Mock 上报");
    assert!(first.mocked && second.mocked);
    assert_eq!(client.recorded_deliveries().len(), 2);
    assert_eq!(
        client.recorded_deliveries()[0].idempotency_key,
        client.recorded_deliveries()[1].idempotency_key,
        "同一载荷的幂等键必须一致"
    );
    assert!(client.queue().is_empty(), "Mock 模式不得产生积压");

    let heartbeat = client.heartbeat_payload(snapshot.statuses.clone());
    let delivered = client.send_heartbeat(&heartbeat).await.expect("Mock 心跳");
    assert_eq!(delivered.kind, PayloadKind::Heartbeat);
}

#[tokio::test]
async fn not_implemented_transport_queues_then_flush_delivers() {
    let home = sample_home();
    let snapshot = collect_all(&identity(), &context(home.path()));
    let dir = tempfile::tempdir().expect("临时目录");
    let config = live_config(&dir.path().join("queue.jsonl"));

    // 无服务端地址时的默认传输：明确 NotImplemented → 退避重试 → 入队（不丢数据）
    let mut client =
        AgentClient::new(identity(), config.clone()).with_transport(Arc::new(HttpTransportNotImplemented::default()));
    let outcome =
        client.send_snapshot(snapshot.payload.report.clone(), snapshot.payload.extras.clone()).await.expect("应入队");
    assert!(outcome.queued, "未实现的上行必须退化为入队而不是丢数据");
    assert!(outcome.note.unwrap_or_default().contains("TODO(agent-http)"));
    assert_eq!(client.queue().len(), 1);
    client.save_queue().expect("落盘");

    // 重启后积压仍在
    let transport = Arc::new(AlwaysOkTransport::default());
    let mut restarted =
        AgentClient::with_persisted_queue(identity(), config).expect("载入队列").with_transport(transport.clone());
    assert_eq!(restarted.queue().len(), 1, "重启后积压必须保留");
    let stats = restarted.flush_queue(10).await;
    assert_eq!(stats.delivered, 1, "{stats:?}");
    assert!(restarted.queue().is_empty());
    assert_eq!(transport.seen.lock().map(|v| v.len()).unwrap_or(0), 1, "补传应真正到达服务端");
}

#[tokio::test]
async fn diff_after_snapshot_tracks_added_and_removed_assets() {
    let mut client = AgentClient::new(identity(), ClientConfig::mock());
    let base = agf_core::agent::AgentReport {
        collector_id: "agent-it-1".into(),
        collected_at: agf_core::time::Timestamp::now(),
        hostname: "host-it".into(),
        os: "windows/x86_64".into(),
        os_user: None,
        agents: vec![DetectedAgent {
            flavor: AgentFlavor::Cursor,
            version: Some("1.0".into()),
            binary_path: None,
            config_dir: Some("~/.cursor".into()),
            config_hash: None,
        }],
        mcp_configs: vec![],
        credential_hits: vec![],
        scan_scope: vec![],
        agent_version: agf_agent::AGENT_VERSION.to_string(),
    };
    client.send_snapshot(base.clone(), CollectionExtras::default()).await.expect("基线快照");

    // 无变化 → 空 diff
    assert!(client.compute_diff(&base).is_empty());

    // 资产变化：Cursor 版本升级 + 新增 Claude Code + 移除 MCP
    let mut changed = base.clone();
    changed.agents[0].version = Some("2.0".into());
    changed.agents.push(DetectedAgent {
        flavor: AgentFlavor::ClaudeCode,
        version: None,
        binary_path: None,
        config_dir: Some("~/.claude".into()),
        config_hash: None,
    });
    let diff = client.compute_diff(&changed);
    assert_eq!(diff.changed_agents.len(), 1);
    assert_eq!(diff.added_agents.len(), 1);
    assert!(diff.removed_agent_keys.is_empty());
    assert_eq!(diff.base_fingerprint.len(), 32);
    let outcome = client.send_diff(&diff).await.expect("上报 diff");
    assert_eq!(outcome.kind, PayloadKind::Diff);

    // 直接调用纯函数同样可用（服务端可复算）
    let from_scratch = compute_diff(Some(&base), &changed);
    assert_eq!(from_scratch.change_count(), diff.change_count());
}

#[tokio::test]
async fn queue_capacity_and_eviction_are_reported() {
    let dir = tempfile::tempdir().expect("临时目录");
    let config =
        live_config(&dir.path().join("q.jsonl")).with_queue(QueueConfig::default().with_capacity(2, 1_000_000));
    let mut client =
        AgentClient::new(identity(), config).with_transport(Arc::new(HttpTransportNotImplemented::default()));
    for key in ["k0", "k1", "k2"] {
        client.deliver(PayloadKind::Heartbeat, "{\"x\":1}", key).await.expect("入队");
    }
    let stats = client.queue_stats();
    assert_eq!(stats.depth, 2, "必须按上限淘汰最旧");
    assert_eq!(stats.evicted_total, 1);
    assert_eq!(client.queue().keys(), vec!["k1".to_string(), "k2".to_string()]);
}

#[test]
fn platform_roster_is_honest_about_support_levels() {
    let roster = collector_roster();
    assert_eq!(roster.len(), 7);
    for descriptor in &roster {
        let implemented = matches!(
            platform::current(),
            platform::HostPlatform::Windows | platform::HostPlatform::Linux | platform::HostPlatform::MacOs
        );
        assert_eq!(descriptor.level == SupportLevel::Implemented, implemented);
        if !implemented {
            assert!(descriptor.todo_anchor.unwrap_or_default().starts_with("agent-"));
        }
    }
    let unsupported: CollectorOutcome<u8> = CollectorOutcome::unsupported("processes", "TODO(agent-linux)".to_string());
    assert_eq!(unsupported.status().level, "interface-only");
}

#[tokio::test]
async fn self_update_is_advisory_only() {
    let bytes = b"agf-agent-binary-0.2.0";
    let manifest = ReleaseManifest {
        version: "0.2.0".into(),
        notes: Some("改进采集".into()),
        rollout_percent: 50,
        assets: vec![agf_agent::ReleaseAsset {
            platform: platform::current().as_str().to_string(),
            arch: platform::current_arch().to_string(),
            url: "https://dl.example.invalid/agf-agent-0.2.0".into(),
            sha256: selfupdate::sha256_hex(bytes),
            size: bytes.len() as u64,
        }],
        signature: Some("test-signature".into()),
    };
    assert!(verify_checksum(bytes, &selfupdate::sha256_hex(bytes)));
    assert!(!verify_checksum(b"tampered", &selfupdate::sha256_hex(bytes)));
    assert!(parse_version("0.2.0").is_ok());

    let plan: Option<UpdatePlan> =
        plan_update(agf_agent::VERSION, &manifest, platform::current(), platform::current_arch()).expect("计划");
    // 0.1.0 < 0.2.0 ⇒ 应给出计划；若未来版本号变化导致为 None，也必须是"已是最新"的合理结果
    if let Some(plan) = plan {
        assert_eq!(plan.target, "0.2.0");
        assert_eq!(plan.sha256.len(), 64);
        assert!(plan.requires_manual_approval, "字段存在不等于验签；预览不能直接 apply");
        assert!(manifest.signature.is_some(), "测试只证明未验签预览的保守语义");
    }
    assert_eq!(selfupdate::verification_conditions().len(), 5);
}
