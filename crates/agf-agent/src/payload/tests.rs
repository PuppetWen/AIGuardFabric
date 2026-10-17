//! 由 `payload.rs` 拆分：`agent` 等 13 个函数（纯搬移，逻辑不变）。
use super::*;

pub(crate) fn agent(flavor: AgentFlavor, dir: &str, version: Option<&str>) -> DetectedAgent {
    DetectedAgent {
        flavor,
        version: version.map(ToString::to_string),
        binary_path: None,
        config_dir: Some(dir.to_string()),
        config_hash: None,
    }
}

pub(crate) fn mcp(file: &str, name: &str) -> DetectedMcp {
    DetectedMcp {
        source_file: file.to_string(),
        server_name: name.to_string(),
        transport: "stdio".to_string(),
        command: Some("node".to_string()),
        args: vec![],
        url: None,
        env_keys: vec![],
        has_plaintext_secret: false,
        auth_configured: false,
    }
}

pub(crate) fn report(agents: Vec<DetectedAgent>, mcps: Vec<DetectedMcp>) -> AgentReport {
    AgentReport {
        collector_id: "c1".into(),
        collected_at: Timestamp::now(),
        hostname: "host1".into(),
        os: "windows/x86_64".into(),
        os_user: Some("alice".into()),
        agents,
        mcp_configs: mcps,
        credential_hits: vec![],
        scan_scope: vec!["~/.cursor".into()],
        agent_version: crate::identity::AGENT_VERSION.to_string(),
    }
}

#[test]
pub(crate) fn envelope_carries_identity_and_idempotency() {
    let identity = crate::identity::AgentIdentity::generate().with_agent_id("a-1");
    let envelope =
        Envelope::new(&identity, PayloadKind::Heartbeat, serde_json::json!({"uptime_secs": 1})).expect("信封应可构造");
    assert_eq!(envelope.schema, SCHEMA);
    assert_eq!(envelope.kind, PayloadKind::Heartbeat);
    assert_eq!(envelope.agent_id, "a-1");
    assert_eq!(envelope.tenant_id, identity.tenant_id);
    assert_eq!(envelope.idempotency_key.len(), 32);
    let json = envelope.to_json().expect("序列化");
    assert!(json.contains("agf.agent.v1"));
    let back: Envelope<serde_json::Value> = serde_json::from_str(&json).expect("反序列化");
    assert_eq!(back.idempotency_key, envelope.idempotency_key);
    assert_eq!(back.kind, envelope.kind);
}

#[test]
pub(crate) fn snapshot_payload_roundtrips_through_core_agent_report() {
    let payload = SnapshotPayload {
        report: report(
            vec![agent(AgentFlavor::Cursor, "~/.cursor", Some("0.4.1"))],
            vec![mcp(".cursor/mcp.json", "fs")],
        ),
        extras: CollectionExtras {
            model_endpoints: vec![DetectedModelEndpoint {
                source_file: "~/.cursor/mcp.json".into(),
                key: "OPENAI_BASE_URL".into(),
                url: "https://api.openai.com/v1".into(),
                provider_hint: Some("openai".into()),
                has_plaintext_key: false,
            }],
            skills: vec![DetectedSkill {
                package: None,
                content_sha256: None,
                content_hash_status: None,
                source_path: "~/.claude/skills/x/SKILL.md".into(),
                name: "x".into(),
                kind: "skill".into(),
            }],
            processes: vec![DetectedProcess { pid: 42, name: "cursor.exe".into(), flavor: Some("cursor".into()) }],
            listening_ports: vec![ListeningPort {
                protocol: "tcp".into(),
                local_addr: "127.0.0.1".into(),
                port: 8080,
                pid: Some(42),
                process: Some("cursor.exe".into()),
            }],
        },
    };
    let json = serde_json::to_string(&payload).expect("序列化");
    let back: SnapshotPayload = serde_json::from_str(&json).expect("反序列化");
    assert_eq!(back.extras, payload.extras, "终端特有事实必须无损往返");
    assert_eq!(back.report.agents.len(), payload.report.agents.len());
    assert_eq!(back.report.mcp_configs[0].server_name, payload.report.mcp_configs[0].server_name);
    assert_eq!(back.report.credential_hits.len(), payload.report.credential_hits.len());
    assert_eq!(back.report.scan_scope, payload.report.scan_scope);
    // 服务端可直接解码内层 AgentReport（既有链路契约不变）
    let report_only: AgentReport =
        serde_json::from_value(serde_json::to_value(&payload.report).expect("值")).expect("AgentReport 解码");
    assert_eq!(report_only.agents.len(), 1);
    assert_eq!(report_only.mcp_configs[0].server_name, "fs");
}

#[test]
pub(crate) fn heartbeat_payload_shape() {
    let payload = HeartbeatPayload {
        uptime_secs: 120,
        queue_depth: 3,
        last_snapshot_at: None,
        collectors: vec![CollectorStatus {
            name: "env-secrets".into(),
            level: "implemented".into(),
            items: 2,
            elapsed_ms: 7,
            error: None,
        }],
    };
    let json = serde_json::to_string(&payload).expect("序列化");
    assert!(!json.contains("last_snapshot_at"), "None 字段不应出现");
    assert!(json.contains("\"queue_depth\":3"));
}

#[test]
pub(crate) fn diff_on_first_report_marks_everything_added() {
    let current =
        report(vec![agent(AgentFlavor::Cursor, "dir-a", Some("1.0"))], vec![mcp("f1", "s1"), mcp("f2", "s2")]);
    let diff = compute_diff(None, &current);
    assert_eq!(diff.added_agents.len(), 1);
    assert_eq!(diff.added_mcp.len(), 2);
    assert!(diff.removed_agent_keys.is_empty());
    assert_eq!(diff.base_fingerprint, "none");
    assert!(!diff.is_empty());
    assert_eq!(diff.change_count(), 3);
}

#[test]
pub(crate) fn diff_detects_add_change_remove() {
    let previous = report(
        vec![agent(AgentFlavor::Cursor, "dir-a", Some("1.0")), agent(AgentFlavor::ClaudeCode, "dir-b", Some("2.0"))],
        vec![mcp("f1", "s1")],
    );
    let current = report(
        vec![agent(AgentFlavor::Cursor, "dir-a", Some("1.1")), agent(AgentFlavor::Windsurf, "dir-c", None)],
        vec![mcp("f2", "s2")],
    );
    let diff = compute_diff(Some(&previous), &current);
    assert_eq!(diff.added_agents.len(), 1);
    assert_eq!(diff.added_agents[0].flavor, AgentFlavor::Windsurf);
    assert_eq!(diff.changed_agents.len(), 1, "版本变化必须计入 changed");
    assert_eq!(diff.changed_agents[0].version.as_deref(), Some("1.1"));
    assert_eq!(diff.removed_agent_keys.len(), 1);
    assert!(diff.removed_agent_keys[0].contains("claude-code"));
    assert_eq!(diff.added_mcp.len(), 1);
    assert_eq!(diff.removed_mcp_keys, vec!["mcp:f1:s1".to_string()]);
    assert_ne!(diff.base_fingerprint, "none");
}

#[test]
pub(crate) fn diff_is_empty_when_nothing_changed() {
    let snapshot = report(vec![agent(AgentFlavor::Cursor, "dir-a", Some("1.0"))], vec![mcp("f1", "s1")]);
    let diff = compute_diff(Some(&snapshot), &snapshot);
    assert!(diff.is_empty(), "无变化时 diff 必须为空");
    assert_eq!(diff.change_count(), 0);
}

#[test]
pub(crate) fn diff_reports_new_credentials_only() {
    let mut previous = report(vec![], vec![]);
    previous.credential_hits.push(DetectedCredential {
        source_file: "env:OPENAI_API_KEY".into(),
        line: 0,
        kind: "openai_key".into(),
        masked: "sk-a********wxyz".into(),
        context: None,
        confidence: 0.95,
    });
    let mut current = previous.clone();
    current.credential_hits.push(DetectedCredential {
        source_file: "~/.cursor/mcp.json".into(),
        line: 12,
        kind: "generic_password_assignment".into(),
        masked: "secr********cret".into(),
        context: None,
        confidence: 0.6,
    });
    let diff = compute_diff(Some(&previous), &current);
    assert_eq!(diff.credential_hits.len(), 1, "已有命中不得重复上报");
    assert_eq!(diff.credential_hits[0].line, 12);
}

#[test]
pub(crate) fn diff_truncates_beyond_limit() {
    let agents: Vec<DetectedAgent> =
        (0..(MAX_DIFF_ITEMS + 20)).map(|i| agent(AgentFlavor::Cursor, &format!("dir-{i}"), None)).collect();
    let current = report(agents, vec![]);
    let diff = compute_diff(None, &current);
    assert!(diff.truncated, "超过上限必须标记截断");
    assert_eq!(diff.added_agents.len(), MAX_DIFF_ITEMS);
}

#[test]
pub(crate) fn fingerprint_is_stable_and_order_independent() {
    let a = report(vec![agent(AgentFlavor::Cursor, "x", None), agent(AgentFlavor::Cline, "y", None)], vec![]);
    let b = report(vec![agent(AgentFlavor::Cline, "y", None), agent(AgentFlavor::Cursor, "x", None)], vec![]);
    assert_eq!(fingerprint(&a), fingerprint(&b), "指纹不得依赖采集顺序");
    let c = report(vec![agent(AgentFlavor::Cursor, "x", None)], vec![]);
    assert_ne!(fingerprint(&a), fingerprint(&c));
}

#[test]
pub(crate) fn payload_kind_paths_and_flavor_hint() {
    assert_eq!(PayloadKind::Snapshot.default_path(), "/api/v1/agent/report");
    assert_eq!(PayloadKind::Heartbeat.default_path(), "/api/v1/agent/heartbeat");
    assert_eq!(PayloadKind::Register.as_str(), "register");
    assert_eq!(flavor_of_dir(".cursor"), Some(AgentFlavor::Cursor));
    assert_eq!(flavor_of_dir(".claude"), Some(AgentFlavor::ClaudeCode));
    assert_eq!(flavor_of_dir("unknown-tool"), None);
}
