//! 由 `mod.rs` 拆分：`context_defaults_and_overrides` 等 8 个函数（纯搬移，逻辑不变）。

use super::*;
use crate::identity::AgentIdentity;
use crate::platform::current;

#[test]
pub(crate) fn context_defaults_and_overrides() {
    let ctx = CollectContext::for_current_user();
    assert!(ctx.max_file_bytes > 0);
    assert!(ctx.include_processes && ctx.include_ports);
    let stripped = ctx.clone().without_system_probes();
    assert!(!stripped.include_processes && !stripped.include_ports);
    let dir = tempfile::tempdir().expect("临时目录");
    let custom = CollectContext::for_current_user().with_home(dir.path()).with_data_dir(dir.path());
    assert!(custom.home_available());
    assert!(!custom.without_system_probes().include_ports);
    let roots = (0..10).map(|index| dir.path().join(index.to_string())).collect::<Vec<_>>();
    let bounded = CollectContext::for_current_user().with_project_roots(roots);
    assert_eq!(bounded.project_roots.len(), 8, "工作区数量必须有界");
}

#[test]
pub(crate) fn collector_outcome_status_and_constructors() {
    let mut outcome: CollectorOutcome<u32> = CollectorOutcome::skipped("processes", "已关闭");
    outcome.items.push(1);
    outcome.elapsed_ms = 5;
    let status = outcome.status();
    assert_eq!(status.name, "processes");
    assert_eq!(status.items, 1);
    assert_eq!(status.level, "implemented");
    assert!(outcome.is_ok());

    let unsupported: CollectorOutcome<u32> = CollectorOutcome::unsupported("ports", "TODO(agent-linux)".to_string());
    assert!(!unsupported.is_ok());
    assert_eq!(unsupported.status().level, "interface-only");
    assert!(unsupported.status().error.unwrap_or_default().contains("TODO(agent-linux)"));
}

#[test]
pub(crate) fn scan_text_secrets_finds_env_and_json_style_keys() {
    let text = "# 注释\nPATH=/usr/bin\nSERVICE_TOKEN=abcdef0123456789abcdef0123456789\nOPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz01\nPLACEHOLDER_TOKEN=${SERVICE_TOKEN}\n";
    let hits = scan_text_secrets("~/.env", text);
    assert!(hits.iter().any(|h| h.line == 3 && h.kind == "generic_kv_secret"), "{hits:?}");
    assert!(hits.iter().any(|h| h.kind == "openai_key"), "{hits:?}");
    assert!(!hits.iter().any(|h| h.line == 2), "PATH 不得误报");
    assert!(!hits.iter().any(|h| h.line == 5), "占位符不得误报");
    for hit in &hits {
        assert!(!hit.masked.contains("abcdef0123456789abcdef0123456789"));
        assert_eq!(hit.source_file, "~/.env");
    }

    let json = "{\n  \"api_key\": \"abcdef0123456789abcdef0123456789\",\n  \"note\": \"ok\"\n}";
    let hits = scan_text_secrets("cfg.json", json);
    assert!(hits.iter().any(|h| h.line == 2), "JSON 风格的敏感键也必须命中: {hits:?}");
}

#[test]
pub(crate) fn extract_kv_pairs_handles_common_formats() {
    assert_eq!(extract_kv_pairs("A=B"), vec![("A".to_string(), "B".to_string())]);
    assert_eq!(extract_kv_pairs("  \"A\": \"B\",  "), vec![("A".to_string(), "B".to_string())]);
    assert_eq!(extract_kv_pairs("- A: B"), vec![("A".to_string(), "B".to_string())]);
    assert!(extract_kv_pairs("# A=B").is_empty(), "注释行必须跳过");
    assert!(extract_kv_pairs("   ").is_empty());
    assert!(extract_kv_pairs("no-separator").is_empty());
    assert!(extract_kv_pairs("A B=C").is_empty(), "键名含空格判否");
    assert_eq!(extract_kv_pairs("PASS=with space"), vec![("PASS".to_string(), "with space".to_string())]);
}

#[test]
pub(crate) fn looks_like_plaintext_secret_matrix() {
    assert!(looks_like_plaintext_secret("SERVICE_TOKEN", "abcdef0123456789abcdef0123456789"));
    assert!(looks_like_plaintext_secret("ANY", "AKIAIOSFODNN7ABCDEFG"));
    assert!(!looks_like_plaintext_secret("SERVICE_TOKEN", "short"));
    assert!(!looks_like_plaintext_secret("SERVICE_TOKEN", "${SERVICE_TOKEN}"));
    assert!(!looks_like_plaintext_secret("COMMENT", "a normal description string"));
    assert!(is_sensitive_key("my_api_key"));
    assert!(is_sensitive_key("DB_PASSWORD"));
    assert!(!is_sensitive_key("description"));
}

#[test]
pub(crate) fn read_text_enforces_size_and_existence() {
    let dir = tempfile::tempdir().expect("临时目录");
    let path = dir.path().join("a.txt");
    std::fs::write(&path, "hello").expect("写入");
    assert_eq!(read_text(&path, 1024).ok().as_deref(), Some("hello"));
    assert!(read_text(&path, 2).is_err(), "超限必须拒绝");
    assert!(read_text(&dir.path().join("missing.txt"), 1024).is_err());
    assert!(read_text(dir.path(), 1024).is_err(), "目录不是普通文件");
}

#[test]
pub(crate) fn collect_all_runs_with_injected_home() {
    let dir = tempfile::tempdir().expect("临时目录");
    // 造一个最小的 MCP 配置样本
    let cursor = dir.path().join(".cursor");
    std::fs::create_dir_all(&cursor).expect("建目录");
    std::fs::write(
            cursor.join("mcp.json"),
            r#"{"mcpServers":{"fs":{"command":"npx","args":["-y","mcp-fs"],"env":{"OPENAI_API_KEY":"sk-abcdefghijklmnopqrstuvwxyz012345"}}}}"#,
        )
        .expect("写样本");

    let ctx = CollectContext::for_current_user().with_home(dir.path()).without_system_probes();
    let identity = AgentIdentity::generate().with_agent_id("collector-1").with_hostname("host-x");
    let snapshot = collect_all(&identity, &ctx);

    assert_eq!(snapshot.payload.report.collector_id, "collector-1");
    assert_eq!(snapshot.payload.report.hostname, "host-x");
    assert_eq!(snapshot.payload.report.mcp_configs.len(), 1);
    assert!(snapshot.payload.report.mcp_configs[0].has_plaintext_secret, "env 中的明文密钥必须被标记");
    assert!(
        snapshot.payload.report.credential_hits.iter().any(|c| c.source_file.ends_with("mcp.json")),
        "MCP 配置里的明文密钥必须进入 credential_hits"
    );
    assert!(snapshot.payload.report.scan_scope.iter().any(|s| s.contains(".cursor")));
    assert_eq!(snapshot.statuses.len(), 7, "七个采集器都要有状态记录（含跳过的进程/端口）");
    assert!(snapshot.total_items() >= 2);
    // 进程/端口被关闭 → 状态里仍然是成功 + 计数 0
    let port_status = snapshot.statuses.iter().find(|s| s.name == "listening-ports").expect("端口状态存在");
    assert_eq!(port_status.items, 0);
}

#[test]
pub(crate) fn platform_support_flag_matches_current() {
    assert_eq!(
        platform_supports_collection(),
        matches!(current(), crate::platform::HostPlatform::Windows | crate::platform::HostPlatform::Linux)
    );
}
