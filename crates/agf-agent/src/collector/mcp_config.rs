//! MCP 配置文件解析；通用 home 路径可在三大桌面系统使用。
//!
//! 覆盖三种真实落盘位置：
//!
//! | 客户端 | 路径（相对用户主目录） |
//! |---|---|
//! | Cursor | `.cursor/mcp.json` |
//! | Claude Desktop | `AppData/Roaming/Claude/claude_desktop_config.json`（Windows）/ `Library/Application Support/Claude/...`（macOS）/ `.config/Claude/...`（Linux） |
//! | Claude Code | `.claude.json` / `.claude/settings.json` |
//! | VS Code | `.vscode/mcp.json` |
//! | Windsurf | `.codeium/windsurf/mcp_config.json` |
//! | Continue | `.continue/config.json` |
//!
//! ## 解析口径（与 `agf-asset::discovery::parse_mcp_config` 的服务端语义对齐）
//!
//! 服务器映射取自 `mcpServers`（兼容 `mcp_servers` / VS Code 的 `servers`）；
//! transport 取 `type`/`transport` 字段，缺省时按 URL 推断（含 `/sse` → `sse`，其余 URL → `http`，
//! 只有 `command` → `stdio`）；`env` **只上报键名**。URL 用户信息、查询串、片段与命令参数中的凭据在上报前移除。
//!
//! ## 降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 候选路径不存在 | 跳过（正常情况，不产生 warning） |
//! | JSON 非法 | 记 warning，跳过该文件（**不影响其它文件**） |
//! | 无 `command`/`url` 的条目 | 忽略（不是 MCP 服务器定义） |
//! | 文件超大/非 UTF-8 | 记 warning 跳过 |
//! | Linux/macOS 路径 | 使用对应的用户目录约定；Linux 容器已测，macOS 仍需真机验证 |

use std::path::{Path, PathBuf};

use crate::platform::HostPlatform;
use agf_core::agent::{AgentFlavor, DetectedAgent, DetectedMcp};
use agf_core::mcp_config_safety::safe_report_command;
use serde_json::Value;

use super::{
    CollectContext, CollectorOutcome, looks_like_plaintext_secret, mcp_auth, mcp_config_redaction::redact_arguments,
    project_paths, read_text, scan_text_secrets, url_safety::safe_report_url,
};

/// 采集器名。
pub const NAME: &str = "mcp-config";

/// 服务器映射的候选键（按优先级）。
pub const SERVER_KEYS: [&str; 3] = ["mcpServers", "mcp_servers", "servers"];

/// 候选配置文件路径（Windows / macOS / Linux 三种 home 布局一并生成，存在即采）。
#[must_use]
pub fn candidate_paths(home: &Path) -> Vec<PathBuf> {
    candidate_paths_for(home, crate::platform::current())
}

fn candidate_paths_for(home: &Path, platform: HostPlatform) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = [
        ".cursor/mcp.json",
        ".cursor/mcp_settings.json",
        ".claude.json",
        ".claude/settings.json",
        ".mcp.json",
        ".vscode/mcp.json",
        ".codeium/windsurf/mcp_config.json",
        ".continue/config.json",
    ]
    .iter()
    .map(|rel| home.join(rel))
    .collect();
    let desktop = match platform {
        HostPlatform::Windows => Some("AppData/Roaming/Claude/claude_desktop_config.json"),
        HostPlatform::MacOs => Some("Library/Application Support/Claude/claude_desktop_config.json"),
        HostPlatform::Linux => Some(".config/Claude/claude_desktop_config.json"),
        HostPlatform::Other => None,
    };
    if let Some(path) = desktop {
        paths.push(home.join(path));
    }
    paths
}

/// 解析 MCP 配置文本。
///
/// # Errors
/// JSON 非法或找不到服务器映射对象（且顶层不是映射）时返回错误描述。
pub fn parse_mcp_text(source_file: &str, text: &str) -> Result<Vec<DetectedMcp>, String> {
    let value: Value = serde_json::from_str(text).map_err(|e| format!("非法 JSON: {e}"))?;
    Ok(parse_mcp_value(source_file, &value))
}

/// 解析 MCP 配置值（纯函数）。
#[must_use]
pub fn parse_mcp_value(source_file: &str, value: &Value) -> Vec<DetectedMcp> {
    let servers = SERVER_KEYS.iter().find_map(|key| value.get(*key)).unwrap_or(value);
    let Some(object) = servers.as_object() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, cfg) in object {
        let Some(entry) = cfg.as_object() else { continue };
        let (url, url_sensitive) = entry
            .get("url")
            .and_then(Value::as_str)
            .and_then(safe_report_url)
            .map_or((None, false), |(safe, sensitive)| (Some(safe), sensitive));
        let raw_command = entry.get("command").and_then(Value::as_str);
        let (command, command_sensitive) =
            raw_command.map(safe_report_command).map_or((None, false), |(safe, sensitive)| (Some(safe), sensitive));
        if url.is_none() && command.is_none() {
            continue;
        }
        let transport = detect_transport(
            entry.get("type").or_else(|| entry.get("transport")).and_then(Value::as_str),
            url.as_deref(),
        );
        let raw_args: Vec<String> = entry
            .get("args")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(|v| v.as_str().map(ToString::to_string)).collect())
            .unwrap_or_default();
        let (args, args_sensitive) = redact_arguments(raw_args);
        let env_keys: Vec<String> =
            entry.get("env").and_then(Value::as_object).map(|env| env.keys().cloned().collect()).unwrap_or_default();
        let env_sensitive = entry
            .get("env")
            .and_then(Value::as_object)
            .is_some_and(|env| env.iter().any(|(k, v)| v.as_str().is_some_and(|s| looks_like_plaintext_secret(k, s))));
        let header_sensitive = entry.get("headers").and_then(Value::as_object).is_some_and(|headers| {
            headers.iter().any(|(k, v)| {
                v.as_str().is_some_and(|s| {
                    looks_like_plaintext_secret(k, s)
                        || (k.eq_ignore_ascii_case("authorization")
                            && !s.trim().is_empty()
                            && !agf_core::secret::is_placeholder(s))
                })
            })
        });
        out.push(DetectedMcp {
            source_file: source_file.to_string(),
            server_name: name.clone(),
            transport: transport.to_string(),
            command,
            args,
            url,
            env_keys,
            has_plaintext_secret: env_sensitive
                || header_sensitive
                || url_sensitive
                || command_sensitive
                || args_sensitive,
            auth_configured: mcp_auth::has_auth_settings(entry),
        });
    }
    out.sort_by(|a, b| a.server_name.cmp(&b.server_name));
    out
}

/// 传输方式推断。
#[must_use]
pub fn detect_transport(declared: Option<&str>, url: Option<&str>) -> &'static str {
    if let Some(declared) = declared {
        let lower = declared.to_ascii_lowercase();
        return match lower.as_str() {
            "sse" => "sse",
            "http" | "streamable-http" | "streamable_http" => "http",
            "stdio" => "stdio",
            _ => "stdio",
        };
    }
    match url {
        Some(u) if u.contains("/sse") => "sse",
        Some(_) => "http",
        None => "stdio",
    }
}

/// 由 MCP 配置推断宿主 Agent 资产（Cursor / Claude Desktop / VS Code …）。
#[must_use]
pub fn agents_from_mcp(mcps: &[DetectedMcp], hostname: &str) -> Vec<DetectedAgent> {
    let mut out: Vec<DetectedAgent> = Vec::new();
    for mcp in mcps {
        let lower = mcp.source_file.to_ascii_lowercase();
        let flavor = if lower.contains(".cursor") {
            Some(AgentFlavor::Cursor)
        } else if lower.contains("claude") {
            Some(AgentFlavor::ClaudeCode)
        } else if lower.contains(".vscode") {
            Some(AgentFlavor::Copilot)
        } else if lower.contains("windsurf") || lower.contains("codeium") {
            Some(AgentFlavor::Windsurf)
        } else if lower.contains(".continue") {
            Some(AgentFlavor::Custom)
        } else {
            None
        };
        let Some(flavor) = flavor else { continue };
        let anchor = Path::new(&mcp.source_file)
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| mcp.source_file.clone());
        if out.iter().any(|a| a.flavor == flavor && a.config_dir.as_deref() == Some(anchor.as_str())) {
            continue;
        }
        out.push(DetectedAgent {
            flavor,
            version: None,
            binary_path: None,
            config_dir: Some(anchor),
            config_hash: Some(agf_core::secret::content_hash(&format!("{hostname}:{}", mcp.source_file))),
        });
    }
    out.sort_by(|a, b| (a.flavor.as_str(), a.config_dir.as_deref()).cmp(&(b.flavor.as_str(), b.config_dir.as_deref())));
    out
}

/// 执行采集。
#[must_use]
pub fn collect(ctx: &CollectContext) -> CollectorOutcome<DetectedMcp> {
    collect_for(ctx, crate::platform::current())
}

fn collect_for(ctx: &CollectContext, platform: HostPlatform) -> CollectorOutcome<DetectedMcp> {
    if platform == HostPlatform::Other {
        return CollectorOutcome::unsupported(NAME, "MCP config collection is unsupported on this platform".into());
    }
    let started = std::time::Instant::now();
    let mut outcome = CollectorOutcome {
        name: NAME,
        items: Vec::new(),
        credential_hits: Vec::new(),
        scope: Vec::new(),
        warnings: Vec::new(),
        level: crate::platform::SupportLevel::Implemented,
        elapsed_ms: 0,
        error: None,
    };
    let mut paths = candidate_paths_for(&ctx.home, platform);
    paths.extend(project_paths::candidate_paths(&ctx.project_roots));
    paths.sort();
    paths.dedup();
    for path in paths {
        if !path.is_file() {
            continue;
        }
        let label = path.display().to_string();
        outcome.scope.push(label.clone());
        let text = match read_text(&path, ctx.max_file_bytes) {
            Ok(text) => text,
            Err(reason) => {
                outcome.warnings.push(format!("{label}: {reason}"));
                continue;
            }
        };
        match parse_mcp_text(&label, &text) {
            Ok(mut mcps) => outcome.items.append(&mut mcps),
            Err(reason) => outcome.warnings.push(format!("{label}: {reason}")),
        }
        // 明文凭据扫描覆盖"服务器映射之外"的内容（如全局 api_key 字段）
        outcome.credential_hits.extend(scan_text_secrets(&label, &text));
    }
    outcome.items.sort_by(|a, b| {
        (a.source_file.as_str(), a.server_name.as_str()).cmp(&(b.source_file.as_str(), b.server_name.as_str()))
    });
    outcome.items.dedup_by(|a, b| a.source_file == b.source_file && a.server_name == b.server_name);
    let mut plaintext_warnings: Vec<String> = Vec::new();
    for mcp in &outcome.items {
        if mcp.has_plaintext_secret {
            plaintext_warnings.push(format!(
                "MCP 配置 {} 的 {} 含疑似明文凭据；请检查源配置中的环境变量、HTTP 头、URL 和命令参数",
                mcp.source_file, mcp.server_name
            ));
        }
    }
    outcome.warnings.extend(plaintext_warnings);
    outcome.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn write_config(home: &Path, rel: &str, content: &str) -> PathBuf {
        let path = home.join(rel);
        std::fs::create_dir_all(path.parent().unwrap_or(home)).expect("建目录");
        std::fs::write(&path, content).expect("写样本");
        path
    }

    #[test]
    fn parses_stdio_server_with_env_keys_only() {
        let value = json!({
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
                    "env": {"OPENAI_API_KEY": "sk-abcdefghijklmnopqrstuvwxyz012345", "PLAIN": "value"}
                }
            }
        });
        let parsed = parse_mcp_value("~/.cursor/mcp.json", &value);
        assert_eq!(parsed.len(), 1);
        let mcp = &parsed[0];
        assert_eq!(mcp.server_name, "filesystem");
        assert_eq!(mcp.transport, "stdio");
        assert_eq!(mcp.command.as_deref(), Some("npx"));
        assert_eq!(mcp.args.len(), 3);
        assert!(mcp.url.is_none());
        assert_eq!(mcp.env_keys.len(), 2, "只上报键名");
        assert!(mcp.has_plaintext_secret, "sk- 开头的 env 值必须判为明文凭据");
    }

    #[test]
    fn parses_remote_transports_and_declared_type() {
        let value = json!({
            "mcpServers": {
                "sse-server": {"url": "https://mcp.example.invalid/sse", "env": {}},
                "http-server": {"url": "https://mcp.example.invalid/mcp", "type": "streamable-http"},
                "declared-stdio": {"command": "python", "type": "stdio"},
            }
        });
        let parsed = parse_mcp_value("cfg", &value);
        let by_name = |n: &str| parsed.iter().find(|m| m.server_name == n).cloned();
        assert_eq!(by_name("sse-server").map(|m| m.transport), Some("sse".to_string()));
        assert_eq!(by_name("http-server").map(|m| m.transport), Some("http".to_string()));
        assert_eq!(by_name("declared-stdio").map(|m| m.transport), Some("stdio".to_string()));
    }

    #[test]
    fn discovered_mcp_never_copies_url_or_argument_credentials() {
        let value = json!({"mcpServers": {
            "remote": {
                "url": "https://sample-user:sample-password@mcp.example.invalid/mcp?token=sample-secret",
                "headers": {"Authorization": "Bearer private-value"}
            },
            "local": {
                "command": "node",
                "args": ["server.js", "--api-key", "private-argument", "--header=private-header",
                    "--endpoint=https://user:password@service.example.invalid/mcp?token=argument-secret"]
            }
        }});
        let parsed = parse_mcp_value("config.json", &value);
        let remote = parsed.iter().find(|m| m.server_name == "remote").expect("HTTP MCP");
        assert_eq!(remote.url.as_deref(), Some("https://mcp.example.invalid/mcp"));
        assert!(remote.has_plaintext_secret);
        let local = parsed.iter().find(|m| m.server_name == "local").expect("stdio MCP");
        assert_eq!(
            local.args,
            [
                "server.js",
                "--api-key",
                "<redacted>",
                "--header=<redacted>",
                "--endpoint=https://service.example.invalid/mcp"
            ]
        );
        assert!(local.has_plaintext_secret);
        let report = serde_json::to_string(&parsed).expect("序列化");
        for secret in [
            "sample-password",
            "sample-secret",
            "private-value",
            "private-argument",
            "private-header",
            "argument-secret",
        ] {
            assert!(!report.contains(secret), "发现结果不得包含原始凭据");
        }
    }

    #[test]
    fn accepts_alternate_server_keys_and_ignores_non_servers() {
        let vscode = json!({"servers": {"x": {"command": "node", "args": []}}});
        assert_eq!(parse_mcp_value("vscode", &vscode).len(), 1);
        let snake = json!({"mcp_servers": {"y": {"url": "https://a.invalid/mcp"}}});
        assert_eq!(parse_mcp_value("snake", &snake).len(), 1);
        let noise = json!({"mcpServers": {"not-a-server": {"description": "no command or url"}}});
        assert!(parse_mcp_value("noise", &noise).is_empty(), "缺 command/url 的条目不得上报");
        assert!(parse_mcp_value("scalar", &json!("just a string")).is_empty());
    }

    #[test]
    fn placeholder_env_is_not_flagged_as_secret() {
        let value = json!({"mcpServers": {"s": {"command": "x", "env": {"API_KEY": "${API_KEY}", "OTHER": "short"}}}});
        let parsed = parse_mcp_value("cfg", &value);
        assert!(!parsed[0].has_plaintext_secret, "占位符/短值不得判为明文凭据");
    }

    #[test]
    fn invalid_json_is_reported_not_panicking() {
        let result = parse_mcp_text("bad.json", "{ not json");
        assert!(result.is_err());
        assert!(result.err().unwrap_or_default().contains("非法 JSON"));
    }

    #[test]
    fn agents_inferred_from_source_path() {
        let mcp = DetectedMcp {
            source_file: "/home/u/.cursor/mcp.json".into(),
            server_name: "fs".into(),
            transport: "stdio".into(),
            command: Some("npx".into()),
            args: vec![],
            url: None,
            env_keys: vec![],
            has_plaintext_secret: false,
            auth_configured: false,
        };
        let agents = agents_from_mcp(&[mcp], "host-1");
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].flavor, AgentFlavor::Cursor);
        assert!(agents[0].config_dir.clone().unwrap_or_default().contains(".cursor"));
        assert!(agents[0].config_hash.as_deref().is_some_and(|h| !h.is_empty()));
    }

    #[test]
    fn collect_reads_temp_home_samples() {
        let dir = tempfile::tempdir().expect("临时目录");
        write_config(
            dir.path(),
            ".cursor/mcp.json",
            r#"{"mcpServers":{"fs":{"command":"npx","args":["-y","mcp-fs"],"env":{"SERVICE_TOKEN":"abcdef0123456789abcdef0123456789"}}}}"#,
        );
        write_config(
            dir.path(),
            "AppData/Roaming/Claude/claude_desktop_config.json",
            r#"{"mcpServers":{"remote":{"url":"https://mcp.example.invalid/sse"}}}"#,
        );
        write_config(dir.path(), ".vscode/mcp.json", "{ broken json");

        let ctx = CollectContext::for_current_user().with_home(dir.path());
        let outcome = collect_for(&ctx, HostPlatform::Windows);
        assert!(outcome.is_ok());
        assert_eq!(outcome.items.len(), 2, "两个合法配置应被解析: {:?}", outcome.items);
        assert!(outcome.items.iter().any(|m| m.has_plaintext_secret));
        assert!(outcome.items.iter().any(|m| m.transport == "sse"));
        assert!(outcome.warnings.iter().any(|w| w.contains("非法 JSON")), "{:?}", outcome.warnings);
        assert!(outcome.warnings.iter().any(|w| w.contains("明文凭据")));
        assert_eq!(outcome.scope.len(), 3, "三个存在的文件都应进入 scope");
        // 明文密钥被定位到行号（单行 JSON → 第 1 行）
        assert!(outcome.credential_hits.iter().any(|c| c.source_file.contains("mcp.json") && c.line >= 1));
    }

    #[test]
    fn missing_home_yields_empty_but_not_failed() {
        let dir = tempfile::tempdir().expect("临时目录");
        let ctx = CollectContext::for_current_user().with_home(dir.path().join("nope"));
        let outcome = collect(&ctx);
        assert!(outcome.is_ok());
        assert!(outcome.items.is_empty());
        assert!(outcome.scope.is_empty());
    }

    #[test]
    fn linux_and_macos_layouts_collect_without_windows_paths() {
        for (platform, path) in [
            (HostPlatform::Linux, ".config/Claude/claude_desktop_config.json"),
            (HostPlatform::MacOs, "Library/Application Support/Claude/claude_desktop_config.json"),
        ] {
            let dir = tempfile::tempdir().expect("临时目录");
            write_config(dir.path(), path, r#"{"mcpServers":{"safe":{"command":"mcp-safe"}}}"#);
            write_config(
                dir.path(),
                "AppData/Roaming/Claude/claude_desktop_config.json",
                r#"{"mcpServers":{"windows-only":{"command":"mcp-windows"}}}"#,
            );
            let ctx = CollectContext::for_current_user().with_home(dir.path());
            let outcome = collect_for(&ctx, platform);
            assert!(outcome.is_ok(), "{outcome:?}");
            assert_eq!(outcome.items.len(), 1);
            assert_eq!(outcome.items[0].server_name, "safe");
            assert_eq!(outcome.scope.len(), 1);
        }
    }

    #[test]
    fn explicit_project_root_discovers_project_mcp_without_repo_walk() {
        let base = tempfile::tempdir().expect("临时目录");
        let home = base.path().join("home");
        let project = base.path().join("workspace");
        std::fs::create_dir_all(&home).expect("home");
        write_config(&project, ".mcp.json", r#"{"mcpServers":{"project-tool":{"command":"node"}}}"#);
        write_config(base.path(), "unrelated/.mcp.json", r#"{"mcpServers":{"unrelated":{"command":"node"}}}"#);
        let ctx = CollectContext::for_current_user().with_home(home).with_project_roots(vec![project]);
        let outcome = collect_for(&ctx, HostPlatform::Linux);
        assert_eq!(outcome.items.len(), 1);
        assert_eq!(outcome.items[0].server_name, "project-tool");
        assert_eq!(outcome.scope.len(), 1);
    }
}
