//! IDE / Agent 插件目录扫描（三大桌面系统共用用户目录实现）。
//!
//! 两类事实：
//!
//! 1. **插件目录**：`<root>/<publisher>.<extension>-<version>`（VS Code / Cursor / Windsurf 通用约定），
//!    目录名即给出厂商与版本，`package.json` 内容哈希作为配置指纹；
//! 2. **宿主目录**：`~/.cursor`、`~/.claude`、`~/.codeium/windsurf` 等标记目录存在即说明该终端 Agent 在装。
//!
//! ## 降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 某插件根目录不存在 | 跳过（正常情况） |
//! | 目录名不符合 `publisher.name-version` | 忽略该目录，不报错 |
//! | `package.json` 不可读 | 仍上报插件（版本取自目录名），`config_hash = None` |
//! | Linux/macOS | 共用目录规则；Linux 容器验证，macOS 仍需真机验证 |

use std::path::Path;

use agf_core::agent::{AgentFlavor, DetectedAgent};

use super::{CollectContext, CollectorOutcome, read_text};
use crate::collector::is_sensitive_key;

/// 采集器名。
pub const NAME: &str = "ide-plugins";

/// 插件目录候选（相对用户主目录）。
pub const EXTENSION_ROOTS: [&str; 5] = [
    ".vscode/extensions",
    ".vscode-insiders/extensions",
    ".cursor/extensions",
    ".windsurf/extensions",
    ".cline/extensions",
];

/// 宿主标记目录及其 Agent 类型（存在即视为在装）。
pub const HOST_MARKERS: [(&str, AgentFlavor); 6] = [
    (".cursor", AgentFlavor::Cursor),
    (".claude", AgentFlavor::ClaudeCode),
    (".codeium/windsurf", AgentFlavor::Windsurf),
    (".continue", AgentFlavor::Custom),
    (".cline", AgentFlavor::Cline),
    (".ollama", AgentFlavor::Custom),
];

/// 解析插件目录名 `publisher.name-version` → `(publisher, name, version)`。
#[must_use]
pub fn parse_extension_dir_name(dir_name: &str) -> Option<(String, String, String)> {
    let (prefix, version) = dir_name.rsplit_once('-')?;
    if version.is_empty() || !version.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return None;
    }
    let (publisher, name) = prefix.split_once('.')?;
    if publisher.is_empty() || name.is_empty() {
        return None;
    }
    Some((publisher.to_string(), name.to_string(), version.to_string()))
}

/// 由 publisher / name 推断 Agent 类型。
#[must_use]
pub fn flavor_from_publisher(publisher: &str, name: &str) -> AgentFlavor {
    let haystack = format!("{publisher}.{name}").to_ascii_lowercase();
    if haystack.contains("cursor") {
        AgentFlavor::Cursor
    } else if haystack.contains("cline") || haystack.contains("saoudrizwan") || haystack.contains("roo") {
        AgentFlavor::Cline
    } else if haystack.contains("anthropic") || haystack.contains("claude") {
        AgentFlavor::ClaudeCode
    } else if haystack.contains("copilot") || haystack.contains("github") {
        AgentFlavor::Copilot
    } else if haystack.contains("codeium") || haystack.contains("windsurf") {
        AgentFlavor::Windsurf
    } else if haystack.contains("continue") {
        AgentFlavor::Custom
    } else {
        AgentFlavor::Unknown
    }
}

/// 扫描单个插件根目录。
#[must_use]
pub fn scan_extension_root(root: &Path, max_file_bytes: u64) -> (Vec<DetectedAgent>, Vec<String>) {
    let mut agents = Vec::new();
    let mut warnings = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return (agents, warnings);
    };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let dir_name = entry.file_name().to_string_lossy().to_string();
        let Some((publisher, name, version)) = parse_extension_dir_name(&dir_name) else {
            continue;
        };
        let dir = entry.path();
        let config_hash = match read_text(&dir.join("package.json"), max_file_bytes) {
            Ok(text) => Some(agf_core::secret::content_hash(&text)),
            Err(reason) => {
                warnings.push(format!("{}: package.json {reason}", dir.display()));
                None
            }
        };
        agents.push(DetectedAgent {
            flavor: flavor_from_publisher(&publisher, &name),
            version: Some(version),
            binary_path: None,
            config_dir: Some(dir.display().to_string()),
            config_hash,
        });
    }
    (agents, warnings)
}

/// 扫描宿主标记目录。
#[must_use]
pub fn scan_host_markers(home: &Path) -> Vec<DetectedAgent> {
    let mut agents = Vec::new();
    for (rel, flavor) in HOST_MARKERS {
        let dir = home.join(rel);
        if !dir.is_dir() {
            continue;
        }
        agents.push(DetectedAgent {
            flavor,
            version: None,
            binary_path: None,
            config_dir: Some(dir.display().to_string()),
            config_hash: None,
        });
    }
    agents
}

/// 执行采集。
#[must_use]
pub fn collect(ctx: &CollectContext) -> CollectorOutcome<DetectedAgent> {
    if crate::platform::current() == crate::platform::HostPlatform::Other {
        return CollectorOutcome::unsupported(NAME, "IDE 插件采集不支持当前平台".to_string());
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
    for rel in EXTENSION_ROOTS {
        let root = ctx.home.join(rel);
        if !root.is_dir() {
            continue;
        }
        outcome.scope.push(root.display().to_string());
        let (mut agents, mut warnings) = scan_extension_root(&root, ctx.max_file_bytes);
        outcome.items.append(&mut agents);
        outcome.warnings.append(&mut warnings);
    }
    let markers = scan_host_markers(&ctx.home);
    for agent in &markers {
        if let Some(dir) = &agent.config_dir {
            outcome.scope.push(dir.clone());
        }
    }
    outcome.items.extend(markers);
    outcome.items.sort_by(|a, b| {
        (a.flavor.as_str(), a.config_dir.as_deref()).cmp(&(b.flavor.as_str(), b.config_dir.as_deref()))
    });
    outcome.items.dedup_by(|a, b| a.flavor == b.flavor && a.config_dir == b.config_dir);
    outcome.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    outcome
}

/// 是否需要在告警中重点关注：IDE 类 Agent 天然可读写源码与本地凭据，
/// 自研 Agent（`Custom`）同样按重点关注处理；`Unknown` 交由服务端研判，不在终端下结论。
#[must_use]
pub fn is_ai_related(flavor: AgentFlavor) -> bool {
    flavor.is_ide_agent() || matches!(flavor, AgentFlavor::Custom)
}

/// 敏感插件名关键词（用于警告，便于人工核对"能读源码/密钥的插件"）。
#[must_use]
pub fn is_sensitive_extension(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    is_sensitive_key(name) || ["secret", "vault", "keychain", "env", "credential"].iter().any(|k| lower.contains(k))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_extension(home: &Path, root: &str, dir: &str, package_json: Option<&str>) -> std::path::PathBuf {
        let path = home.join(root).join(dir);
        std::fs::create_dir_all(&path).expect("建目录");
        if let Some(content) = package_json {
            std::fs::write(path.join("package.json"), content).expect("写 package.json");
        }
        path
    }

    #[test]
    fn directory_name_parsing_matrix() {
        assert_eq!(
            parse_extension_dir_name("anthropic.claude-code-1.2.3"),
            Some(("anthropic".to_string(), "claude-code".to_string(), "1.2.3".to_string()))
        );
        assert_eq!(
            parse_extension_dir_name("github.copilot-chat-0.24.0"),
            Some(("github".to_string(), "copilot-chat".to_string(), "0.24.0".to_string()))
        );
        assert!(parse_extension_dir_name("no-version-here").is_none());
        assert!(parse_extension_dir_name("nopublisher-1.0.0").is_none());
        assert!(parse_extension_dir_name("publisher.name-notaversion").is_none());
        assert!(parse_extension_dir_name(".DS_Store").is_none());
    }

    #[test]
    fn flavor_inference_from_publisher_and_name() {
        assert_eq!(flavor_from_publisher("anthropic", "claude-code"), AgentFlavor::ClaudeCode);
        assert_eq!(flavor_from_publisher("github", "copilot-chat"), AgentFlavor::Copilot);
        assert_eq!(flavor_from_publisher("codeium", "windsurf"), AgentFlavor::Windsurf);
        assert_eq!(flavor_from_publisher("saoudrizwan", "claude-dev"), AgentFlavor::Cline);
        assert_eq!(flavor_from_publisher("someone", "random-tool"), AgentFlavor::Unknown);
        assert_eq!(flavor_from_publisher("cursor", "cursor-py"), AgentFlavor::Cursor);
    }

    #[test]
    fn scan_extension_root_reads_dir_names_and_hashes_package_json() {
        let dir = tempfile::tempdir().expect("临时目录");
        let root = dir.path().join(".vscode").join("extensions");
        mk_extension(
            dir.path(),
            ".vscode/extensions",
            "anthropic.claude-code-1.2.3",
            Some(r#"{"name":"claude-code"}"#),
        );
        mk_extension(dir.path(), ".vscode/extensions", "someone.random-tool-0.1.0", None);
        std::fs::create_dir_all(root.join("not-an-extension")).expect("建干扰目录");

        let (agents, warnings) = scan_extension_root(&root, 4096);
        assert_eq!(agents.len(), 2, "干扰目录必须被忽略: {agents:?}");
        let claude = agents.iter().find(|a| a.flavor == AgentFlavor::ClaudeCode).expect("claude-code 插件");
        assert_eq!(claude.version.as_deref(), Some("1.2.3"));
        assert!(claude.config_hash.as_deref().is_some_and(|h| !h.is_empty()));
        let random = agents.iter().find(|a| a.flavor == AgentFlavor::Unknown).expect("未知插件也上报");
        assert!(random.config_hash.is_none());
        assert_eq!(warnings.len(), 1, "缺 package.json 应给 warning: {warnings:?}");
    }

    #[test]
    fn host_markers_detected() {
        let dir = tempfile::tempdir().expect("临时目录");
        std::fs::create_dir_all(dir.path().join(".cursor")).expect("建 .cursor");
        std::fs::create_dir_all(dir.path().join(".claude")).expect("建 .claude");
        let agents = scan_host_markers(dir.path());
        assert_eq!(agents.len(), 2);
        assert!(agents.iter().any(|a| a.flavor == AgentFlavor::Cursor));
        assert!(agents.iter().any(|a| a.flavor == AgentFlavor::ClaudeCode));
    }

    #[test]
    fn collect_aggregates_roots_and_markers() {
        let dir = tempfile::tempdir().expect("临时目录");
        mk_extension(dir.path(), ".cursor/extensions", "anthropic.claude-code-2.0.0", Some("{}"));
        mk_extension(dir.path(), ".vscode/extensions", "github.copilot-chat-0.24.0", Some("{}"));
        std::fs::create_dir_all(dir.path().join(".continue")).expect("建 .continue");

        let ctx = CollectContext::for_current_user().with_home(dir.path());
        let outcome = collect(&ctx);
        assert!(outcome.is_ok());
        assert_eq!(outcome.items.len(), 4, "两个插件 + `.cursor`/`.continue` 宿主目录: {:?}", outcome.items);
        assert!(outcome.scope.iter().any(|s| s.contains(".cursor")));
        assert!(outcome.scope.iter().any(|s| s.contains(".vscode")));
        assert!(outcome.items.iter().any(|a| a.flavor == AgentFlavor::Copilot));
        assert!(outcome.items.iter().any(|a| a.flavor == AgentFlavor::Custom));
        let cursor = outcome.items.iter().find(|a| a.flavor == AgentFlavor::Cursor).expect("宿主目录应上报 Cursor");
        assert!(cursor.config_dir.clone().unwrap_or_default().ends_with(".cursor"));

        // 无插件根目录时不应报错
        let empty = tempfile::tempdir().expect("临时目录");
        let outcome = collect(&CollectContext::for_current_user().with_home(empty.path()));
        assert!(outcome.is_ok());
        assert!(outcome.items.is_empty());
        assert!(outcome.scope.is_empty());
    }

    #[test]
    fn sensitive_extension_detection() {
        assert!(is_sensitive_extension("vault-secrets"));
        assert!(is_sensitive_extension("API_KEY_manager"));
        assert!(!is_sensitive_extension("theme-dracula"));
        assert!(is_ai_related(AgentFlavor::Cursor));
        assert!(is_ai_related(AgentFlavor::Custom));
        assert!(!is_ai_related(AgentFlavor::Unknown), "未知类型不下结论（服务端研判）");
    }
}
