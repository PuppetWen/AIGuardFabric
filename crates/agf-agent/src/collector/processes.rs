//! AI 相关进程扫描（Windows/Linux/macOS 共用 `sysinfo`）。
//!
//! 只上报**命中 AI Agent 特征**的进程（可执行名或命令行含 `claude`/`cursor`/`codex`/`ollama` …），
//! 不做全量进程清单——避免把终端变成"进程监控器"（最小采集原则）。
//!
//! ## 降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 无权限读取某进程名/命令行 | 跳过该进程（不报错、不 panic） |
//! | 未命中任何 AI 特征 | 产出空列表（正常情况） |
//! | 上下文关闭进程采集 | 上层记 `skipped` 状态（见 [`skipped_outcome`]） |
//! | Linux/macOS | 复用 `sysinfo`；Linux 容器已运行，macOS 待真机验证 |

use agf_core::agent::AgentFlavor;

use super::{CollectContext, CollectorOutcome};
use crate::payload::DetectedProcess;

/// 采集器名。
pub const NAME: &str = "processes";

/// AI Agent 进程特征表：`(可执行名关键词, 命令行关键词, Agent 类型)`。
pub const PROCESS_SIGNATURES: [(&str, &str, AgentFlavor); 12] = [
    ("claude", "claude", AgentFlavor::ClaudeCode),
    ("cursor", "cursor", AgentFlavor::Cursor),
    ("windsurf", "windsurf", AgentFlavor::Windsurf),
    ("codeium", "codeium", AgentFlavor::Windsurf),
    ("copilot", "copilot", AgentFlavor::Copilot),
    ("codex", "codex", AgentFlavor::OpenAiAgents),
    ("ollama", "ollama", AgentFlavor::Custom),
    ("lmstudio", "lm studio", AgentFlavor::Custom),
    ("dify", "dify", AgentFlavor::Dify),
    ("coze", "coze", AgentFlavor::Coze),
    ("n8n", "n8n", AgentFlavor::N8n),
    ("python", "langgraph", AgentFlavor::LangGraph),
];

/// 由进程名与命令行推断 Agent 类型（纯函数）。
#[must_use]
pub fn classify_process(name: &str, cmdline: &str) -> Option<AgentFlavor> {
    let name_lower = name.to_ascii_lowercase();
    let cmd_lower = cmdline.to_ascii_lowercase();
    for (name_key, cmd_key, flavor) in PROCESS_SIGNATURES {
        if name_lower.contains(name_key) || cmd_lower.contains(cmd_key) {
            return Some(flavor);
        }
    }
    None
}

/// "已关闭"状态（不采集但不报错）。
#[must_use]
pub fn skipped_outcome() -> CollectorOutcome<DetectedProcess> {
    CollectorOutcome::skipped(NAME, "进程采集已在上下文中关闭（低开销模式）")
}

/// 执行采集（Windows/Linux/macOS：`sysinfo`）。
#[must_use]
pub fn collect(ctx: &CollectContext) -> CollectorOutcome<DetectedProcess> {
    if crate::platform::current() == crate::platform::HostPlatform::Other {
        return CollectorOutcome::unsupported(NAME, "进程采集不支持当前平台".to_string());
    }
    let started = std::time::Instant::now();
    let mut outcome = CollectorOutcome {
        name: NAME,
        items: Vec::new(),
        credential_hits: Vec::new(),
        scope: vec!["process:list".to_string()],
        warnings: Vec::new(),
        level: crate::platform::SupportLevel::Implemented,
        elapsed_ms: 0,
        error: None,
    };
    let system = sysinfo::System::new_all();
    let mut scanned = 0_usize;
    for (pid, process) in system.processes() {
        scanned += 1;
        let name = process.name().to_string_lossy().to_string();
        let cmdline = process.cmd().iter().map(|c| c.to_string_lossy()).collect::<Vec<_>>().join(" ");
        if let Some(flavor) = classify_process(&name, &cmdline) {
            outcome.items.push(DetectedProcess { pid: pid.as_u32(), name, flavor: Some(flavor.as_str().to_string()) });
        }
    }
    outcome.scope.push(format!("process:scanned={scanned}"));
    outcome.items.sort_by_key(|p| p.pid);
    if scanned == 0 {
        outcome.warnings.push("未能枚举任何进程（权限受限或平台异常）".to_string());
    }
    if !ctx.home_available() {
        outcome.warnings.push("home 目录不可用（不影响进程采集）".to_string());
    }
    outcome.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_matrix() {
        assert_eq!(classify_process("claude.exe", "claude --resume"), Some(AgentFlavor::ClaudeCode));
        assert_eq!(classify_process("Cursor.exe", ""), Some(AgentFlavor::Cursor));
        assert_eq!(classify_process("node.exe", "npx @anthropic-ai/claude-code"), Some(AgentFlavor::ClaudeCode));
        assert_eq!(classify_process("python.exe", "python -m langgraph.server"), Some(AgentFlavor::LangGraph));
        assert_eq!(classify_process("ollama.exe", "ollama serve"), Some(AgentFlavor::Custom));
        assert_eq!(classify_process("explorer.exe", ""), None);
        assert_eq!(classify_process("chrome.exe", "--type=renderer"), None);
    }

    #[test]
    fn skipped_outcome_is_not_an_error() {
        let outcome = skipped_outcome();
        assert_eq!(outcome.name, NAME);
        assert!(outcome.items.is_empty());
        assert!(outcome.is_ok(), "关闭采集不是错误");
        assert!(!outcome.warnings.is_empty());
    }

    #[test]
    fn collect_returns_only_ai_related_processes() {
        let dir = tempfile::tempdir().expect("临时目录");
        let ctx = CollectContext::for_current_user().with_home(dir.path());
        let outcome = collect(&ctx);
        assert!(outcome.is_ok());
        assert!(outcome.scope.iter().any(|s| s.starts_with("process:scanned=")), "{:?}", outcome.scope);
        for process in &outcome.items {
            assert!(
                classify_process(&process.name, "").is_some() || process.flavor.is_some(),
                "只允许上报命中特征的进程: {process:?}"
            );
        }
    }

    #[test]
    fn collect_does_not_depend_on_home_existing() {
        let ctx = CollectContext::for_current_user().with_home(std::path::PathBuf::from("Z:\\definitely-missing"));
        let outcome = collect(&ctx);
        assert!(outcome.is_ok(), "home 不存在不得影响进程采集");
        assert!(outcome.warnings.iter().any(|w| w.contains("home")));
    }
}
