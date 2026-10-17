//! 工具与 Skill 目录扫描（三大桌面系统共用用户目录实现）。
//!
//! 覆盖四类真实落盘形态（相对用户主目录）：
//!
//! | 来源 | 认定规则 |
//! |---|---|
//! | `.claude/skills/<name>/SKILL.md` | 每个子目录一项 `skill` |
//! | `.claude/commands/*.md` | 每个 `.md` 一项 `command` |
//! | `.cursor/rules/*` | 每个文件一项 `rule` |
//! | `.codeium/windsurf/global_rules.md` | 单项 `rule` |
//!
//! ## 降级行为
//!
//! | 情况 | 行为 |
//! |---|---|
//! | 目录不存在 | 跳过（正常情况） |
//! | 子目录缺 `SKILL.md` | 不上报该目录（避免把普通目录当 Skill） |
//! | 文件名不可读/非 UTF-8 | 用 lossy 名称占位，不失败 |
//! | Linux/macOS | 共用目录规则；Linux 容器验证，macOS 仍需真机验证 |

use std::path::Path;

use super::{CollectContext, CollectorOutcome};
use crate::payload::DetectedSkill;

/// 采集器名。
pub const NAME: &str = "skills";

/// Skill 根目录（相对用户主目录）。
pub const SKILL_ROOTS: [&str; 3] = [".claude/skills", ".cursor/skills", ".windsurf/skills"];

/// Command 目录（相对用户主目录）。
pub const COMMAND_ROOTS: [&str; 2] = [".claude/commands", ".continue/prompts"];

/// Rule 目录/文件（相对用户主目录）。
pub const RULE_ROOTS: [&str; 3] = [".cursor/rules", ".windsurf/rules", ".codeium/windsurf"];

/// 扫描 Skill 目录（每个含 `SKILL.md` 的子目录计一项）。
#[must_use]
pub fn scan_skill_root(root: &Path) -> Vec<DetectedSkill> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else { return out };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let dir = entry.path();
        let manifest = dir.join("SKILL.md");
        if !manifest.is_file() {
            continue;
        }
        out.push(detected(&manifest, entry.file_name().to_string_lossy().to_string(), "skill"));
    }
    out
}

/// 扫描文件型目录（`*.md` / 任意文件）。
#[must_use]
pub fn scan_file_root(root: &Path, kind: &str, only_markdown: bool) -> Vec<DetectedSkill> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else { return out };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else { continue };
        if !file_type.is_file() {
            continue;
        }
        let path = entry.path();
        if only_markdown && !path.extension().is_some_and(|e| e.eq_ignore_ascii_case("md")) {
            continue;
        }
        let name = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        out.push(detected(&path, name, kind));
    }
    out
}

fn detected(path: &Path, name: String, kind: &str) -> DetectedSkill {
    let (hash, status) = match super::skill_hash::content_hash(path) {
        Ok(hash) => (Some(hash), "verified"),
        Err(reason) => (None, reason),
    };
    DetectedSkill {
        package: (kind == "skill").then(|| super::skill_package::observe(path.parent().unwrap_or(path))),
        source_path: path.display().to_string(),
        name,
        kind: kind.into(),
        content_sha256: hash,
        content_hash_status: Some(status.into()),
    }
}

/// 执行采集。
#[must_use]
pub fn collect(ctx: &CollectContext) -> CollectorOutcome<DetectedSkill> {
    if crate::platform::current() == crate::platform::HostPlatform::Other {
        return CollectorOutcome::unsupported(NAME, "Skill 采集不支持当前平台".to_string());
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
    for rel in SKILL_ROOTS {
        let root = ctx.home.join(rel);
        if !root.is_dir() {
            continue;
        }
        outcome.scope.push(root.display().to_string());
        outcome.items.extend(scan_skill_root(&root));
    }
    for rel in COMMAND_ROOTS {
        let root = ctx.home.join(rel);
        if !root.is_dir() {
            continue;
        }
        outcome.scope.push(root.display().to_string());
        outcome.items.extend(scan_file_root(&root, "command", true));
    }
    for rel in RULE_ROOTS {
        let root = ctx.home.join(rel);
        if !root.is_dir() {
            continue;
        }
        outcome.scope.push(root.display().to_string());
        let mut found = scan_file_root(&root, "rule", false);
        found.retain(|skill| {
            Path::new(&skill.source_path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("md") || ext.eq_ignore_ascii_case("mdc"))
        });
        found.retain(|skill| skill.source_path.contains("rule") || skill.source_path.contains("windsurf"));
        outcome.items.extend(found);
    }
    outcome
        .items
        .sort_by(|a, b| (a.source_path.as_str(), a.name.as_str()).cmp(&(b.source_path.as_str(), b.name.as_str())));
    outcome.items.dedup_by(|a, b| a.source_path == b.source_path);
    for skill in &outcome.items {
        if skill.content_sha256.is_none() {
            outcome.warnings.push(format!(
                "Skill content hash unavailable: {} ({})",
                skill.source_path,
                skill.content_hash_status.as_deref().unwrap_or("unknown")
            ));
        }
    }
    for skill in &outcome.items {
        if let Some(package) = &skill.package {
            if package.sha256.is_none() {
                outcome.warnings.push(format!(
                    "Skill package observation unavailable: {} ({:?})",
                    skill.source_path, package.status
                ));
            }
        }
    }
    outcome.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skill_root_requires_manifest() {
        let dir = tempfile::tempdir().expect("临时目录");
        let root = dir.path().join(".claude").join("skills");
        std::fs::create_dir_all(root.join("pdf-tools")).expect("建目录");
        std::fs::write(root.join("pdf-tools").join("SKILL.md"), "# pdf").expect("写 SKILL.md");
        std::fs::create_dir_all(root.join("not-a-skill")).expect("建目录");

        let skills = scan_skill_root(&root);
        assert_eq!(skills.len(), 1, "缺 SKILL.md 的目录不得上报: {skills:?}");
        assert_eq!(skills[0].name, "pdf-tools");
        assert_eq!(skills[0].kind, "skill");
        assert!(skills[0].source_path.ends_with("SKILL.md"));
    }

    #[test]
    fn file_root_filters_markdown() {
        let dir = tempfile::tempdir().expect("临时目录");
        let root = dir.path().join("commands");
        std::fs::create_dir_all(&root).expect("建目录");
        std::fs::write(root.join("review.md"), "x").expect("写");
        std::fs::write(root.join("notes.txt"), "x").expect("写");
        let marked = scan_file_root(&root, "command", true);
        assert_eq!(marked.len(), 1);
        assert_eq!(marked[0].name, "review");
        let all = scan_file_root(&root, "rule", false);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn missing_roots_yield_empty_without_error() {
        let dir = tempfile::tempdir().expect("临时目录");
        assert!(scan_skill_root(&dir.path().join("nope")).is_empty());
        assert!(scan_file_root(&dir.path().join("nope"), "rule", true).is_empty());
    }

    #[test]
    fn collect_aggregates_skill_command_and_rule_sources() {
        let dir = tempfile::tempdir().expect("临时目录");
        let skills = dir.path().join(".claude").join("skills").join("audit");
        std::fs::create_dir_all(&skills).expect("建目录");
        std::fs::write(skills.join("SKILL.md"), "# audit").expect("写");
        let commands = dir.path().join(".claude").join("commands");
        std::fs::create_dir_all(&commands).expect("建目录");
        std::fs::write(commands.join("triage.md"), "# triage").expect("写");
        let rules = dir.path().join(".cursor").join("rules");
        std::fs::create_dir_all(&rules).expect("建目录");
        std::fs::write(rules.join("rules.md"), "# rules").expect("写");

        let ctx = CollectContext::for_current_user().with_home(dir.path());
        let outcome = collect(&ctx);
        assert!(outcome.is_ok());
        assert_eq!(outcome.items.len(), 3, "{:?}", outcome.items);
        assert!(outcome.items.iter().any(|s| s.kind == "skill"));
        assert!(outcome.items.iter().any(|s| s.kind == "command"));
        assert!(outcome.items.iter().any(|s| s.kind == "rule"));
        assert_eq!(outcome.scope.len(), 3);
    }

    #[test]
    fn collect_with_empty_home_is_clean() {
        let dir = tempfile::tempdir().expect("临时目录");
        let ctx = CollectContext::for_current_user().with_home(dir.path());
        let outcome = collect(&ctx);
        assert!(outcome.is_ok());
        assert!(outcome.items.is_empty());
        assert!(outcome.scope.is_empty());
    }
}
