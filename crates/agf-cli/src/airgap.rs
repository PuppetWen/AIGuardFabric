//! `agfctl airgap bundle|verify` — 气隙离线包导出与校验（§4.10）。
//!
//! ## 离线包里放什么
//!
//! | 来源 | 内容 | 缺失时 |
//! |---|---|---|
//! | `rules/` | 检测规则包（YAML，目录名即安全域） | 报错（规则是平台核心资产，缺了离线包没有意义） |
//! | `redteam/` | 红队用例库（200+ YAML 剧本） | 报错 |
//! | `deploy/sql/migrations/` | 数据库迁移（只向前） | 报错 |
//! | `deploy/sql/migration_parts/` | 历史 0001 四分片（合并后校验和不变） | 报错 |
//! | `parsers/` | 日志解析器配置（可选） | **如实标注 `present=false` 继续** |
//! | `manifest.json` | 每个文件的相对路径/字节数/sha256 + 生成时间 + 版本 | 由本命令生成 |
//!
//! 导出采用「先清空目标目录里的清单外文件、再复制」的策略，保证
//! `airgap verify` 立刻可过——否则上一次导出的残留文件会被判为"清单外文件"。

use std::path::{Path, PathBuf};

use crate::error::{AppError, Exit};
use crate::manifest::{Manifest, SourceState, collect_files, normalize_relative, now_rfc3339};

/// 离线包清单文件名。
pub const MANIFEST_FILE: &str = "manifest.json";

/// 必需的来源目录（缺失即失败）。
pub const REQUIRED_SOURCES: [&str; 4] = ["rules", "redteam", "deploy/sql/migrations", "deploy/sql/migration_parts"];

/// 初始迁移必须全部随离线包交付。
pub const INITIAL_MIGRATION_PARTS: [&str; 4] = [
    "deploy/sql/migration_parts/0001_init_01.sql",
    "deploy/sql/migration_parts/0001_init_02.sql",
    "deploy/sql/migration_parts/0001_init_03.sql",
    "deploy/sql/migration_parts/0001_init_04.sql",
];

/// 可选的来源目录（缺失时降级并在清单里标注）。
pub const OPTIONAL_SOURCES: [&str; 1] = ["parsers"];

/// 一个来源目录的收集说明。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSpec {
    /// 来源标识（清单里的 `name`）。
    pub name: String,
    /// 相对项目根的路径。
    pub path: String,
    /// 是否必需。
    pub required: bool,
}

/// 全部来源定义（顺序即清单展示顺序）。
#[must_use]
pub fn source_specs() -> Vec<SourceSpec> {
    let mut out: Vec<SourceSpec> = REQUIRED_SOURCES
        .iter()
        .map(|p| SourceSpec { name: (*p).to_string(), path: (*p).to_string(), required: true })
        .collect();
    out.extend(OPTIONAL_SOURCES.iter().map(|p| SourceSpec {
        name: (*p).to_string(),
        path: (*p).to_string(),
        required: false,
    }));
    out
}

/// `airgap bundle --out <目录> [--project-root <目录>]`。
///
/// # Errors
/// 必需来源缺失、复制文件失败、清单写入失败。
pub fn bundle(out: &Path, project_root: &Path, version: &str, output: crate::output::Output) -> Result<(), AppError> {
    let specs = source_specs();
    let mut states: Vec<SourceState> = Vec::new();
    let mut missing_required: Vec<String> = Vec::new();

    for spec in &specs {
        let dir = project_root.join(&spec.path);
        let present = dir.is_dir();
        let files = if present { collect_files(&dir)? } else { Vec::new() };
        if spec.required && files.is_empty() {
            missing_required.push(spec.path.clone());
        }
        states.push(SourceState { name: spec.name.clone(), path: spec.path.clone(), present, files: files.len() });
    }

    if !missing_required.is_empty() {
        return Err(AppError::Exit(Exit::failed(format!(
            "离线包导出中止：必需来源目录缺失或为空 {}（用 --project-root 指定项目根）",
            missing_required.join("、")
        ))));
    }
    for part in INITIAL_MIGRATION_PARTS {
        if !project_root.join(part).is_file() {
            return Err(AppError::Exit(Exit::failed(format!("离线包导出中止：缺少初始迁移分片 {part}"))));
        }
    }

    std::fs::create_dir_all(out)?;
    let out_abs = out.canonicalize().unwrap_or_else(|_| out.to_path_buf());
    clean_stale(out)?;

    let mut written: Vec<PathBuf> = Vec::new();
    for spec in &specs {
        let src = project_root.join(&spec.path);
        if !src.is_dir() {
            continue;
        }
        for file in collect_files(&src)? {
            let rel = normalize_relative(project_root, &file)?;
            let dest = out_abs.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&file, &dest)?;
            written.push(dest);
        }
    }

    let manifest = Manifest::build(&out_abs, &written, states.clone(), "agfctl airgap bundle", version, now_rfc3339())?;
    manifest.save(&out_abs.join(MANIFEST_FILE))?;

    let skipped: Vec<&SourceState> = states.iter().filter(|s| !s.present).collect();
    if output.is_json() {
        output.emit(&serde_json::json!({
            "out": out_abs.to_string_lossy().replace('\\', "/"),
            "version": version,
            "generated_at": manifest.generated_at,
            "files": manifest.len(),
            "bytes": manifest.total_bytes(),
            "sources": states,
        }))?;
    } else {
        output.line(&format!("离线包已导出：{}", out_abs.display()));
        output.line(&format!("  版本: {version}  生成时间: {}", manifest.generated_at));
        output.line(&format!("  文件: {} 个，共 {} 字节", manifest.len(), manifest.total_bytes()));
        for state in &states {
            output.line(&format!(
                "  来源 {:<24} {:<10} {} 个文件",
                state.path,
                if state.present { "已纳入" } else { "缺失" },
                state.files
            ));
        }
        for state in skipped {
            output.line(&format!("  说明：可选来源 {} 不存在，未纳入离线包；补齐目录后重新导出", state.path));
        }
    }
    Ok(())
}

/// `airgap verify --dir <目录>`。
///
/// # Errors
/// 清单缺失/非法（退出码 1），或目录遍历失败。
pub fn verify(dir: &Path, output: crate::output::Output) -> Result<(), AppError> {
    let manifest_path = dir.join(MANIFEST_FILE);
    if !manifest_path.is_file() {
        return Err(AppError::Exit(Exit::failed(format!(
            "离线包校验失败：{} 不存在（该目录不是 agfctl airgap bundle 的产物）",
            manifest_path.display()
        ))));
    }
    let manifest = Manifest::load(&manifest_path)?;
    if manifest.manifest_version != crate::manifest::MANIFEST_VERSION {
        return Err(AppError::Exit(Exit::failed(format!(
            "离线包清单版本 {} 不受支持（当前支持 {}）",
            manifest.manifest_version,
            crate::manifest::MANIFEST_VERSION
        ))));
    }
    let mut report = manifest.verify(dir, &[MANIFEST_FILE])?;
    for required in REQUIRED_SOURCES {
        if !manifest.sources.iter().any(|source| source.path == required && source.present && source.files > 0) {
            report.issues.push(format!("离线包缺少必需来源: {required}"));
        }
    }
    let listed = manifest.paths();
    for part in INITIAL_MIGRATION_PARTS {
        if !listed.contains(part) {
            report.issues.push(format!("离线包缺少初始迁移分片: {part}"));
        }
    }

    if output.is_json() {
        output.emit(&serde_json::json!({
            "dir": dir.to_string_lossy().replace('\\', "/"),
            "version": manifest.version,
            "generated_at": manifest.generated_at,
            "checked": report.checked,
            "expected": report.expected,
            "ok": report.is_ok(),
            "issues": report.issues,
        }))?;
    } else {
        output.line(&format!(
            "校验目录: {}（发布版本 {}，生成于 {}）",
            dir.display(),
            manifest.version,
            manifest.generated_at
        ));
        output.line(&report.summary_line());
        for issue in &report.issues {
            output.line(&format!("  - {issue}"));
        }
    }

    if report.is_ok() { Ok(()) } else { Err(AppError::Exit(Exit::failed("离线包校验未通过"))) }
}

/// 清理目标目录中不属于本次导出的历史残留文件（保留目录结构，删除空目录）。
fn clean_stale(out: &Path) -> anyhow::Result<()> {
    for file in collect_files(out)? {
        let name = file.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        if name == MANIFEST_FILE {
            continue;
        }
        std::fs::remove_file(&file)?;
    }
    // 自底向上删除空目录（避免上次导出的目录结构残留）
    let mut dirs: Vec<PathBuf> = walkdir::WalkDir::new(out)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_dir() && e.path() != out)
        .map(|e| e.path().to_path_buf())
        .collect();
    dirs.sort_by_key(|d| std::cmp::Reverse(d.components().count()));
    for dir in dirs {
        if std::fs::read_dir(&dir).map(|mut it| it.next().is_none()).unwrap_or(false) {
            let _ = std::fs::remove_dir(&dir);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Output;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("agf-airgap-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("建临时目录");
        dir
    }

    fn seed_project(root: &Path) {
        let files: [(&str, &str); 9] = [
            ("rules/prompt-attack/pa-001.yaml", "key: PA-001"),
            ("rules/credential-leak/cl-001.yaml", "key: CL-001"),
            ("redteam/jailbreak/rt-jb-001.yaml", "key: RT-JB-001"),
            ("deploy/sql/migrations/0002_followup.sql", "SELECT 1;"),
            ("deploy/sql/migration_parts/0001_init_01.sql", "SELECT 1;"),
            ("deploy/sql/migration_parts/0001_init_02.sql", "SELECT 2;"),
            ("deploy/sql/migration_parts/0001_init_03.sql", "SELECT 3;"),
            ("deploy/sql/migration_parts/0001_init_04.sql", "SELECT 4;"),
            ("parsers/README.md", "# parsers"),
        ];
        for (rel, content) in files {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().expect("有父目录")).expect("建父目录");
            std::fs::write(path, content).expect("写文件");
        }
    }

    #[test]
    fn source_specs_keep_optional_parsers_last_and_flagged() {
        let specs = source_specs();
        assert_eq!(specs.len(), 5);
        assert_eq!(specs.iter().filter(|s| s.required).count(), 4);
        let parsers = specs.iter().find(|s| s.path == "parsers").expect("包含 parsers");
        assert!(!parsers.required, "parsers 是可选来源");
        assert_eq!(specs.last().map(|s| s.path.as_str()), Some("parsers"));
    }

    #[test]
    fn missing_optional_source_is_tolerated_and_recorded() {
        let project = temp_dir("proj-no-parsers");
        seed_project(&project);
        std::fs::remove_dir_all(project.join("parsers")).expect("删 parsers");
        let out = temp_dir("bundle-no-parsers");
        let res = bundle(&out, &project, "0.1.0", Output::silent());
        assert!(res.is_ok(), "缺可选来源不应失败: {:?}", res.err().map(|e| e.to_string()));
        let manifest = Manifest::load(&out.join(MANIFEST_FILE)).expect("载入清单");
        let parsers = manifest.sources.iter().find(|s| s.name == "parsers").expect("有 parsers 记录");
        assert!(!parsers.present);
        assert_eq!(parsers.files, 0);
        let _ = std::fs::remove_dir_all(&project);
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn missing_migration_parts_fails_with_clear_reason() {
        let project = temp_dir("proj-no-migration-parts");
        seed_project(&project);
        std::fs::remove_dir_all(project.join("deploy/sql/migration_parts")).expect("删迁移分片");
        let out = temp_dir("bundle-no-migration-parts");
        let err = bundle(&out, &project, "0.1.0", Output::silent()).expect_err("缺必需来源必须失败");
        assert_eq!(err.exit_code(), 1, "内容缺失属于判定失败而非依赖不可用");
        let msg = err.to_string();
        assert!(msg.contains("deploy/sql/migration_parts"), "错误信息应指出缺失的目录: {msg}");
        let _ = std::fs::remove_dir_all(&project);
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn missing_one_migration_part_fails_before_export() {
        let project = temp_dir("proj-missing-part");
        seed_project(&project);
        std::fs::remove_file(project.join(INITIAL_MIGRATION_PARTS[3])).expect("删第四分片");
        let out = temp_dir("bundle-missing-part");
        let err = bundle(&out, &project, "0.1.0", Output::silent()).expect_err("缺分片必须失败");
        assert!(err.to_string().contains("0001_init_04.sql"));
        let _ = std::fs::remove_dir_all(&project);
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn verify_rejects_older_bundle_without_migration_parts() {
        let project = temp_dir("proj-old-bundle");
        seed_project(&project);
        let out = temp_dir("bundle-old-layout");
        bundle(&out, &project, "0.1.0", Output::silent()).expect("导出");
        let mut manifest = Manifest::load(&out.join(MANIFEST_FILE)).expect("载入清单");
        manifest.sources.retain(|source| source.path != "deploy/sql/migration_parts");
        manifest.files.retain(|file| !file.path.starts_with("deploy/sql/migration_parts/"));
        manifest.save(&out.join(MANIFEST_FILE)).expect("写旧清单");
        std::fs::remove_dir_all(out.join("deploy/sql/migration_parts")).expect("模拟旧包缺分片");
        let err = verify(&out, Output::silent()).expect_err("旧包不能通过新版本校验");
        assert_eq!(err.exit_code(), 1);
        let _ = std::fs::remove_dir_all(&project);
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn bundle_then_verify_roundtrip_is_clean_and_rebundle_drops_stale_files() {
        let project = temp_dir("proj-roundtrip");
        seed_project(&project);
        let out = temp_dir("bundle-roundtrip");
        bundle(&out, &project, "0.1.0", Output::silent()).expect("导出");
        let manifest = Manifest::load(&out.join(MANIFEST_FILE)).expect("载入清单");
        assert_eq!(manifest.len(), 9, "全部 9 个来源文件都应纳入");
        assert_eq!(manifest.paths().len(), 9);
        for part in 1..=4 {
            let path = format!("deploy/sql/migration_parts/0001_init_{part:02}.sql");
            assert!(manifest.paths().contains(path.as_str()), "离线包缺少 {path}");
        }
        verify(&out, Output::silent()).expect("校验应通过");

        // 上一次导出的残留文件必须被判出来
        std::fs::write(out.join("rules/stale.yaml"), "stale").expect("写残留");
        assert!(verify(&out, Output::silent()).is_err(), "残留文件应导致校验失败");

        // 重新导出会清理残留，因此再次校验必须通过
        bundle(&out, &project, "0.1.0", Output::silent()).expect("再次导出");
        assert!(!out.join("rules/stale.yaml").exists(), "残留文件应被清理");
        verify(&out, Output::silent()).expect("重新导出后校验应通过");
        let _ = std::fs::remove_dir_all(&project);
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn bundle_output_is_byte_stable_for_unchanged_sources() {
        let project = temp_dir("proj-stable");
        seed_project(&project);
        let out1 = temp_dir("bundle-stable-1");
        let out2 = temp_dir("bundle-stable-2");
        bundle(&out1, &project, "0.1.0", Output::silent()).expect("导出1");
        bundle(&out2, &project, "0.1.0", Output::silent()).expect("导出2");
        let m1 = Manifest::load(&out1.join(MANIFEST_FILE)).expect("载入1");
        let m2 = Manifest::load(&out2.join(MANIFEST_FILE)).expect("载入2");
        assert_eq!(m1.files, m2.files, "同一来源两次导出的文件清单必须逐字节一致");
        assert_eq!(m1.total_bytes(), m2.total_bytes());
        let _ = std::fs::remove_dir_all(&project);
        let _ = std::fs::remove_dir_all(&out1);
        let _ = std::fs::remove_dir_all(&out2);
    }

    #[test]
    fn verify_without_manifest_fails_with_exit_one() {
        let dir = temp_dir("no-manifest");
        let err = verify(&dir, Output::silent()).expect_err("无清单必须失败");
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains(MANIFEST_FILE));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_rejects_tampered_bundle() {
        let project = temp_dir("proj-tamper");
        seed_project(&project);
        let out = temp_dir("bundle-tamper");
        bundle(&out, &project, "0.1.0", Output::silent()).expect("导出");
        std::fs::write(out.join("rules/prompt-attack/pa-001.yaml"), "key: PA-999").expect("篡改");
        let err = verify(&out, Output::silent()).expect_err("篡改必须被检出");
        assert_eq!(err.exit_code(), 1);
        let _ = std::fs::remove_dir_all(&project);
        let _ = std::fs::remove_dir_all(&out);
    }
}
