//! `agfctl version` — 版本与构建信息（§4.10）。
//!
//! 打印的不只是 semver：出问题时排障第一问是"哪个二进制、哪个目标平台、
//! 哪个源码版本"，因此把编译期已知的信息一次给全。
//!
//! ## 值从哪来
//!
//! 全部来自**编译期**注入（`crates/agf-cli/build.rs`）：
//! `TARGET`（Cargo 给 build script 的目标三元组）、`AGF_BUILD_GIT_SHA`（本地取 `git rev-parse`、
//! 脏工作区带 `-dirty`；**环境变量优先**，CI 可覆盖）、`AGF_BUILD_TIME`（构建时刻 UTC；
//! 同样环境变量优先，便于可复现构建注入固定值）。
//!
//! 因此运行期**不调用任何外部命令、不读系统时钟**——气隙环境行为一致；
//! 拿不到（源码包 / 无 git / 时钟异常）时如实显示 `unknown`，绝不编造。

use serde::Serialize;

use crate::error::AppError;
use crate::output::Output;

/// CI 可注入的构建元数据（build script 的同名读取优先）。
pub const GIT_SHA_ENV: &str = "AGF_BUILD_GIT_SHA";
/// CI 可注入的构建时间（build script 的同名读取优先）。
pub const BUILD_TIME_ENV: &str = "AGF_BUILD_TIME";

/// 构建信息。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildInfo {
    /// 命令行名。
    pub name: String,
    /// 版本。
    pub version: String,
    /// 目标三元组。
    pub target: String,
    /// 构建 profile。
    pub profile: String,
    /// 目标平台。
    pub os: String,
    /// 目标架构。
    pub arch: String,
    /// 是否 Debug 构建。
    pub debug: bool,
    /// git 提交（未知时为 `unknown`）。
    pub git_sha: String,
    /// 构建时间（未知时为 `unknown`）。
    pub build_time: String,
    /// 支持的子命令列表（便于脚本自描述）。
    pub subcommands: Vec<String>,
}

/// 收集构建信息。
#[must_use]
pub fn build_info() -> BuildInfo {
    BuildInfo {
        name: "agfctl".to_string(),
        version: crate::VERSION.to_string(),
        target: option_env!("TARGET").unwrap_or("unknown").to_string(),
        profile: if cfg!(debug_assertions) { "debug" } else { "release" }.to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        debug: cfg!(debug_assertions),
        git_sha: option_env!("AGF_BUILD_GIT_SHA").unwrap_or("unknown").to_string(),
        build_time: option_env!("AGF_BUILD_TIME").unwrap_or("unknown").to_string(),
        subcommands: subcommand_names(),
    }
}

/// 支持的子命令名（唯一来源：[`crate::cli::Command`]）。
#[must_use]
pub fn subcommand_names() -> Vec<String> {
    vec![
        "healthcheck".to_string(),
        "rules verify".to_string(),
        "redteam verify".to_string(),
        "db check-schema".to_string(),
        "migrate".to_string(),
        "genkey".to_string(),
        "backup".to_string(),
        "restore".to_string(),
        "airgap bundle".to_string(),
        "airgap verify".to_string(),
        "version".to_string(),
    ]
}

/// 渲染单行摘要（日志友好）。
#[must_use]
pub fn summary_line(info: &BuildInfo) -> String {
    format!("{} {} ({}, {}, {})", info.name, info.version, info.profile, info.os, info.arch)
}

/// 执行 `version`。
///
/// # Errors
/// 序列化失败。
pub fn run(output: Output) -> Result<(), AppError> {
    let info = build_info();
    if output.is_json() {
        output.emit(&serde_json::json!({ "ok": true, "build": info }))?;
    } else {
        output.line(&summary_line(&info));
        output.line(&format!("目标三元组: {}", info.target));
        output.line(&format!("git 提交: {}", info.git_sha));
        output.line(&format!("构建时间: {}", info.build_time));
        output.line(&format!("子命令: {}", info.subcommands.join(", ")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_info_exposes_version_and_platform() {
        let info = build_info();
        assert_eq!(info.name, "agfctl");
        assert_eq!(info.version, crate::VERSION);
        assert!(!info.version.is_empty());
        assert_eq!(info.os, std::env::consts::OS);
        assert_eq!(info.arch, std::env::consts::ARCH);
        assert_eq!(info.debug, cfg!(debug_assertions));
        assert!(matches!(info.profile.as_str(), "debug" | "release"));
    }

    #[test]
    fn build_info_is_a_compile_time_constant() {
        // 连续两次调用必须逐字段一致 —— 说明它没有在运行期调外部命令或读时钟。
        assert_eq!(build_info(), build_info());
    }

    #[test]
    fn build_metadata_is_injected_at_compile_time() {
        let info = build_info();
        // build script 一定会注入目标三元组（Cargo 提供），不该是空串。
        assert!(!info.target.is_empty(), "目标三元组为空");
        assert_ne!(info.target, "unknown", "build script 未注入 TARGET：{}", info.target);
        // 有 git 时是短 sha（可能带 -dirty）；源码包/无 git 时才是 unknown。
        assert!(info.git_sha == "unknown" || info.git_sha.len() >= 7, "git_sha 形状异常: {}", info.git_sha);
        // 构建时间是 ISO 8601 UTC（秒级）；时钟异常时才是 unknown。
        assert!(
            info.build_time == "unknown" || info.build_time.ends_with('Z'),
            "build_time 形状异常: {}",
            info.build_time
        );
    }

    #[test]
    fn env_overrides_are_honoured_by_the_build_script() {
        // build script 的契约：环境变量优先。这里只断言编译期常量与"环境变量优先"的语义一致 ——
        // 若设置了环境变量，注入值必须等于它（CI 用它做可复现构建）。
        if let Ok(expected) = std::env::var(GIT_SHA_ENV) {
            assert_eq!(build_info().git_sha, expected);
        }
        if let Ok(expected) = std::env::var(BUILD_TIME_ENV) {
            assert_eq!(build_info().build_time, expected);
        }
    }

    #[test]
    fn subcommand_list_matches_cli_surface() {
        let names = subcommand_names();
        assert_eq!(names.len(), 11);
        for expected in [
            "healthcheck",
            "migrate",
            "genkey",
            "backup",
            "restore",
            "version",
            "airgap verify",
            "rules verify",
            "redteam verify",
            "db check-schema",
            "airgap bundle",
        ] {
            assert!(names.iter().any(|n| n == expected), "缺少子命令 {expected}");
        }
    }

    #[test]
    fn summary_line_is_single_line_and_contains_version() {
        let info = build_info();
        let line = summary_line(&info);
        assert!(!line.contains('\n'));
        assert!(line.starts_with("agfctl "));
        assert!(line.contains(&info.version));
    }

    #[test]
    fn json_shape_has_build_object() {
        let info = build_info();
        let value = serde_json::to_value(&info).unwrap_or_default();
        assert!(value.get("version").is_some());
        assert!(value.get("subcommands").is_some());
        assert_eq!(value.get("debug").and_then(serde_json::Value::as_bool), Some(cfg!(debug_assertions)));
    }
}
