#![forbid(unsafe_code)]
// 单元测试用 assert!/unwrap/panic 表达不变量；生产代码的 panic 仍在工作区层被 deny
// （`--all-targets` 下 clippy 会单独编译 `--test` 目标，此时 `test` cfg 生效）。
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]
//! # agf-cli — agfctl 命令行
//!
//! `agfctl` 是 AIGuardFabric（智御矩阵）的运维入口，覆盖提示词 §4.10 的
//! **备份 / 恢复 / 迁移 / 健康自检 / 气隙离线包导出**，以及规则包与红队用例库的自检。
//!
//! ## 子命令与实现程度
//!
//! | 子命令 | 实现 | 复用的既有能力 |
//! |---|---|---|
//! | `healthcheck --url <URL>` | ✅ 真做 | 与 `apps/{server,ingest,scheduler}` 探针行为一致 |
//! | `rules verify --dir <目录>` | ✅ 真做 | `agf-scan` 的 `RulePackLoader::strict` + `SampleRegression::run_pack` |
//! | `redteam verify --dir <目录> [--min-cases N]` | ✅ 真做 | `agf-scan` 的 `CaseLibrary` / `CaseLibraryStats` |
//! | `db check-schema [--url <DSN>]` | ✅ 真做（PG 不可达 → 退出码 2） | `agf-storage::REQUIRED_TABLES` |
//! | `migrate [--url <DSN>] [--dir <目录>]` | ✅ 真做（PG 不可达 → 退出码 2） | 默认内嵌完整项目迁移；自定义目录运行期读取 |
//! | `genkey [--kind jwt\|field\|admin-password] [--out <文件>]` | ✅ 真做 | `agf-core::secret` + `agf-auth::PasswordHasher`（Argon2id） |
//! | `backup --out <目录>` | ✅ 真做（`pg_dump`/PG 缺失 → 退出码 2） | `pg_dump -Fc` + `data-files.zip` + sha256 清单 |
//! | `restore --in <目录>` | ✅ 真做（`pg_restore`/PG 缺失 → 退出码 2） | `pg_restore --clean --if-exists` |
//! | `airgap bundle --out <目录>` | ✅ 真做 | 规则/用例/迁移/解析器 + `manifest.json`（sha256） |
//! | `airgap verify --dir <目录>` | ✅ 真做 | 同上清单的真校验 |
//! | `version` | ✅ 真做 | 编译期构建信息（不依赖外部命令） |
//!
//! ## 退出码契约
//!
//! | 码 | 含义 |
//! |---|---|
//! | 0 | 成功 |
//! | 1 | 判定失败（校验未过 / 探针不健康 / 清单不一致）或意外错误 |
//! | 2 | 外部依赖不可用或尚未验证（PG 不可达、`pg_dump`/`pg_restore` 不存在） |
//!
//! 所有子命令支持全局 `--json`；失败信息走 stderr。
//!
//! ## 未做到 / 待阶段二验证（`TODO(agfctl-*)` 锚点）
//!
//! - `check-schema`/`migrate` 已在独立 PostgreSQL 与已有库验证；`backup`/`restore`
//!   仍需对具体部署的备份与恢复流程验收；
//! - `TODO(agfctl-pg-tools)`：容器拓扑下的 `pg_dump`/`pg_restore` 由
//!   `scripts/{backup,restore}.ps1` 承担（`docker compose exec`），agfctl 侧走本机工具；
//! - 气隙包的解析器清单与恢复流程须在交付环境逐项核对；
//! - 自定义 `--dir` 使用目录内 SQLx 迁移，需由提供者保证迁移集完整。

pub mod airgap;
pub mod archive;
pub mod backup;
pub mod cli;
pub mod db;
pub mod error;
pub mod exit;
pub mod genkey;
pub mod health;
pub mod info;
pub mod manifest;
pub mod output;
pub mod redteam;
pub mod rules;

use std::path::Path;

pub use cli::{AirgapCommand, Cli, Command, DbCommand, GlobalArgs, KeyKind, RedteamCommand, RulesCommand};
pub use error::{AppError, Exit};
pub use output::Output;

/// 平台版本。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 执行一条命令（供 `main` 与集成测试共用）。
///
/// # Errors
/// 参见 [`AppError`]；退出码经 [`AppError::exit_code`] 映射。
pub async fn run(cli: Cli) -> Result<(), AppError> {
    run_with_project_root(cli, None).await
}

/// 带显式项目根的执行入口（`airgap bundle` 用；`None` = 当前工作目录）。
///
/// # Errors
/// 同 [`run`]。
pub async fn run_with_project_root(cli: Cli, project_root: Option<&Path>) -> Result<(), AppError> {
    let output = Output::new(cli.global.json);
    match cli.command {
        Command::Healthcheck { url, timeout_secs } => health::run(&url, timeout_secs, output).await,
        Command::Rules { command: RulesCommand::Verify { dir } } => rules::run(&dir, output),
        Command::Redteam { command: RedteamCommand::Verify { dir, min_cases } } => {
            redteam::run(&dir, min_cases, output)
        }
        Command::Db { command: DbCommand::CheckSchema { url } } => db::check_schema(url.as_deref(), output).await,
        Command::Migrate { url, dir } => db::migrate(url.as_deref(), dir.as_deref(), output).await,
        Command::Genkey { kind, out } => genkey::run(kind, out, output),
        Command::Backup { out, skip_data, url } => {
            backup::backup(out.as_deref(), skip_data, url.as_deref(), output).await
        }
        Command::Restore { input, with_data, no_pre_backup, force, url } => {
            backup::restore(&input, with_data, no_pre_backup, force, url.as_deref(), output).await
        }
        Command::Airgap { command: AirgapCommand::Bundle { out, project_root: cli_root } } => {
            let root = cli_root.as_deref().or(project_root).unwrap_or_else(|| Path::new("."));
            airgap::bundle(&out, root, VERSION, output)
        }
        Command::Airgap { command: AirgapCommand::Verify { dir } } => airgap::verify(&dir, output),
        Command::Version => info::run(output),
    }
}

/// 加载 `.env`（不存在时静默）。
///
/// # Errors
/// `.env` 存在但无法解析（而非"文件不存在"）。
pub fn load_dotenv() -> Result<(), AppError> {
    match dotenvy::dotenv() {
        Ok(_) => Ok(()),
        Err(dotenvy::Error::Io(_)) => Ok(()),
        Err(e) => Err(AppError::Fatal(anyhow::anyhow!(".env 解析失败: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    #[test]
    fn version_constant_is_nonempty() {
        assert!(!VERSION.is_empty());
    }

    #[tokio::test]
    async fn version_subcommand_succeeds() {
        let cli = Cli::try_parse_from(["agfctl", "version"]).expect("解析 version");
        assert!(run(cli).await.is_ok());
    }

    #[tokio::test]
    async fn unsupported_kind_paths_are_reachable_through_run() {
        // 目录不存在的两条路径必须给出退出码 1，而不是 panic
        let cli = Cli::try_parse_from(["agfctl", "rules", "verify", "--dir", "Z:/nope/rules"]).expect("解析");
        let err = run(cli).await.expect_err("应失败");
        assert_eq!(err.exit_code(), 1);

        let cli = Cli::try_parse_from(["agfctl", "airgap", "verify", "--dir", "Z:/nope/bundle"]).expect("解析");
        let err = run(cli).await.expect_err("应失败");
        assert_eq!(err.exit_code(), 1);
    }

    #[tokio::test]
    async fn healthcheck_against_closed_port_returns_exit_one_via_run() {
        let cli = Cli::try_parse_from([
            "agfctl",
            "healthcheck",
            "--url",
            "http://127.0.0.1:1/healthz",
            "--timeout-secs",
            "2",
        ])
        .expect("解析");
        let err = run(cli).await.expect_err("不可达应失败");
        assert_eq!(err.exit_code(), exit::VALIDATION_FAILED);
    }
}
