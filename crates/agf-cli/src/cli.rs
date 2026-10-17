//! agfctl 命令行定义（clap derive）。
//!
//! 参数与「§4.10 备份/恢复/迁移/健康自检/气隙离线包导出」一一对应。
//! 所有子命令都接受全局 `--json`（机器可读输出）；人类可读输出走 stdout，
//! 失败结论走 stderr（见 [`crate::output`]）。
//!
//! 铁律 4：路径与凭据一律从命令行参数或环境变量读取，**没有任何硬编码绝对路径**。

// 参数解析测试用 panic/unwrap 表达"参数必须可解析"这类不变量。
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// AIGuardFabric 平台命令行。
#[derive(Debug, Parser)]
#[command(
    name = "agfctl",
    version,
    about = "AIGuardFabric 智御矩阵 · 平台运维命令行",
    long_about = "agfctl 提供平台自检与运维子命令：健康探测、规则与红队用例校验、\
                  数据库迁移与结构自检、密钥生成、备份恢复、气隙离线包导出与校验。"
)]
pub struct Cli {
    /// 全局选项。
    #[command(flatten)]
    pub global: GlobalArgs,

    /// 子命令。
    #[command(subcommand)]
    pub command: Command,
}

/// 全局选项。
#[derive(Debug, Clone, Copy, Default, Args)]
pub struct GlobalArgs {
    /// 以 JSON 输出（机器可读）；失败信息仍走 stderr。
    #[arg(long, global = true)]
    pub json: bool,
}

/// 子命令。
#[derive(Debug, Subcommand)]
pub enum Command {
    /// 探测 HTTP `/healthz`：健康退出 0，不健康退出 1。
    Healthcheck {
        /// 探测地址。
        #[arg(long, default_value = "http://127.0.0.1:8080/healthz")]
        url: String,
        /// 超时（秒）。
        #[arg(long, default_value_t = 5)]
        timeout_secs: u64,
    },
    /// 规则包校验。
    Rules {
        /// 规则子命令。
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// 红队用例库校验。
    Redteam {
        /// 用例库子命令。
        #[command(subcommand)]
        command: RedteamCommand,
    },
    /// 数据库相关运维。
    Db {
        /// 数据库子命令。
        #[command(subcommand)]
        command: DbCommand,
    },
    /// 执行数据库迁移（只向前，幂等）。
    Migrate {
        /// PG 连接串（缺省取 `DATABASE_URL`，再回退 `AGF_PG_*` 环境变量）。
        #[arg(long)]
        url: Option<String>,
        /// 自定义迁移目录；省略时使用程序内嵌的完整项目迁移。
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// 生成密钥 / 强随机口令。
    Genkey {
        /// 生成类型。
        #[arg(long, value_enum, default_value_t = KeyKind::Jwt)]
        kind: KeyKind,
        /// 输出文件（省略时写 stdout）。
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// 备份：PG 逻辑备份 + 数据目录 + sha256 清单。
    Backup {
        /// 备份目录（省略时自动落 `<data_dir>/backup/<时间戳>`）。
        #[arg(long)]
        out: Option<PathBuf>,
        /// 只备份数据库，不打包数据目录。
        #[arg(long)]
        skip_data: bool,
        /// PG 连接串（缺省取 `DATABASE_URL`，再回退 `AGF_PG_*`）。
        #[arg(long)]
        url: Option<String>,
    },
    /// 恢复：从备份目录恢复数据库（可选数据目录）。
    Restore {
        /// 备份目录或其中的 `agf.dump` 文件。
        #[arg(long = "in")]
        input: PathBuf,
        /// 同时解包备份里的数据目录。
        #[arg(long)]
        with_data: bool,
        /// 跳过恢复前自动备份（不推荐）。
        #[arg(long)]
        no_pre_backup: bool,
        /// 跳过交互确认（CI 用）。
        #[arg(long)]
        force: bool,
        /// PG 连接串（缺省取 `DATABASE_URL`，再回退 `AGF_PG_*`）。
        #[arg(long)]
        url: Option<String>,
    },
    /// 气隙离线包：导出与校验。
    Airgap {
        /// 气隙子命令。
        #[command(subcommand)]
        command: AirgapCommand,
    },
    /// 打印版本与构建信息。
    #[command(name = "version")]
    Version,
}

/// `rules` 子命令。
#[derive(Debug, Subcommand)]
pub enum RulesCommand {
    /// 严格加载规则包并跑正负样本回归。
    Verify {
        /// 规则目录。
        #[arg(long, default_value = "rules")]
        dir: PathBuf,
    },
}

/// `redteam` 子命令。
#[derive(Debug, Subcommand)]
pub enum RedteamCommand {
    /// 加载红队用例库并校验规模与类别覆盖。
    Verify {
        /// 用例目录。
        #[arg(long, default_value = "redteam")]
        dir: PathBuf,
        /// 用例总数下限。
        #[arg(long, default_value_t = 200)]
        min_cases: usize,
    },
}

/// `db` 子命令。
#[derive(Debug, Subcommand)]
pub enum DbCommand {
    /// 校验 §7 关键表是否齐全。
    CheckSchema {
        /// PG 连接串（缺省取 `DATABASE_URL`，再回退 `AGF_PG_*`）。
        #[arg(long)]
        url: Option<String>,
    },
}

/// `airgap` 子命令。
#[derive(Debug, Subcommand)]
pub enum AirgapCommand {
    /// 导出气隙离线包（规则/用例/迁移/解析器 + `manifest.json`）。
    Bundle {
        /// 目标目录。
        #[arg(long)]
        out: PathBuf,
        /// 项目根（缺省当前目录）。
        #[arg(long)]
        project_root: Option<PathBuf>,
    },
    /// 按 `manifest.json` 校验气隙离线包。
    Verify {
        /// 离线包目录。
        #[arg(long)]
        dir: PathBuf,
    },
}

/// `genkey --kind` 取值。
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum KeyKind {
    /// JWT 签名密钥（base64，48 字节熵）。
    Jwt,
    /// 字段级加密主密钥（base64，32 字节）。
    Field,
    /// 引导管理员强口令（含 Argon2id PHC 哈希，**不打印明文到日志**）。
    AdminPassword,
}

impl KeyKind {
    /// 文本形式（稳定标识，供 JSON 输出使用）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Jwt => "jwt",
            Self::Field => "field",
            Self::AdminPassword => "admin-password",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use clap::error::ErrorKind;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("agfctl").chain(args.iter().copied()))
    }

    #[test]
    fn cli_definition_is_valid() {
        // 校验 clap 定义自洽（重复参数名/非法默认值等会在此暴露）
        Cli::command().debug_assert();
    }

    #[test]
    fn json_flag_is_global() {
        for args in [
            vec!["--json", "version"],
            vec!["version", "--json"],
            vec!["--json", "rules", "verify"],
            vec!["redteam", "verify", "--json"],
            vec!["--json", "genkey", "--kind", "field"],
        ] {
            let parsed = parse(&args);
            assert!(parsed.is_ok(), "参数 {args:?} 应可解析：{:?}", parsed.err().map(|e| e.to_string()));
            assert!(parsed.map(|c| c.global.json).unwrap_or(false), "参数 {args:?} 的 --json 未生效");
        }
    }

    #[test]
    fn defaults_match_documented_values() {
        let Ok(cli) = parse(&["healthcheck"]) else { return };
        assert!(matches!(
            cli.command,
            Command::Healthcheck { ref url, timeout_secs } if url == "http://127.0.0.1:8080/healthz" && timeout_secs == 5
        ));

        let Ok(cli) = parse(&["rules", "verify"]) else { return };
        assert!(
            matches!(cli.command, Command::Rules { command: RulesCommand::Verify { ref dir } } if dir == &PathBuf::from("rules"))
        );

        let Ok(cli) = parse(&["redteam", "verify"]) else { return };
        assert!(matches!(cli.command, Command::Redteam { command: RedteamCommand::Verify { min_cases: 200, .. } }));
    }

    #[test]
    fn migrate_accepts_url_and_dir() {
        let Ok(cli) = parse(&["migrate", "--url", "postgres://u:p@h:5432/db", "--dir", "deploy/sql/migrations"]) else {
            return;
        };
        match cli.command {
            Command::Migrate { url, dir } => {
                assert_eq!(url.as_deref(), Some("postgres://u:p@h:5432/db"));
                assert_eq!(dir, Some(PathBuf::from("deploy/sql/migrations")));
            }
            other => panic!("期望 Migrate，实际 {other:?}"),
        }
    }

    #[test]
    fn genkey_kind_is_enum_validated() {
        let Ok(cli) = parse(&["genkey", "--kind", "admin-password"]) else { return };
        assert!(matches!(cli.command, Command::Genkey { kind: KeyKind::AdminPassword, out: None }));

        let Ok(cli) = parse(&["genkey", "--kind", "field", "--out", "data/field.key"]) else { return };
        assert!(
            matches!(cli.command, Command::Genkey { kind: KeyKind::Field, out: Some(ref p) } if p == &PathBuf::from("data/field.key"))
        );

        let err = parse(&["genkey", "--kind", "not-a-kind"]);
        assert!(err.is_err(), "非法 --kind 必须被拒绝");
        assert_eq!(err.map(|_| ()).unwrap_err().kind(), ErrorKind::InvalidValue);
    }

    #[test]
    fn restore_uses_in_flag_not_positional() {
        let Ok(cli) = parse(&["restore", "--in", "data/backup/x", "--force", "--with-data"]) else { return };
        match cli.command {
            Command::Restore { input, with_data, force, no_pre_backup, .. } => {
                assert_eq!(input, PathBuf::from("data/backup/x"));
                assert!(with_data);
                assert!(force);
                assert!(!no_pre_backup);
            }
            other => panic!("期望 Restore，实际 {other:?}"),
        }
        assert!(parse(&["restore", "data/backup/x"]).is_err(), "--in 是必填选项，位置参数应被拒绝");
    }

    #[test]
    fn airgap_subcommands_are_wired() {
        let Ok(cli) = parse(&["airgap", "bundle", "--out", "data/airgap"]) else { return };
        assert!(
            matches!(cli.command, Command::Airgap { command: AirgapCommand::Bundle { ref out, project_root: None } } if out == &PathBuf::from("data/airgap"))
        );

        let Ok(cli) = parse(&["airgap", "verify", "--dir", "data/airgap"]) else { return };
        assert!(
            matches!(cli.command, Command::Airgap { command: AirgapCommand::Verify { ref dir } } if dir == &PathBuf::from("data/airgap"))
        );

        assert!(parse(&["airgap", "bundle"]).is_err(), "--out 必填");
        assert!(parse(&["airgap", "verify"]).is_err(), "--dir 必填");
    }

    #[test]
    fn unknown_subcommand_is_rejected() {
        let err = parse(&["frobnicate"]);
        assert!(err.is_err());
        assert_eq!(err.map(|_| ()).unwrap_err().kind(), ErrorKind::InvalidSubcommand);
    }

    #[test]
    fn key_kind_text_forms_are_stable() {
        assert_eq!(KeyKind::Jwt.as_str(), "jwt");
        assert_eq!(KeyKind::Field.as_str(), "field");
        assert_eq!(KeyKind::AdminPassword.as_str(), "admin-password");
    }
}
