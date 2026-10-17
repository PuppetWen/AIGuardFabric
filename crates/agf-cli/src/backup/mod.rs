//! `agfctl backup|restore` — 备份与恢复（§4.10）。
//!
//! ## 与 `scripts/backup.ps1` / `scripts/restore.ps1` 的能力边界
//!
//! 两个 PowerShell 脚本走 **`docker compose exec postgres pg_dump`**（compose 部署拓扑），
//! 本子命令走**本机 `pg_dump`/`pg_restore` + `PG*` 环境变量**（离机/裸机拓扑）。
//! 二者的产物结构保持一致，因此互为备份：
//!
//! | 产物 | 说明 |
//! |---|---|
//! | `agf.dump` | `pg_dump -Fc` 自定义格式（`pg_restore` 可选表恢复） |
//! | `data-files.zip` | `data/{seed,uploads,fixtures}` 打包（`--skip-data` 可跳过） |
//! | `MANIFEST.txt` | PowerShell 版脚本同款格式（`文件名 字节数 sha256`），供 restore.ps1 校验 |
//! | `manifest.json` | agfctl 结构化清单（复用 [`crate::manifest`]） |
//! | `README.txt` | 恢复步骤 |
//!
//! ## 诚实降级
//!
//! - `pg_dump`/`pg_restore` 不在 PATH → **退出码 2** + `TODO(agfctl-pg-tools)`；
//! - PG 不可达 → **退出码 2** + `TODO(agfctl-pg-live)`；
//! - 绝不"因为工具缺失就跳过备份并报成功"。
//!
//! ## 口令传递
//!
//! 口令只经 `PGPASSWORD` 环境变量传给子进程（`libpq` 原生支持），
//! 不出现在命令行参数里（避免 `ps`/进程审计泄露），也不进日志。

pub(crate) use std::path::Path;
pub(crate) use std::path::PathBuf;

pub(crate) use std::process::Command;
pub(crate) use std::process::Stdio;

pub(crate) use crate::error::AppError;
pub(crate) use crate::error::Exit;

pub(crate) use crate::manifest::ManifestEntry;
pub(crate) use crate::manifest::now_rfc3339;

pub(crate) use crate::output::Output;

#[allow(unused_imports)]
pub use impl_process_failure::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;
#[allow(unused_imports)]
pub use verify_backup_package::*;

/// 默认 `pg_dump` 程序名（可用 `AGF_PG_DUMP` 覆盖，便于异构环境指定路径）。
pub const PG_DUMP: &str = "pg_dump";

/// 默认 `pg_restore` 程序名（可用 `AGF_PG_RESTORE` 覆盖）。
pub const PG_RESTORE: &str = "pg_restore";

/// 数据库备份文件名（与 `scripts/restore.ps1` 约定一致）。
pub const DUMP_NAME: &str = "agf.dump";

/// 数据目录包文件名。
pub const DATA_ZIP: &str = "data-files.zip";

/// PowerShell 版兼容清单。
pub const MANIFEST_TXT: &str = "MANIFEST.txt";

/// agfctl 结构化清单。
pub const MANIFEST_JSON: &str = "manifest.json";

/// 恢复说明。
pub const README_TXT: &str = "README.txt";

/// 参与打包的数据子目录（相对项目根；与 backup.ps1 一致）。
pub const DATA_SUBDIRS: [&str; 3] = ["data/seed", "data/uploads", "data/fixtures"];

/// 备份目录名的时间戳格式。
pub const STAMP_FORMAT: &str = "%Y%m%d-%H%M%S";

/// 子进程执行失败的原因分类。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessFailure {
    /// 可执行文件不存在（未安装/不在 PATH）。
    NotFound,
    /// 进程起来了但退出码非 0。
    NonZero(i32),
    /// 进程内的数据库连接错误（输出里出现 libpq 连接类错误）。
    Connection(String),
    /// 其它执行失败（含无法捕获 stderr）。
    Spawn(String),
}

/// 备份包布局解析结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupLayout {
    /// 备份目录。
    pub dir: PathBuf,
    /// `agf.dump` 路径。
    pub dump: PathBuf,
    /// 结构化清单路径。
    pub manifest_json: PathBuf,
    /// PowerShell 兼容清单路径。
    pub manifest_txt: PathBuf,
    /// 数据包路径（可能不存在）。
    pub data_zip: PathBuf,
}

/// 备份清单（结构化）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BackupManifest {
    /// 生成时间。
    pub generated_at: String,
    /// 平台版本。
    pub version: String,
    /// 目标（脱敏）。
    pub target: String,
    /// 数据子目录是否纳入。
    pub with_data: bool,
    /// 条目。
    pub files: Vec<ManifestEntry>,
}

mod impl_process_failure;
#[cfg(test)]
mod tests;
mod verify_backup_package;
