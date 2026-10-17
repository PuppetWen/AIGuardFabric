//! PostgreSQL 连接目标解析与迁移执行（`db check-schema` / `migrate`）。
//!
//! ## 项目迁移与自定义目录
//!
//! 默认目录使用 [`agf_storage::db::MIGRATOR`]，包含按原字节合并的历史 0001；
//! 其它 `--dir` 目录仍由 `sqlx::migrate::Migrator::new()` 在运行期读取。
//! 两者均按 SQLx 的版本和校验和规则只向前执行。

pub(crate) use std::path::Path;
pub(crate) use std::path::PathBuf;

pub(crate) use agf_storage::REQUIRED_TABLES;

pub(crate) use sqlx::postgres::PgConnectOptions;
pub(crate) use sqlx::postgres::PgPoolOptions;

pub(crate) use sqlx::ConnectOptions;
pub(crate) use sqlx::PgPool;

pub(crate) use crate::error::AppError;
pub(crate) use crate::error::Exit;

#[allow(unused_imports)]
pub use impl_pg_target::*;
#[allow(unused_imports)]
#[cfg(test)]
pub(crate) use tests::*;

/// 项目默认迁移目录（仅用于识别显式 `--dir`；省略时直接使用内嵌迁移）。
pub const DEFAULT_MIGRATIONS_DIR: &str = "deploy/sql/migrations";

/// 连接超时（秒）——运维命令要快速失败，不能像服务一样等 10 秒以上。
pub const CONNECT_TIMEOUT_SECS: u64 = 6;

/// 解析后的 PG 连接目标。
#[derive(Clone, PartialEq, Eq)]
pub struct PgTarget {
    /// 主机。
    pub host: String,
    /// 端口。
    pub port: u16,
    /// 库名。
    pub database: String,
    /// 用户名。
    pub user: String,
    /// 口令（**不打印**）。
    pub password: String,
}

/// 关键表自检结果。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SchemaReport {
    /// 目标（脱敏）。
    pub target: String,
    /// 数据库自报版本。
    pub server_version: String,
    /// RLS 已启用的表数。
    pub rls_enabled_tables: i64,
    /// 含 tenant_id 的业务表总数。
    pub tenant_tables: i64,
    /// 缺少 RLS 或预期租户策略的表。
    pub rls_unprotected: Vec<String>,
    /// 运行角色不具超级用户、BYPASSRLS 和直接登录权限。
    pub runtime_role_safe: bool,
    /// 实到的关键表数。
    pub present: usize,
    /// 应有的关键表数。
    pub expected: usize,
    /// 缺失的表。
    pub missing: Vec<String>,
}

mod impl_pg_target;
mod rls;
#[cfg(test)]
mod tests;
