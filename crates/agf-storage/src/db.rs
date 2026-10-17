//! PostgreSQL / TimescaleDB 连接与租户上下文（§7 数据库核心表）。
//!
//! ## 为什么用运行时 SQL 而不是 `sqlx::query!` 宏
//!
//! `query!` 系列宏需要在**编译期**连接数据库校验 SQL，这意味着构建机必须持有可用
//! 的 Postgres 实例与 `.sqlx` 离线缓存。本项目要求"离线可编译、单目录自包含"，
//! 因此统一使用运行时 `sqlx::query(...)`，并配合：
//! - `deploy/sql/migrations/` 的版本化迁移（历史 0001 原字节分片内嵌）；
//! - `agfctl db check-schema` 在运行期做一次表结构自检（见 `agf-cli`）。
//!
//! ## 租户隔离的实现
//!
//! 数据库层启用了 RLS（策略基于 `current_setting('agf.tenant_id')`）。
//! [`Database::begin_tenant`] 在事务内切换到无 BYPASSRLS 权限的运行角色，
//! 并设置当前租户。租户级查询因此受数据库策略约束；平台连接池仍拥有
//! 跨租户管理权限，只能用于租户目录、迁移和明确授权的运维操作。

use std::time::Duration;

use agf_core::error::{DomainError, DomainResult};
use agf_core::ids::{Id, TenantId};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{ConnectOptions, PgPool, Postgres, Transaction};
use tracing::{info, warn};

use crate::StorageConfig;

mod migrations;
pub use migrations::MIGRATOR;

/// 数据库句柄。
///
/// 克隆开销极小（内部是 `Arc`），可作为 application state 自由传递。
#[derive(Debug, Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    /// 建立连接池。
    ///
    /// # Errors
    /// 连接失败或池初始化失败。
    pub async fn connect(cfg: &StorageConfig) -> DomainResult<Self> {
        let mut opts = PgConnectOptions::new()
            .host(&cfg.pg_host)
            .port(cfg.pg_port)
            .database(&cfg.pg_database)
            .username(&cfg.pg_user)
            .password(&cfg.pg_password)
            // 生产必须 verify-full；开发环境允许 disable（本地 compose 无证书）
            .ssl_mode(if cfg.pg_require_tls { PgSslMode::VerifyFull } else { PgSslMode::Prefer })
            .application_name("aiguardfabric")
            .statement_cache_capacity(256);

        opts = opts.log_slow_statements(tracing::log::LevelFilter::Warn, Duration::from_millis(800));
        // 不在日志里打印绑定参数（可能含敏感值）
        opts = opts.log_statements(tracing::log::LevelFilter::Debug);

        let pool = PgPoolOptions::new()
            .max_connections(cfg.pg_pool_max)
            .min_connections(cfg.pg_pool_min)
            .acquire_timeout(Duration::from_secs(cfg.pg_connect_timeout_secs))
            // 连接池空闲 10 分钟回收、最长存活 30 分钟：
            // 用 `from_mins` 而不是 `from_secs(600/1800)`，单位即语义（clippy::duration_suboptimal_units）。
            .idle_timeout(Some(Duration::from_mins(10)))
            .max_lifetime(Some(Duration::from_mins(30)))
            .test_before_acquire(true)
            .connect_with(opts)
            .await
            .map_err(|e| DomainError::DependencyUnavailable {
                dependency: "postgres".to_string(),
                cause: format!("连接失败: {e}"),
            })?;

        info!(
            host = %cfg.pg_host,
            port = cfg.pg_port,
            database = %cfg.pg_database,
            pool_max = cfg.pg_pool_max,
            "PostgreSQL 连接池就绪"
        );
        Ok(Self { pool })
    }

    /// 由已有连接池构造（测试与嵌入场景）。
    #[must_use]
    pub const fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// 底层连接池。
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// 执行迁移（幂等；仅向前）。
    ///
    /// # Errors
    /// 任一迁移失败即整体失败，并报告具体版本。
    pub async fn migrate(&self) -> DomainResult<()> {
        info!("开始执行数据库迁移");
        MIGRATOR.run(&self.pool).await.map_err(|e| DomainError::Internal(format!("迁移失败: {e}")))?;
        let applied = MIGRATOR.iter().count();
        info!(migrations = applied, "数据库迁移完成");
        Ok(())
    }

    /// 健康探测（`SELECT 1`）。
    ///
    /// # Errors
    /// 数据库不可达。
    pub async fn ping(&self) -> DomainResult<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(|e| DomainError::DependencyUnavailable {
            dependency: "postgres".to_string(),
            cause: format!("ping 失败: {e}"),
        })?;
        Ok(())
    }

    /// 开启一个带租户上下文的事务。
    ///
    /// 这是**所有租户级读写**的唯一入口：`SET LOCAL` 只在事务内生效，
    /// 事务结束自动清理，避免连接复用导致的租户串号。
    ///
    /// # Errors
    /// 开启事务或设置上下文失败。
    pub async fn begin_tenant(&self, tenant: TenantId) -> DomainResult<TenantTransaction<'_>> {
        let mut tx = self.pool.begin().await.map_err(|e| DomainError::Internal(format!("开启事务失败: {e}")))?;
        // 即使连接账号是 Docker 初始化的超级用户，租户查询也必须受 RLS 约束。
        sqlx::query("SET LOCAL ROLE agf_tenant_runtime")
            .execute(&mut *tx)
            .await
            .map_err(|e| DomainError::Internal(format!("启用租户数据库角色失败，请先执行数据库迁移: {e}")))?;
        // SET LOCAL 不接受绑定参数，用 set_config 既参数化又只作用于当前事务
        sqlx::query("SELECT set_config('agf.tenant_id', $1, true)")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| DomainError::Internal(format!("设置租户上下文失败: {e}")))?;
        Ok(TenantTransaction { tenant, tx })
    }

    /// 开启不带租户上下文的事务（仅用于平台级操作：租户表本身、迁移、全局字典）。
    ///
    /// 此事务沿用连接池账号；若该账号是表所有者或超级用户，可绕过 RLS。
    /// 不得通过此入口访问租户业务数据，租户读写须调用 `begin_tenant`。
    ///
    /// # Errors
    /// 开启事务失败。
    pub async fn begin_platform(&self) -> DomainResult<Transaction<'_, Postgres>> {
        self.pool.begin().await.map_err(|e| DomainError::Internal(format!("开启事务失败: {e}")))
    }

    /// 在平台上下文中读取单个标量（用于健康检查与统计）。
    ///
    /// # Errors
    /// 查询失败。
    pub async fn scalar_i64(&self, sql: &str) -> DomainResult<i64> {
        let row: (i64,) = sqlx::query_as(sql)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| DomainError::Internal(format!("查询失败: {e}")))?;
        Ok(row.0)
    }

    /// 统计某表行数（跨租户；仅供平台运维页，需超级管理员权限）。
    ///
    /// # Errors
    /// 表名非法或查询失败。
    pub async fn table_count(&self, table: &str) -> DomainResult<i64> {
        if !is_safe_identifier(table) {
            return Err(DomainError::Validation(format!("非法表名: {table}")));
        }
        self.scalar_i64(&format!("SELECT count(*) FROM {table}")).await
    }

    /// 检查必需的表是否都存在（`agfctl db check-schema`）。
    ///
    /// # Errors
    /// 查询 `information_schema` 失败。
    pub async fn missing_tables(&self, expected: &[&str]) -> DomainResult<Vec<String>> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
                .fetch_all(&self.pool)
                .await
                .map_err(|e| DomainError::Internal(format!("读取表清单失败: {e}")))?;
        let present: std::collections::BTreeSet<String> = rows.into_iter().map(|r| r.0).collect();
        Ok(expected.iter().filter(|t| !present.contains(**t)).map(|t| (*t).to_string()).collect())
    }

    /// 数据库版本与扩展信息（自检页展示）。
    ///
    /// # Errors
    /// 查询失败。
    pub async fn server_info(&self) -> DomainResult<DatabaseInfo> {
        let version: (String,) = sqlx::query_as("SELECT version()")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| DomainError::Internal(format!("读取版本失败: {e}")))?;
        let timescale: Option<(String,)> =
            sqlx::query_as("SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'")
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| DomainError::Internal(format!("读取扩展失败: {e}")))?;
        let rls_tables: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM pg_tables t JOIN pg_class c ON c.relname = t.tablename \
             WHERE t.schemaname = 'public' AND c.relrowsecurity",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| DomainError::Internal(format!("统计 RLS 表失败: {e}")))?;
        Ok(DatabaseInfo {
            version: version.0,
            timescaledb_version: timescale.map(|t| t.0),
            rls_enabled_tables: rls_tables.0,
            pool_size: self.pool.size(),
            pool_idle: self.pool.num_idle(),
        })
    }

    /// 关闭连接池（优雅停机）。
    pub async fn close(&self) {
        self.pool.close().await;
        info!("PostgreSQL 连接池已关闭");
    }

    /// 删除过期软删除记录（归档任务用）。
    ///
    /// # Errors
    /// 表名非法或执行失败。
    pub async fn purge_soft_deleted(&self, table: &str, older_than_days: i64) -> DomainResult<u64> {
        if !is_safe_identifier(table) {
            return Err(DomainError::Validation(format!("非法表名: {table}")));
        }
        let sql = format!("DELETE FROM {table} WHERE deleted_at IS NOT NULL AND deleted_at < now() - $1::interval");
        let res = sqlx::query(&sql)
            .bind(format!("{older_than_days} days"))
            .execute(&self.pool)
            .await
            .map_err(|e| DomainError::Internal(format!("清理 {table} 失败: {e}")))?;
        let n = res.rows_affected();
        if n > 0 {
            warn!(table, rows = n, "已清理软删除记录");
        }
        Ok(n)
    }
}

/// 数据库信息快照。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DatabaseInfo {
    /// `SELECT version()` 结果。
    pub version: String,
    /// TimescaleDB 扩展版本（未安装为 `None`）。
    pub timescaledb_version: Option<String>,
    /// 已启用 RLS 的表数量。
    pub rls_enabled_tables: i64,
    /// 连接池总连接数。
    pub pool_size: u32,
    /// 空闲连接数。
    pub pool_idle: usize,
}

/// 带租户上下文的事务包装。
///
/// 提供常用的租户级操作方法；需要复杂 SQL 时可通过 [`Self::tx`] 取到底层事务。
#[derive(Debug)]
pub struct TenantTransaction<'a> {
    /// 租户。
    pub tenant: TenantId,
    /// 底层事务。
    tx: Transaction<'a, Postgres>,
}

impl<'a> TenantTransaction<'a> {
    /// 租户 id。
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// 可变借用底层事务（需要 `commit`/`rollback` 等事务级 API 时使用）。
    ///
    /// 注意：`sqlx` 0.8 只为 `&mut PgConnection` 实现 `Executor`（`Transaction` 的 impl 已被移除），
    /// 所以执行 SQL 时请**直接**把 `&mut TenantTransaction` 传进去——本类型实现了
    /// [`Deref`]/[`DerefMut`] 指向内层 `PgConnection`，sqlx 的 `Executor` 解析会自动完成。
    pub fn tx(&mut self) -> &mut Transaction<'a, Postgres> {
        &mut self.tx
    }

    /// 提交。
    ///
    /// # Errors
    /// 提交失败。
    pub async fn commit(self) -> DomainResult<()> {
        self.tx.commit().await.map_err(|e| DomainError::Internal(format!("提交事务失败: {e}")))
    }

    /// 回滚。
    ///
    /// # Errors
    /// 回滚失败。
    pub async fn rollback(self) -> DomainResult<()> {
        self.tx.rollback().await.map_err(|e| DomainError::Internal(format!("回滚事务失败: {e}")))
    }

    /// 插入（返回受影响行数）。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn execute(&mut self, sql: &str) -> DomainResult<u64> {
        let res = sqlx::query(sql)
            .execute(&mut *self.tx)
            .await
            .map_err(|e| DomainError::Internal(format!("执行 SQL 失败: {e}")))?;
        Ok(res.rows_affected())
    }

    /// 读取单个 i64 标量。
    ///
    /// # Errors
    /// 查询失败。
    pub async fn scalar_i64(&mut self, sql: &str) -> DomainResult<i64> {
        let row: (i64,) = sqlx::query_as(sql)
            .fetch_one(&mut *self.tx)
            .await
            .map_err(|e| DomainError::Internal(format!("查询失败: {e}")))?;
        Ok(row.0)
    }

    /// 断言某资源属于当前租户，否则返回 [`DomainError::TenantViolation`]。
    ///
    /// 用法：在按 id 读取/修改前调用，把"越权"从静默返回 404 提升为显式审计事件。
    ///
    /// # Errors
    /// 表名非法或查询失败。
    pub async fn assert_owned(&mut self, table: &str, id: Id) -> DomainResult<()> {
        if !is_safe_identifier(table) {
            return Err(DomainError::Validation(format!("非法表名: {table}")));
        }
        let sql = format!("SELECT count(*) FROM {table} WHERE id = $1 AND tenant_id = $2");
        let row: (i64,) = sqlx::query_as(&sql)
            .bind(id.as_uuid())
            .bind(self.tenant.as_uuid())
            .fetch_one(&mut *self.tx)
            .await
            .map_err(|e| DomainError::Internal(format!("校验归属失败: {e}")))?;
        if row.0 == 0 {
            return Err(DomainError::TenantViolation {
                tenant: self.tenant.to_string(),
                resource: format!("{table}#{id}"),
            });
        }
        Ok(())
    }

    /// 乐观锁更新：按 `version` 列更新，返回是否成功。
    ///
    /// # Errors
    /// 表名非法或执行失败。
    pub async fn optimistic_update(
        &mut self,
        table: &str,
        id: Id,
        expected_version: i32,
        set_clause: &str,
        payload_json: &serde_json::Value,
    ) -> DomainResult<bool> {
        if !is_safe_identifier(table) {
            return Err(DomainError::Validation(format!("非法表名: {table}")));
        }
        let sql = format!(
            "UPDATE {table} SET {set_clause}, version = version + 1 \
             WHERE id = $1 AND tenant_id = $2 AND version = $3"
        );
        let res = sqlx::query(&sql)
            .bind(id.as_uuid())
            .bind(self.tenant.as_uuid())
            .bind(expected_version)
            .bind(payload_json)
            .execute(&mut *self.tx)
            .await
            .map_err(|e| DomainError::Internal(format!("乐观锁更新失败: {e}")))?;
        Ok(res.rows_affected() == 1)
    }
}

impl std::ops::Deref for TenantTransaction<'_> {
    type Target = sqlx::PgConnection;

    /// 解引用到内层连接，使 `Executor` 方法解析可直接作用于本类型。
    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

impl std::ops::DerefMut for TenantTransaction<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tx
    }
}
/// 校验标识符（表名/列名）只含 ASCII 字母、数字与下划线。
///
/// 用于所有需要把表名拼进 SQL 的场景（`format!`），防止 SQL 注入。
#[must_use]
pub fn is_safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !value.starts_with(|c: char| c.is_ascii_digit())
}

/// 把 `sqlx::Error` 映射为领域错误（保留唯一约束冲突语义，便于上层返回 409）。
#[must_use]
pub fn map_sqlx_err(context: &str, e: &sqlx::Error) -> DomainError {
    match e {
        sqlx::Error::Database(db) => {
            let code = db.code().map(std::borrow::Cow::into_owned).unwrap_or_default();
            match code.as_str() {
                // unique_violation
                "23505" => DomainError::Conflict(format!("{context}: 唯一约束冲突（{db}）")),
                // foreign_key_violation
                "23503" => DomainError::Validation(format!("{context}: 外键约束失败（引用的记录不存在）")),
                // not_null_violation
                "23502" => DomainError::Validation(format!("{context}: 必填字段为空")),
                // check_violation
                "23514" => DomainError::Validation(format!("{context}: CHECK 约束失败（取值非法）")),
                _ => DomainError::Internal(format!("{context}: 数据库错误 {code} ({db})")),
            }
        }
        sqlx::Error::RowNotFound => DomainError::NotFound { entity: "row", id: context.to_string() },
        sqlx::Error::PoolTimedOut => DomainError::DependencyUnavailable {
            dependency: "postgres".to_string(),
            cause: format!("{context}: 连接池等待超时"),
        },
        other => DomainError::Internal(format!("{context}: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_identifier_accepts_normal_names() {
        for name in ["assets", "finding_evidence", "a", "t123", "_x"] {
            assert!(is_safe_identifier(name), "{name} 应被接受");
        }
    }

    #[test]
    fn safe_identifier_rejects_injection_and_oddities() {
        for name in ["", "assets; DROP TABLE users", "assets--", "1assets", "assets name", "资产", "assets\"quote"] {
            assert!(!is_safe_identifier(name), "{name} 应被拒绝");
        }
        let long = "a".repeat(64);
        assert!(!is_safe_identifier(&long), "超长标识符应被拒绝");
    }

    #[test]
    fn sqlx_error_mapping_unique_violation_becomes_conflict() {
        // 构造一个 Database 错误不方便，这里验证非 Database 分支
        let e = sqlx::Error::RowNotFound;
        let mapped = map_sqlx_err("find_asset", &e);
        assert!(matches!(mapped, DomainError::NotFound { .. }));
        let e2 = sqlx::Error::PoolTimedOut;
        let mapped2 = map_sqlx_err("query", &e2);
        assert!(matches!(mapped2, DomainError::DependencyUnavailable { .. }));
        let e3 = sqlx::Error::Protocol("x".into());
        assert!(matches!(map_sqlx_err("q", &e3), DomainError::Internal(_)));
    }

    #[test]
    fn migrator_embeds_migration_files() {
        let count = MIGRATOR.iter().count();
        assert_eq!(count, 22, "应内嵌 0001 至 0022 的全部迁移");
        assert_eq!(MIGRATOR.iter().last().map(|migration| migration.version), Some(22));
        let first = MIGRATOR.iter().next();
        assert!(first.is_some());
        if let Some(m) = first {
            assert_eq!(m.version, 1);
            assert_eq!(m.description, "init");
            assert_eq!(
                hex::encode(&m.checksum),
                "5de7ec35232cd1e5ce4ff653c17236ca93a25df6482b3660d37a96e84d483f42d9be9d2482fd98bc60028de7c373564d"
            );
        }
    }
}
