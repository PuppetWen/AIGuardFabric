//! 由 `db.rs` 拆分：`impl_PgTarget`/`impl_PgTarget` 等 12 项（纯搬移，逻辑不变）。
use super::*;

impl std::fmt::Debug for PgTarget {
    /// 口令永不进入 Debug 输出（本类型可能被顺手 `?` 打印）。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgTarget")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database", &self.database)
            .field("user", &self.user)
            .field("password", &agf_core::secret::mask_default(&self.password))
            .finish()
    }
}

impl PgTarget {
    /// 脱敏 DSN（可安全打印）。
    #[must_use]
    pub fn masked(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.user,
            agf_core::secret::mask_default(&self.password),
            self.host,
            self.port,
            self.database
        )
    }

    /// 连接串（含口令，**禁止写日志**）。
    #[must_use]
    pub fn dsn(&self) -> String {
        format!("postgres://{}:{}@{}:{}/{}", self.user, self.password, self.host, self.port, self.database)
    }

    /// `libpq` 兼容环境变量（`pg_dump`/`pg_restore` 用，避免口令出现在命令行被 `ps` 看到）。
    #[must_use]
    pub fn libpq_env(&self) -> Vec<(String, String)> {
        let mut env = vec![
            ("PGHOST".to_string(), self.host.clone()),
            ("PGPORT".to_string(), self.port.to_string()),
            ("PGDATABASE".to_string(), self.database.clone()),
            ("PGUSER".to_string(), self.user.clone()),
        ];
        if !self.password.is_empty() {
            env.push(("PGPASSWORD".to_string(), self.password.clone()));
        }
        // 非交互：任何提示都应当失败而不是挂住等输入
        env.push(("PGCONNECT_TIMEOUT".to_string(), CONNECT_TIMEOUT_SECS.to_string()));
        env
    }

    /// 解析连接串。
    ///
    /// 支持 `postgres://user:pass@host:port/db` 与 `postgresql://...`；
    /// 缺少的字段回退到 `AGF_PG_*` / 默认值。
    ///
    /// # Errors
    /// 方案不是 postgres/postgresql、端口非法等。
    pub fn parse(url: &str, fallback: &Self) -> anyhow::Result<Self> {
        let trimmed = url.trim();
        let rest = trimmed
            .strip_prefix("postgres://")
            .or_else(|| trimmed.strip_prefix("postgresql://"))
            .ok_or_else(|| anyhow::anyhow!("连接串必须以 postgres:// 或 postgresql:// 开头"))?;
        // 去掉 query（如 ?sslmode=require）——运维命令只取基础连接信息
        let rest = rest.split('?').next().unwrap_or(rest);
        let (authority, database) = match rest.split_once('/') {
            Some((a, d)) => (a, d.to_string()),
            None => (rest, fallback.database.clone()),
        };
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        let (user, password) = match userinfo {
            Some(info) => match info.split_once(':') {
                Some((u, p)) => (u.to_string(), p.to_string()),
                None => (info.to_string(), fallback.password.clone()),
            },
            None => (fallback.user.clone(), fallback.password.clone()),
        };
        let (host, port) = if hostport.is_empty() {
            (fallback.host.clone(), fallback.port)
        } else {
            match hostport.rsplit_once(':') {
                Some((h, p)) => {
                    let port: u16 = p.parse().map_err(|e| anyhow::anyhow!("端口非法: {p}（{e}）"))?;
                    (if h.is_empty() { fallback.host.clone() } else { h.to_string() }, port)
                }
                None => (hostport.to_string(), fallback.port),
            }
        };
        if host.is_empty() {
            anyhow::bail!("连接串缺少主机");
        }
        if database.is_empty() {
            anyhow::bail!("连接串缺少数据库名");
        }
        Ok(Self { host, port, database, user, password })
    }
}

/// 从环境变量构造回退目标（`DATABASE_URL` 优先，其次 `AGF_PG_*`）。
///
/// # Errors
/// `DATABASE_URL` 存在但无法解析。
pub fn target_from_env() -> anyhow::Result<PgTarget> {
    let fallback = PgTarget {
        host: env_or("AGF_PG_HOST", "127.0.0.1"),
        port: env_or("AGF_PG_PORT", "5432").parse().unwrap_or(5432),
        database: env_or("AGF_PG_DB", "aiguardfabric"),
        user: env_or("AGF_PG_USER", "agf"),
        password: std::env::var("AGF_PG_PASSWORD").unwrap_or_default(),
    };
    match std::env::var("DATABASE_URL") {
        Ok(url) if !url.trim().is_empty() => PgTarget::parse(&url, &fallback),
        _ => Ok(fallback),
    }
}

/// 解析 CLI `--url`（缺省走环境变量）。
///
/// # Errors
/// 连接串非法。
pub fn resolve_target(url: Option<&str>) -> anyhow::Result<PgTarget> {
    let fallback = target_from_env()?;
    match url {
        Some(u) if !u.trim().is_empty() => PgTarget::parse(u, &fallback),
        _ => Ok(fallback),
    }
}

pub(crate) fn env_or(key: &str, default: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => default.to_string(),
    }
}

/// 连接数据库。
///
/// # Errors
/// PG 不可达 —— 调用方应把它映射为**退出码 2**（外部依赖不可用）。
pub async fn connect(target: &PgTarget) -> Result<PgPool, AppError> {
    let opts = PgConnectOptions::new()
        .host(&target.host)
        .port(target.port)
        .database(&target.database)
        .username(&target.user)
        .password(&target.password)
        .application_name("agfctl")
        .log_statements(tracing::log::LevelFilter::Off);
    PgPoolOptions::new()
        .max_connections(2)
        .min_connections(0)
        .acquire_timeout(std::time::Duration::from_secs(CONNECT_TIMEOUT_SECS))
        .connect_with(opts)
        .await
        .map_err(|e| dependency_error("PostgreSQL", &target.masked(), &e.to_string()))
}

/// PG 不可达的统一错误（退出码 2 + TODO 锚点）。
#[must_use]
pub fn dependency_error(what: &str, target: &str, cause: &str) -> AppError {
    AppError::Exit(Exit::dependency_unavailable(format!(
        "{what} 不可达（{target}）: {cause}\n\
         提示：设置 AGF_PG_HOST/AGF_PG_PORT/AGF_PG_DB/AGF_PG_USER/AGF_PG_PASSWORD 或 --url，\
         或先用 docker compose up -d postgres 起依赖\n\
         TODO(agfctl-pg-live)：真实 PG 上的 check-schema/migrate/backup/restore 需在部署环境（阶段二）验证"
    )))
}

impl SchemaReport {
    /// 关键表和数据库租户边界是否齐全。
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.missing.is_empty()
            && self.tenant_tables > 0
            && self.rls_enabled_tables == self.tenant_tables
            && self.rls_unprotected.is_empty()
            && self.runtime_role_safe
    }

    /// 结论行。
    #[must_use]
    pub fn summary_line(&self) -> String {
        if self.is_complete() {
            format!(
                "表结构校验通过：{}/{} 张关键表、{}/{} 张租户表受 RLS 保护",
                self.present, self.expected, self.rls_enabled_tables, self.tenant_tables
            )
        } else {
            format!(
                "表结构校验失败：缺少表 [{}]；RLS 异常表 [{}]；租户运行角色安全={}；租户表={}",
                self.missing.join(", "),
                self.rls_unprotected.join(", "),
                self.runtime_role_safe,
                self.tenant_tables
            )
        }
    }
}

/// 对比期望表与实到表，产出缺失清单（纯函数，便于单测）。
#[must_use]
pub fn missing_tables(expected: &[&str], present: &[String]) -> Vec<String> {
    let have: std::collections::BTreeSet<&str> = present.iter().map(String::as_str).collect();
    expected.iter().filter(|t| !have.contains(**t)).map(|t| (*t).to_string()).collect()
}

/// `db check-schema`。
///
/// # Errors
/// - PG 不可达 → 退出码 2；
/// - 关键表缺失或租户 RLS 边界异常 → 退出码 1。
pub async fn check_schema(url: Option<&str>, output: crate::output::Output) -> Result<(), AppError> {
    let target = resolve_target(url)?;
    let pool = connect(&target).await?;

    let version: (String,) = sqlx::query_as("SELECT version()")
        .fetch_one(&pool)
        .await
        .map_err(|e| AppError::Fatal(anyhow::anyhow!("读取版本失败: {e}")))?;
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
            .fetch_all(&pool)
            .await
            .map_err(|e| AppError::Fatal(anyhow::anyhow!("读取表清单失败: {e}")))?;
    let present: Vec<String> = rows.into_iter().map(|r| r.0).collect();
    let missing = missing_tables(REQUIRED_TABLES, &present);
    let rls = rls::inspect(&pool).await?;

    let report = SchemaReport {
        target: target.masked(),
        server_version: version.0,
        rls_enabled_tables: rls.enabled_tables,
        tenant_tables: rls.tenant_tables,
        rls_unprotected: rls.unprotected,
        runtime_role_safe: rls.runtime_role_safe,
        present: REQUIRED_TABLES.len().saturating_sub(missing.len()),
        expected: REQUIRED_TABLES.len(),
        missing: missing.clone(),
    };
    pool.close().await;

    if output.is_json() {
        output.emit(&serde_json::json!({ "ok": report.is_complete(), "report": report }))?;
    } else {
        output.line(&format!("数据库: {}", report.target));
        output.line(&format!("服务版本: {}", report.server_version));
        output.line(&format!(
            "RLS 租户表: {}/{}，运行角色安全: {}",
            report.rls_enabled_tables, report.tenant_tables, report.runtime_role_safe
        ));
        output.line(&report.summary_line());
    }

    if report.is_complete() { Ok(()) } else { Err(AppError::Exit(Exit::failed(report.summary_line()))) }
}

/// 解析迁移目录（`--dir` 优先，否则 [`DEFAULT_MIGRATIONS_DIR`]）。
#[must_use]
pub fn resolve_migrations_dir(dir: Option<&Path>) -> PathBuf {
    dir.map_or_else(|| PathBuf::from(DEFAULT_MIGRATIONS_DIR), Path::to_path_buf)
}

/// `migrate`。
///
/// # Errors
/// - PG 不可达或显式指定的迁移目录不存在 → 退出码 2；
/// - 迁移执行失败 → 退出码 1（内容问题）。
pub async fn migrate(url: Option<&str>, dir: Option<&Path>, output: crate::output::Output) -> Result<(), AppError> {
    let migrations_dir = resolve_migrations_dir(dir);
    let default_dir = Path::new(DEFAULT_MIGRATIONS_DIR);
    let use_embedded = dir.is_none()
        || (migrations_dir.is_dir()
            && default_dir.is_dir()
            && std::fs::canonicalize(&migrations_dir).ok() == std::fs::canonicalize(default_dir).ok());
    if !use_embedded && !migrations_dir.is_dir() {
        return Err(AppError::Exit(Exit::dependency_unavailable(format!(
            "迁移目录不存在: {}\n提示：省略 --dir 可使用程序内嵌的项目迁移；自定义目录须包含完整迁移集",
            migrations_dir.display()
        ))));
    }

    let custom = if use_embedded {
        None
    } else {
        Some(
            sqlx::migrate::Migrator::new(migrations_dir.as_path())
                .await
                .map_err(|e| AppError::Fatal(anyhow::anyhow!("读取迁移目录失败: {e}")))?,
        )
    };
    let migrator: &sqlx::migrate::Migrator =
        if let Some(migrator) = &custom { migrator } else { &agf_storage::db::MIGRATOR };
    let planned = migrator.iter().count();
    if planned == 0 {
        return Err(AppError::Exit(Exit::failed(format!(
            "迁移目录 {} 下没有可执行的迁移（文件名须形如 0001_init.sql）",
            migrations_dir.display()
        ))));
    }

    let target = resolve_target(url)?;
    let pool = connect(&target).await?;
    migrator.run(&pool).await.map_err(|e| AppError::Exit(Exit::failed(format!("迁移执行失败: {e}"))))?;

    let applied: (i64,) = sqlx::query_as("SELECT count(*) FROM _sqlx_migrations WHERE success")
        .fetch_one(&pool)
        .await
        .map_err(|e| AppError::Fatal(anyhow::anyhow!("读取迁移记录失败: {e}")))?;
    pool.close().await;

    if output.is_json() {
        output.emit(&serde_json::json!({
            "ok": true,
            "target": target.masked(),
            "dir": migrations_dir.to_string_lossy().replace('\\', "/"),
            "source": if use_embedded { "embedded" } else { "directory" },
            "planned": planned,
            "applied": applied.0,
        }))?;
    } else {
        output.line(&format!("数据库: {}", target.masked()));
        if use_embedded {
            output.line(&format!("迁移来源: 程序内嵌（{planned} 个迁移版本）"));
        } else {
            output.line(&format!("迁移目录: {}（{} 个迁移版本）", migrations_dir.display(), planned));
        }
        output.line(&format!("迁移完成（只向前，幂等）：库内已成功应用 {} 个版本", applied.0));
    }
    Ok(())
}
