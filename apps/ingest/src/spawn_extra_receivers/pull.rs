//! 拉取型接收器装配段（由 `spawn_extra_receivers.rs` 按块拆分，纯搬移、逻辑不变）。
//!
//! 覆盖对象存储（S3/OSS/MinIO）与 SQL 拉取（"JDBC"：PostgreSQL/MySQL 共用同一套拉取内核）。
use super::*;

impl ExtraReceiverCtx<'_> {
    /// ---- 对象存储拉取（S3/OSS/MinIO） ----
    pub(super) async fn object_pull(&mut self) {
        let source_identity = self.identity.clone();
        let pipeline = self.pipeline;
        let metrics = self.metrics;
        let listeners = &mut *self.listeners;
        let bucket = env_or("AGF_INGEST_OBJECT_PULL_BUCKET", "");
        if bucket.is_empty() {
            listeners.note("对象存储拉取未启用：未配置 AGF_INGEST_OBJECT_PULL_BUCKET".to_string());
        } else {
            let endpoint = env_or("AGF_S3_ENDPOINT", "");
            let region = env_or("AGF_S3_REGION", "us-east-1");
            let access = env_or("AGF_S3_ACCESS_KEY", "");
            let secret = env_or("AGF_S3_SECRET_KEY", "");
            // 自建 MinIO/OSS 必须 path-style；显式 env 优先
            let path_style = env_flag("AGF_S3_FORCE_PATH_STYLE") || !endpoint.is_empty();
            match S3ObjectSource::new(&endpoint, &region, &access, &secret, &bucket, path_style) {
                Ok(s3) => {
                    let config = ObjectPullConfig {
                        bucket: bucket.clone(),
                        prefix: env_or("AGF_INGEST_OBJECT_PULL_PREFIX", ""),
                        interval_secs: env_num("AGF_INGEST_OBJECT_PULL_INTERVAL_SECS", 60_u64).max(1),
                        max_objects: env_num("AGF_INGEST_OBJECT_PULL_MAX_OBJECTS", 200_usize).max(1),
                        max_object_bytes: env_num("AGF_INGEST_OBJECT_PULL_MAX_OBJECT_BYTES", 64 * 1024 * 1024_usize)
                            .max(1),
                        max_records_per_object: env_num("AGF_INGEST_OBJECT_PULL_MAX_RECORDS", 10_000_usize).max(1),
                        cursor_path: Some(PathBuf::from(env_or(
                            "AGF_INGEST_OBJECT_PULL_STATE",
                            "data/ingest/object-pull-cursor.json",
                        ))),
                    };
                    let receiver = Arc::new(
                        ObjectPullReceiver::new(Arc::new(s3), config).with_counters(metrics.counters("object-pull")),
                    );
                    tracing::info!(bucket = %bucket, "对象存储拉取接收器已启用（ETag 幂等游标 + 游标落盘）");
                    let pipeline = Arc::clone(pipeline);
                    let source = ingest_source(&source_identity, IngestProtocol::ObjectStorage, "object-pull");
                    tokio::spawn(async move {
                        if let Err(e) = receiver.start(pipeline, source).await {
                            tracing::warn!(error = %e, "对象存储拉取任务退出");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "对象存储拉取未启用（配置不完整，其余能力不受影响）");
                    listeners.note(format!("对象存储拉取未启用：{e}"));
                }
            }
        }
    }

    /// ---- SQL 拉取（"JDBC"） ----
    pub(super) async fn sql_pull(&mut self) {
        let source_identity = self.identity.clone();
        let pipeline = self.pipeline;
        let metrics = self.metrics;
        let listeners = &mut *self.listeners;
        let dsn = env_or("AGF_INGEST_SQL_DSN", "");
        let query = env_or("AGF_INGEST_SQL_QUERY", "");
        if dsn.is_empty() || query.is_empty() {
            listeners.note("SQL 拉取未启用：需同时配置 AGF_INGEST_SQL_DSN 与 AGF_INGEST_SQL_QUERY".to_string());
        } else {
            let config = SqlPullConfig {
                sql: query,
                cursor_field: std::env::var("AGF_INGEST_SQL_CURSOR_FIELD").ok().filter(|v| !v.trim().is_empty()),
                cursor_type: std::env::var("AGF_INGEST_SQL_CURSOR_TYPE")
                    .ok()
                    .and_then(|v| agf_ingest::jdbc::CursorType::parse(&v))
                    .unwrap_or_default(),
                batch_limit: env_num("AGF_INGEST_SQL_BATCH_LIMIT", 500_usize).max(1),
                interval_secs: env_num("AGF_INGEST_SQL_INTERVAL_SECS", 60_u64).max(1),
                cursor_path: Some(PathBuf::from(env_or(
                    "AGF_INGEST_SQL_CURSOR_PATH",
                    "data/ingest/sql-pull-cursor.json",
                ))),
            };
            match SqlDialect::from_dsn(&dsn) {
                Ok(dialect) => match config_pull_sql(dialect, &config) {
                    Ok(sql) => tracing::info!(
                        sql = %sql,
                        dialect = dialect.as_str(),
                        driver = dialect.driver_label(),
                        "SQL 拉取接收器已配置（驱动按 DSN scheme 选定；连接在后台建立）"
                    ),
                    Err(e) => tracing::warn!(error = %e, "SQL 拉取语句拼装失败（该接收器仍会按轮次重试并报错）"),
                },
                Err(e) => tracing::warn!(error = %e, "SQL 拉取 DSN scheme 不受支持，该接收器不会启用"),
            }
            // 连接放到**后台任务**里：数据库不可达时绝不阻塞 HTTP 启动（可用性优先），
            // 只 warn + 写入 /readyz 的 notes，进程与其余接收器完全不受影响。
            let counters = metrics.counters("jdbc");
            let pipeline = Arc::clone(pipeline);
            let notes = Arc::clone(&listeners.notes);
            let source = ingest_source(&source_identity, IngestProtocol::Jdbc, "sql-pull");
            let max_connections = env_num("AGF_INGEST_SQL_MAX_CONNECTIONS", 4_u32);
            tokio::spawn(async move {
                // 按 scheme 自动选驱动（postgres:// ⇒ sqlx/PostgreSQL，mysql:// ⇒ sqlx/MySQL，
                // mssql:// ⇒ tiberius/MSSQL，oracle:// ⇒ oracle/OCI）
                let connected =
                    tokio::time::timeout(std::time::Duration::from_secs(8), connect_from_dsn(&dsn, max_connections))
                        .await;
                match connected {
                    Ok(Ok(sql_source)) => {
                        tracing::info!(
                            dialect = sql_source.dialect().as_str(),
                            driver = sql_source.dialect().driver_label(),
                            "SQL 拉取驱动已选定（游标/分页/落盘逻辑与方言无关，只有一份实现）"
                        );
                        let receiver = JdbcReceiver::new(sql_source, config).with_counters(counters);
                        if let Err(e) = receiver.start(pipeline, source).await {
                            tracing::warn!(error = %e, "SQL 拉取任务退出");
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "SQL 拉取连接失败，该接收器未启用（其余能力不受影响）");
                        push_note(&notes, format!("SQL 拉取未启用：{e}"));
                    }
                    Err(_) => {
                        tracing::warn!("SQL 拉取连接超时（8s），该接收器未启用（其余能力不受影响）");
                        push_note(&notes, "SQL 拉取未启用：连接超时（8s）");
                    }
                }
            });
        }
    }

    /// === MySQL ===（方言运行态标注）
    pub(super) fn annotate_sql_dialect(&mut self) {
        let listeners = &mut *self.listeners;
        // PostgreSQL / MySQL / MSSQL / Oracle **共用同一套拉取逻辑**（游标推进/批上限/游标落盘/幂等
        // 只有一份实现），差异只落在方言层（`agf_ingest::jdbc::SqlDialect`）：
        //   * 占位符：MySQL `?`、MSSQL `@P1`、Oracle `:1`（PostgreSQL `$1`）；
        //   * 游标转型：MySQL `CAST(col AS signed|datetime|char)`、MSSQL `CAST(col AS bigint|datetime2|nvarchar(max))`、
        //     Oracle `CAST(col AS NUMBER|VARCHAR2(4000))` + 时间列 `TO_CHAR(...)` 归一
        //     （PostgreSQL `(col)::bigint|timestamptz|text`）；
        //   * 标识符引号：MySQL 反引号、MSSQL 方括号、Oracle/PostgreSQL 双引号；
        //   * 行 → JSON：MySQL / MSSQL / Oracle 无 `row_to_json`，按结果集列元数据解码
        //     （PostgreSQL 用 `row_to_json`）。
        // 驱动由上面同一个 `connect_from_dsn` 按 DSN scheme 选定；本段落只做**如实标注**，
        // 让 /readyz 的 notes 反映"本次进程到底选了哪个驱动"。
        {
            let dsn = env_or("AGF_INGEST_SQL_DSN", "");
            if !dsn.trim().is_empty() {
                match SqlDialect::from_dsn(&dsn) {
                    Ok(SqlDialect::MySql) => {
                        tracing::info!(
                            dialect = "mysql",
                            driver = "sqlx/MySQL",
                            "SQL 拉取方言 = MySQL（? 占位符 + CAST 转型 + 反引号标识符 + 列元数据解码行 JSON）；\
                             指标 agf_ingest_jdbc_rows_pulled_total / _rows_dropped_total / _errors_total / _cursor_advanced_total"
                        );
                        listeners.note(
                            "SQL 拉取：MySQL 驱动已启用（dialect=mysql，游标语义与 PostgreSQL 一致）".to_string(),
                        );
                    }
                    Ok(SqlDialect::Postgres) => {
                        tracing::info!(
                            dialect = "postgres",
                            driver = "sqlx/PostgreSQL",
                            "SQL 拉取方言 = PostgreSQL（row_to_json + $1）；MySQL 亦已支持（把 DSN 换成 mysql:// 即可）"
                        );
                        listeners.note("SQL 拉取：PostgreSQL 驱动已启用（dialect=postgres）".to_string());
                    }
                    Ok(SqlDialect::MsSql) => {
                        tracing::info!(
                            dialect = "mssql",
                            driver = "tiberius/TDS",
                            "SQL 拉取方言 = MSSQL（tiberius/TDS 驱动；游标/分页/落盘仍走同一份实现）"
                        );
                        listeners.note("SQL 拉取：MSSQL 方言已启用（dialect=mssql）".to_string());
                    }
                    Ok(SqlDialect::Oracle) => {
                        tracing::info!(
                            dialect = "oracle",
                            driver = "oracle/OCI",
                            "SQL 拉取方言 = Oracle（oracle crate / OCI；:1 占位符 + CAST(col AS NUMBER|VARCHAR2) \
                             + 时间列 TO_CHAR 归一 + 双引号标识符 + 列元数据解码行 JSON，游标/分页/落盘仍走同一份实现）"
                        );
                        // OCI 运行库目录与"未覆盖项"一并说清（缺失/失败只 warn，不阻塞进程）
                        let lib_dir = std::env::var("AGF_ORACLE_CLIENT_LIB_DIR")
                            .ok()
                            .filter(|dir| !dir.trim().is_empty())
                            .unwrap_or_else(|| "tools/oracle/instantclient_23_5（仓库内默认）".to_string());
                        listeners.note(format!(
                            "SQL 拉取：Oracle 方言已启用（dialect=oracle，OCI 运行库目录 {lib_dir}，\
                             游标语义与 PostgreSQL 一致；未覆盖项见 TODO ingest-jdbc-oracle-extras）"
                        ));
                    }
                    Err(e) => listeners.note(format!("SQL 拉取未启用：{e}")),
                }
            }
        }
    }
}
