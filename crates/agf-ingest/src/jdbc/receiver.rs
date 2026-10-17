//! SQL（"JDBC"）增量拉取接收器：单轮取数、游标推进与 `Receiver` 实现。

use super::*;

/// SQL（"JDBC"）拉取接收器。
#[derive(Debug)]
pub struct JdbcReceiver {
    source: Arc<dyn SqlSource>,
    config: SqlPullConfig,
    cursor: Mutex<Option<String>>,
    counters: Arc<ReceiverCounters>,
    metrics: Arc<SqlPullMetrics>,
}

impl JdbcReceiver {
    /// 构造（游标从 `config.cursor_path` 恢复）。
    ///
    /// 构造时把指标句柄登记进进程级槽位（[`pull_prometheus`] 只读它），
    /// 这样 `/metrics` 与接收器**共用同一个计数器实例**，不复制、不推算。
    #[must_use]
    pub fn new(source: Arc<dyn SqlSource>, config: SqlPullConfig) -> Self {
        let cursor = config.cursor_path.as_deref().and_then(SqlCursorFile::load);
        if cursor.is_some() {
            info!(cursor = ?cursor, "SQL 拉取游标已恢复（进程重启不重复拉取）");
        }
        let metrics = Arc::new(SqlPullMetrics::new());
        register_process_pull_metrics(&metrics, source.dialect());
        Self { source, config, cursor: Mutex::new(cursor), counters: Arc::new(ReceiverCounters::new()), metrics }
    }

    /// 拉取专属指标（拉取条数 / 丢弃 / 失败 / 游标推进）。
    #[must_use]
    pub fn pull_metrics(&self) -> &SqlPullMetrics {
        &self.metrics
    }

    /// 生效的 SQL 方言（由数据源实现给出，来自 DSN scheme）。
    #[must_use]
    pub fn dialect(&self) -> SqlDialect {
        self.source.dialect()
    }

    /// 注入共享计数器。
    #[must_use]
    pub fn with_counters(mut self, counters: Arc<ReceiverCounters>) -> Self {
        self.counters = counters;
        self
    }

    /// 配置。
    #[must_use]
    pub const fn config(&self) -> &SqlPullConfig {
        &self.config
    }

    /// 计数器。
    #[must_use]
    pub fn counters(&self) -> &Arc<ReceiverCounters> {
        &self.counters
    }

    /// 当前游标。
    #[must_use]
    pub fn cursor(&self) -> Option<String> {
        match self.cursor.lock() {
            Ok(cursor) => cursor.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// 设置游标（并落盘）。
    ///
    /// # Errors
    /// 落盘失败。
    pub fn set_cursor(&self, value: Option<String>) -> DomainResult<()> {
        {
            let mut cursor = match self.cursor.lock() {
                Ok(cursor) => cursor,
                Err(poisoned) => poisoned.into_inner(),
            };
            *cursor = value;
        }
        if let Some(path) = &self.config.cursor_path {
            SqlCursorFile::save(path, self.cursor().as_deref())?;
        }
        Ok(())
    }

    /// 单轮拉取。
    ///
    /// # Errors
    /// 查询失败（连接断开/语法错误）或落库失败。单行 JSON 非法只计数丢弃。
    pub async fn pull_once(
        &self,
        pipeline: &IngestPipeline,
        source: &LogSource,
        max: usize,
    ) -> DomainResult<SqlPullReport> {
        let limit = max.min(self.config.batch_limit).max(1);
        let cursor_field = self.config.cursor_field.as_deref().map(str::trim).filter(|f| !f.is_empty());
        let cursor = self.cursor();
        // 首轮（无游标）不带 WHERE：拉取表头 N 行；之后才按游标列增量推进。
        let effective_cursor = if cursor_field.is_some() { cursor.as_deref() } else { None };
        let effective_field = if effective_cursor.is_some() { cursor_field } else { None };
        let dialect = self.source.dialect();
        let sql = build_pull_sql_for(dialect, &self.config.sql, effective_field, self.config.cursor_type, limit)?;
        let rows = match self.source.fetch_rows(&sql, effective_cursor).await {
            Ok(rows) => rows,
            Err(e) => {
                self.metrics.record_error();
                return Err(e);
            }
        };
        let mut report = SqlPullReport { rows: rows.len(), ..SqlPullReport::default() };
        self.metrics.record_pulled(report.rows);
        if rows.is_empty() {
            debug!(dialect = dialect.as_str(), "SQL 拉取：无新行");
            return Ok(report);
        }
        let mut items: Vec<(Vec<u8>, String)> = Vec::with_capacity(rows.len());
        let mut last_cursor: Option<String> = None;
        for row in &rows {
            if let Some(field) = cursor_field {
                match cursor_from_row(row, field) {
                    Some(value) => last_cursor = Some(value),
                    None => {
                        warn!(field, "行 JSON 缺少游标列，按无游标处理（不推进游标，避免跳数据）");
                        last_cursor = None;
                        break;
                    }
                }
            }
            items.push((row.clone().into_bytes(), self.source.describe()));
        }
        report.malformed = rows.len().saturating_sub(items.len());
        self.metrics.record_dropped(report.malformed);
        if !items.is_empty() {
            self.counters.add_received(u64::try_from(items.len()).unwrap_or(u64::MAX));
            let outcomes = pipeline.ingest_batch(source, IngestProtocol::Jdbc, &items).await?;
            report.persisted = outcomes.iter().filter(|o| o.persisted).count();
            self.counters.record_outcomes(&outcomes);
        }
        // 游标只推进到**本批最后一行**：绝不跳过中间数据
        if let Some(next) = last_cursor {
            self.set_cursor(Some(next))?;
            self.metrics.record_cursor_advanced();
        }
        debug!(rows = report.rows, persisted = report.persisted, dialect = dialect.as_str(), "SQL 拉取完成一轮");
        Ok(report)
    }

    /// 拼装后将执行的拉取语句（运维排障用；**不含**任何数据）。
    ///
    /// # Errors
    /// 配置非法。
    pub fn preview_sql(&self) -> DomainResult<String> {
        let cursor_field = self.config.cursor_field.as_deref().map(str::trim).filter(|f| !f.is_empty());
        let effective = if self.cursor().is_none() { None } else { cursor_field };
        build_pull_sql_for(
            self.source.dialect(),
            &self.config.sql,
            effective,
            self.config.cursor_type,
            self.config.batch_limit,
        )
    }
}

#[async_trait]
impl Receiver for JdbcReceiver {
    fn protocol(&self) -> IngestProtocol {
        IngestProtocol::Jdbc
    }

    fn describe(&self) -> ReceiverDescriptor {
        let cursor = self.config.cursor_field.clone().unwrap_or_else(|| "<无（全量）>".to_string());
        let dialect = self.source.dialect();
        ReceiverDescriptor {
            name: "jdbc".to_string(),
            protocol: IngestProtocol::Jdbc,
            status: ReceiverStatus::Ready,
            note: format!(
                "{} 增量拉取（dialect={}） {}（游标列 {cursor}，单轮上限 {} 行，间隔 {}s，游标持久化）",
                dialect.driver_label(),
                dialect.as_str(),
                self.source.describe(),
                self.config.batch_limit,
                self.config.interval_secs
            ),
            todo: Some(
                "TODO ingest-jdbc-oracle-extras：Oracle 已接线（oracle/OCI，驱动按 DSN scheme 自动选择）；\
                 本轮**未覆盖**：REFCURSOR/对象/集合列按字符串兜底（`<undecodable:类型>` 之外的形态未细分）、\
                 钱包无专用 config_dir 环境变量（可用 `?descriptor=` 透传完整 TNS 描述符）、\
                 OCI 运行库需 `AGF_ORACLE_CLIENT_LIB_DIR` 或仓库内 `tools/oracle/instantclient_23_5`\
                 （缺失/连接失败只 warn，不阻塞启动）"
                    .to_string(),
            ),
            mock_replay: false,
        }
    }

    async fn start(&self, pipeline: Arc<IngestPipeline>, source: LogSource) -> DomainResult<()> {
        let interval = self.config.interval_secs.max(1);
        loop {
            match self.pull_once(&pipeline, &source, self.config.batch_limit).await {
                Ok(report) if report.rows > 0 => info!(?report, "SQL 拉取完成一轮"),
                Ok(_) => debug!("SQL 拉取：无新行"),
                // 数据库不可达只 warn：进程照常，下一轮重试（"连接失败不影响进程启动"）
                Err(e) => warn!(error = %e, "SQL 拉取失败（下轮重试，进程不受影响）"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        }
    }

    async fn poll_once(&self, pipeline: Arc<IngestPipeline>, source: LogSource, max: usize) -> DomainResult<usize> {
        Ok(self.pull_once(&pipeline, &source, max).await?.persisted)
    }
}
