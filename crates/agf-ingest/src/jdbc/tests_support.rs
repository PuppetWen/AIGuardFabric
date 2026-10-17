//! JDBC 单元测试的**共享夹具**：内存 SQL 源（四种方言）、日志源、流水线 + 内存 Sink、游标配置。
//!
//! 拆成独立文件有两个原因：`tests.rs` 与 `tests_oracle.rs` 要共用**同一份夹具**
//! （"Oracle 与 PostgreSQL/MySQL/MSSQL 走同一份游标逻辑"的守卫断言正依赖这一点），
//! 且单文件有 500 行上限。

use super::*;
use crate::bus::NoopEventBus;
use crate::pipeline::{InMemorySink, IngestConfig, Sink};
use crate::registry::ParserRegistry;
use agf_core::enums::HealthState;
use agf_core::ids::{Id, TenantId};
use agf_core::source::{CollectionMode, SourceConnection};
use agf_core::time::Timestamp;

/// 内存 SQL 源：模拟"按游标列升序返回"的表，并记录收到的 SQL/游标。
#[derive(Debug, Default)]
pub(super) struct FakeSqlSource {
    rows: Mutex<Vec<(i64, String)>>,
    calls: Mutex<Vec<(String, Option<String>)>>,
    failing: Mutex<bool>,
    dialect: SqlDialect,
}

impl FakeSqlSource {
    pub(super) fn seed(&self, count: i64) {
        self.append(1, count);
    }

    /// 追加 `from..=to` 的行（模拟 Docker 用例里的"再插 2 行"）。
    pub(super) fn append(&self, from: i64, to: i64) {
        if let Ok(mut rows) = self.rows.lock() {
            for id in from..=to {
                rows.push((
                    id,
                    format!(r#"{{"id":{id},"ts":"2026-02-21T10:23:4{id}Z","message":"audit event {id}"}}"#),
                ));
            }
        }
    }

    /// MySQL 方言的内存源（SQL 里应出现 `?` 与 `CAST(... AS signed)`）。
    pub(super) fn mysql() -> Self {
        Self { dialect: SqlDialect::MySql, ..Self::default() }
    }

    /// Oracle 方言的内存源（SQL 里应出现 `:1`、`CAST(... AS NUMBER)` 与 `FETCH … ROWS ONLY`）。
    pub(super) fn oracle() -> Self {
        Self { dialect: SqlDialect::Oracle, ..Self::default() }
    }

    pub(super) fn calls(&self) -> Vec<(String, Option<String>)> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }

    pub(super) fn set_failing(&self, failing: bool) {
        if let Ok(mut flag) = self.failing.lock() {
            *flag = failing;
        }
    }
}

/// 从拼装后的 SQL 里取单轮上限（PG/MySQL `LIMIT n`、Oracle `FETCH NEXT|FIRST n ROWS ONLY`、
/// MSSQL `TOP (n)`）——让同一个内存源在四种方言下都按 `batch_limit` 截断。
pub(super) fn limit_of(sql: &str) -> usize {
    for marker in ["LIMIT ", "FETCH NEXT ", "FETCH FIRST ", "TOP ("] {
        if let Some(rest) = sql.split(marker).nth(1) {
            let token = rest.split_whitespace().next().unwrap_or_default().trim_matches(')');
            if let Ok(limit) = token.parse::<usize>() {
                return limit;
            }
        }
    }
    usize::MAX
}

#[async_trait]
impl SqlSource for FakeSqlSource {
    async fn fetch_rows(&self, sql: &str, cursor: Option<&str>) -> DomainResult<Vec<String>> {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push((sql.to_string(), cursor.map(ToString::to_string)));
        }
        if self.failing.lock().map(|f| *f).unwrap_or(false) {
            return Err(DomainError::DependencyUnavailable {
                dependency: "jdbc-postgres".to_string(),
                cause: "注入的连接失败".to_string(),
            });
        }
        let threshold = cursor.and_then(|c| c.parse::<i64>().ok()).unwrap_or(0);
        let limit = limit_of(sql);
        let rows = self.rows.lock().map_err(|e| DomainError::Internal(format!("锁中毒: {e}")))?;
        Ok(rows.iter().filter(|(id, _)| *id > threshold).take(limit).map(|(_, json)| json.clone()).collect())
    }

    fn describe(&self) -> String {
        match self.dialect {
            SqlDialect::Postgres => "postgres://agf:***@postgres:5432/aiguardfabric".to_string(),
            SqlDialect::MySql => "mysql://agf:***@mysql:3306/aiguardfabric".to_string(),
            SqlDialect::MsSql => "mssql://agf:***@mssql:1433/aiguardfabric".to_string(),
            SqlDialect::Oracle => "oracle://agf:***@oracle:1521/FREEPDB1".to_string(),
        }
    }

    fn dialect(&self) -> SqlDialect {
        self.dialect
    }
}

pub(super) fn log_source() -> LogSource {
    let now = Timestamp::now();
    LogSource {
        id: Id::new(),
        tenant_id: TenantId::default_tenant(),
        name: "sql-pull-test".to_string(),
        protocol: IngestProtocol::Jdbc,
        vendor: "generic".to_string(),
        product: "json".to_string(),
        enabled: true,
        parser_id: None,
        connection: SourceConnection {
            sql: Some("SELECT id, ts, message FROM audit_log".to_string()),
            ..SourceConnection::default()
        },
        mode: CollectionMode::Pull,
        poll_interval_secs: Some(5),
        require_mtls: false,
        allowed_cidrs: vec![],
        max_message_bytes: 1_048_576,
        max_eps: 0,
        tags: vec![],
        health: HealthState::Healthy,
        last_event_at: None,
        total_events: 0,
        last_error: None,
        created_at: now,
        updated_at: now,
    }
}

pub(super) fn pipeline_and_sink() -> (Arc<IngestPipeline>, Arc<InMemorySink>) {
    let sink = Arc::new(InMemorySink::new());
    let pipeline = IngestPipeline::new(
        ParserRegistry::with_builtins(),
        Arc::clone(&sink) as Arc<dyn Sink>,
        Arc::new(NoopEventBus),
        IngestConfig { emit_to_bus: false, ..IngestConfig::default() },
    );
    (Arc::new(pipeline), sink)
}

pub(super) fn config(cursor_field: Option<&str>, batch_limit: usize, cursor_path: Option<PathBuf>) -> SqlPullConfig {
    SqlPullConfig {
        sql: "SELECT id, ts, message FROM audit_log".to_string(),
        cursor_field: cursor_field.map(ToString::to_string),
        cursor_type: CursorType::Int,
        batch_limit,
        interval_secs: 1,
        cursor_path,
    }
}
