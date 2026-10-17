//! SQL 拉取单元测试：方言 SQL 组装、DSN 脱敏、游标落盘与接收器行为。

use super::tests_support::{FakeSqlSource, config, log_source, pipeline_and_sink};
use super::*;
use crate::pipeline::Sink as _;
use agf_core::ids::TenantId;

#[test]
fn pull_sql_is_composed_with_cursor_order_and_limit() {
    let sql = build_pull_sql("SELECT id FROM t;", Some("id"), CursorType::Int, 100);
    assert!(sql.is_ok(), "{sql:?}");
    let Ok(sql) = sql else { return };
    assert!(sql.starts_with("SELECT row_to_json(t)::text FROM (SELECT id FROM t) t"), "{sql}");
    assert!(sql.contains(r#"WHERE ("id")::bigint > $1::bigint"#), "{sql}");
    assert!(sql.contains(r#"ORDER BY ("id")::bigint ASC"#), "{sql}");
    assert!(sql.ends_with("LIMIT 100"), "{sql}");

    // 时间/文本游标使用各自的转型
    let ts = build_pull_sql("SELECT * FROM t", Some("ts"), CursorType::Timestamp, 10);
    assert!(ts.map(|s| s.contains("timestamptz")).unwrap_or(false));
    let text = build_pull_sql("SELECT * FROM t", Some("ts"), CursorType::Text, 10);
    assert!(text.map(|s| s.contains("::text")).unwrap_or(false));

    // 无游标列 ⇒ 不做增量（也不出现 $1）
    let plain = build_pull_sql("SELECT * FROM t", None, CursorType::Int, 5);
    assert!(plain.map(|s| !s.contains("$1")).unwrap_or(false));
    // 空 SQL ⇒ 配置错误
    assert!(matches!(build_pull_sql("   ", None, CursorType::Int, 1), Err(DomainError::Config(_))));
}

#[test]
fn identifiers_are_validated_against_injection() {
    assert_eq!(quote_identifier("id").unwrap_or_default(), "\"id\"");
    assert_eq!(quote_identifier("audit_log.id").unwrap_or_default(), "\"audit_log\".\"id\"");
    for bad in ["id; DROP TABLE t", "id\"", "id)", "1id", "", "a b"] {
        assert!(quote_identifier(bad).is_err(), "{bad:?} 必须被拒绝");
    }
    assert!(build_pull_sql("SELECT 1", Some("id; DROP TABLE x"), CursorType::Int, 1).is_err());
}

#[test]
fn mysql_dialect_uses_backticks_question_mark_and_cast() {
    // MySQL 默认 sql_mode 不认双引号标识符；也没有 `::` 转型运算符 ⇒ 必须 CAST + 反引号
    assert_eq!(quote_identifier_for("id", SqlDialect::MySql).unwrap_or_default(), "`id`");
    assert_eq!(quote_identifier_for("t.id", SqlDialect::MySql).unwrap_or_default(), "`t`.`id`");
    let sql = build_pull_sql_for(
        SqlDialect::MySql,
        "SELECT id, ts, message FROM audit_log;",
        Some("id"),
        CursorType::Int,
        100,
    );
    assert!(sql.is_ok(), "{sql:?}");
    let Ok(sql) = sql else { return };
    assert!(sql.starts_with("SELECT * FROM (SELECT id, ts, message FROM audit_log) t"), "{sql}");
    assert!(sql.contains("WHERE CAST(`id` AS signed) > CAST(? AS signed)"), "{sql}");
    assert!(sql.contains("ORDER BY CAST(`id` AS signed) ASC"), "{sql}");
    assert!(sql.ends_with("LIMIT 100"), "{sql}");
    assert!(!sql.contains("row_to_json"), "MySQL 没有 row_to_json：{sql}");
    assert!(!sql.contains("$1"), "MySQL 用 ? 占位符：{sql}");

    // 时间游标：MySQL 没有 timestamptz，映射到 datetime
    let ts = build_pull_sql_for(SqlDialect::MySql, "SELECT * FROM t", Some("ts"), CursorType::Timestamp, 10);
    assert!(ts.as_ref().map(|s| s.contains("CAST(`ts` AS datetime)")).unwrap_or(false), "{ts:?}");
    // 文本游标
    let text = build_pull_sql_for(SqlDialect::MySql, "SELECT * FROM t", Some("k"), CursorType::Text, 10);
    assert!(text.as_ref().map(|s| s.contains("CAST(`k` AS char)")).unwrap_or(false), "{text:?}");
    // 无游标列 ⇒ 不做增量（也不出现占位符）
    let plain = build_pull_sql_for(SqlDialect::MySql, "SELECT * FROM t", None, CursorType::Int, 5);
    assert!(plain.as_ref().map(|s| !s.contains('?') && !s.contains("WHERE")).unwrap_or(false), "{plain:?}");
    // MySQL 方言语义下同样拒绝注入
    assert!(build_pull_sql_for(SqlDialect::MySql, "SELECT 1", Some("id`; DROP"), CursorType::Int, 1).is_err());
    assert!(build_pull_sql_for(SqlDialect::MySql, "   ", Some("id"), CursorType::Int, 1).is_err());
}

#[test]
fn driver_is_selected_by_dsn_scheme() {
    assert_eq!(SqlDialect::from_dsn("postgres://agf:pw@pg:5432/db").ok(), Some(SqlDialect::Postgres));
    assert_eq!(SqlDialect::from_dsn("postgresql://agf@pg/db").ok(), Some(SqlDialect::Postgres));
    assert_eq!(SqlDialect::from_dsn("mysql://agf:pw@mysql:3306/db").ok(), Some(SqlDialect::MySql));
    assert_eq!(SqlDialect::from_dsn("  MariaDB://agf@db/x ").ok(), Some(SqlDialect::MySql));
    assert_eq!(SqlDialect::default(), SqlDialect::Postgres);
    // Oracle 已接线（oracle/OCI）：`oracle://` 与 `oracle+tcps://` 都归 Oracle 方言
    assert_eq!(SqlDialect::from_dsn("oracle://u:p@h:1521/svc").ok(), Some(SqlDialect::Oracle));
    assert_eq!(SqlDialect::from_dsn("oracle+tcps://u:p@h:2484/svc").ok(), Some(SqlDialect::Oracle));
    // 真正不受支持的 scheme 必须显式失败，绝不静默当 PostgreSQL 连
    assert!(matches!(SqlDialect::from_dsn("clickhouse://u:p@h:8123/db"), Err(DomainError::Config(_))));
    // MSSQL 已接线（tiberius）：三种 scheme 别名都认
    assert_eq!(SqlDialect::from_dsn("mssql://u:p@h:1433/db").ok(), Some(SqlDialect::MsSql));
    assert_eq!(SqlDialect::from_dsn("sqlserver://u:p@h/db").ok(), Some(SqlDialect::MsSql));
    assert_eq!(SqlDialect::from_dsn("tds://u:p@h/db").ok(), Some(SqlDialect::MsSql));
    assert!(matches!(SqlDialect::from_dsn(""), Err(DomainError::Config(_))));
    // 方言自述
    assert_eq!(SqlDialect::Postgres.as_str(), "postgres");
    assert_eq!(SqlDialect::MySql.driver_label(), "sqlx/MySQL");
    assert_eq!(SqlDialect::MsSql.driver_label(), "tiberius/MSSQL");
    assert_eq!(SqlDialect::Oracle.driver_label(), "oracle/OCI");
    assert_eq!(SqlDialect::MsSql.as_str(), "mssql");
    assert_eq!(SqlDialect::Oracle.as_str(), "oracle");
    assert_eq!(SqlDialect::Postgres.placeholder(), "$1");
    assert_eq!(SqlDialect::MySql.placeholder(), "?");
    assert_eq!(SqlDialect::MsSql.placeholder(), "@P1");
    assert_eq!(SqlDialect::Oracle.placeholder(), ":1");
    assert_eq!(SqlDialect::Postgres.driver_label(), "sqlx/PostgreSQL");
    assert_eq!(SqlDialect::MySql.as_str(), "mysql");
    // 游标类型 × 方言的转型矩阵
    assert_eq!(CursorType::Int.as_sql_cast(), "bigint");
    assert_eq!(CursorType::Int.as_sql_cast_for(SqlDialect::MySql), "signed");
    assert_eq!(CursorType::Int.as_sql_cast_for(SqlDialect::MsSql), "bigint");
    assert_eq!(CursorType::Int.as_sql_cast_for(SqlDialect::Oracle), "NUMBER");
    assert_eq!(CursorType::Timestamp.as_sql_cast_for(SqlDialect::Postgres), "timestamptz");
    assert_eq!(CursorType::Timestamp.as_sql_cast_for(SqlDialect::MySql), "datetime");
    assert_eq!(CursorType::Timestamp.as_sql_cast_for(SqlDialect::MsSql), "datetime2");
    assert_eq!(CursorType::Text.as_sql_cast_for(SqlDialect::MySql), "char");
    assert_eq!(CursorType::Text.as_sql_cast_for(SqlDialect::MsSql), "nvarchar(max)");
    assert_eq!(CursorType::Text.as_sql_cast_for(SqlDialect::Oracle), "VARCHAR2(4000)");
}

#[test]
fn mssql_dialect_uses_brackets_at_p1_and_offset_fetch() {
    // 有游标：CAST([id] AS bigint) + @P1 + ORDER BY + OFFSET/FETCH（T-SQL 的 OFFSET 强制要 ORDER BY）
    let sql = build_pull_sql_for(SqlDialect::MsSql, "SELECT id FROM t;", Some("id"), CursorType::Int, 100);
    assert!(sql.is_ok(), "{sql:?}");
    let Ok(sql) = sql else { return };
    assert!(sql.starts_with("SELECT * FROM (SELECT id FROM t) t"), "{sql}");
    assert!(sql.contains("WHERE CAST([id] AS bigint) > CAST(@P1 AS bigint)"), "{sql}");
    assert!(sql.contains("ORDER BY CAST([id] AS bigint) ASC"), "{sql}");
    assert!(sql.ends_with("OFFSET 0 ROWS FETCH NEXT 100 ROWS ONLY"), "{sql}");
    assert!(!sql.contains("LIMIT"), "T-SQL 没有 LIMIT：{sql}");
    assert!(!sql.contains("::"), "T-SQL 没有 :: 转型运算符：{sql}");
    // 无游标：没有 ORDER BY，因此改用 TOP (n)
    let plain = build_pull_sql_for(SqlDialect::MsSql, "SELECT id FROM t", None, CursorType::Int, 7);
    assert_eq!(plain.ok().as_deref(), Some("SELECT TOP (7) * FROM (SELECT id FROM t) t"));
    // 时间/文本游标的转型：datetime2 / nvarchar(max)
    let ts = build_pull_sql_for(SqlDialect::MsSql, "SELECT * FROM t", Some("ts"), CursorType::Timestamp, 10);
    assert!(ts.map(|s| s.contains("CAST([ts] AS datetime2)")).unwrap_or(false));
    let text = build_pull_sql_for(SqlDialect::MsSql, "SELECT * FROM t", Some("ts"), CursorType::Text, 10);
    assert!(text.map(|s| s.contains("CAST([ts] AS nvarchar(max))")).unwrap_or(false));
    // 方括号方言下同样拒绝注入与空 SQL
    assert!(build_pull_sql_for(SqlDialect::MsSql, "SELECT 1", Some("id]; DROP"), CursorType::Int, 1).is_err());
    assert!(build_pull_sql_for(SqlDialect::MsSql, "   ", Some("id"), CursorType::Int, 1).is_err());
}

#[test]
fn mssql_dsn_becomes_an_ado_connection_config() {
    let config = mssql_config_from_dsn("mssql://sa:P%40ssw0rd@mssql:1433/aiguardfabric").ok();
    assert!(config.is_some(), "DSN 应能解析成 tiberius::Config: {config:?}");
    let Some(config) = config else { return };
    // 自签证书默认信任（AGF 内网口径）；地址与端口来自 DSN
    assert_eq!(config.get_addr(), "mssql:1433");
    // 未知查询参数必须**显式报错**（不静默忽略一条写错的连接串）
    assert!(matches!(mssql_config_from_dsn("mssql://sa:pw@h:1433/db?bogus=1"), Err(DomainError::Config(_))));
    // 支持的参数可透传
    assert!(mssql_config_from_dsn("mssql://sa:pw@h/db?encrypt=required&application_name=agf").is_ok());
    // 缺主机 ⇒ 显式配置错误
    assert!(matches!(mssql_config_from_dsn("mssql:///db"), Err(DomainError::Config(_))));
    // 非法 DSN 的错误文本**不得包含口令**
    let leaked = mssql_config_from_dsn("mssql://sa:S3cret@h:notaport/db?encrypt=maybe").map_err(|e| e.to_string());
    if let Err(message) = leaked {
        assert!(!message.contains("S3cret"), "错误文本泄露了口令: {message}");
    }
}

#[test]
fn cursor_extraction_handles_types_and_nesting() {
    assert_eq!(cursor_from_row(r#"{"id":42}"#, "id").as_deref(), Some("42"));
    assert_eq!(cursor_from_row(r#"{"id":"abc"}"#, "id").as_deref(), Some("abc"));
    assert_eq!(cursor_from_row(r#"{"meta":{"seq":7}}"#, "meta.seq").as_deref(), Some("7"));
    assert_eq!(cursor_from_row(r#"{"id":true}"#, "id").as_deref(), Some("true"));
    assert!(cursor_from_row(r#"{"id":null}"#, "id").is_none());
    assert!(cursor_from_row(r#"{"other":1}"#, "id").is_none());
    assert!(cursor_from_row("not json", "id").is_none());
    assert_eq!(CursorType::parse("BIGINT"), Some(CursorType::Int));
    assert_eq!(CursorType::parse("timestamptz"), Some(CursorType::Timestamp));
    assert_eq!(CursorType::parse("bogus"), None);
    assert_eq!(CursorType::default().as_str(), "int");
}

#[test]
fn dsn_redaction_hides_password() {
    assert_eq!(redact_dsn("postgres://agf:s3cret@postgres:5432/db"), "postgres://agf:***@postgres:5432/db");
    assert_eq!(redact_dsn("mysql://agf:s3cret@mysql:3306/db"), "mysql://agf:***@mysql:3306/db");
    assert_eq!(redact_dsn("postgres://postgres:5432/db"), "postgres://postgres:5432/db");
    assert_eq!(redact_dsn("garbage"), "<dsn 非法或缺失 scheme>");
}

#[tokio::test]
async fn poll_advances_cursor_by_batch_and_never_skips_rows() {
    let source = Arc::new(FakeSqlSource::default());
    source.seed(5);
    let receiver = JdbcReceiver::new(Arc::clone(&source) as Arc<dyn SqlSource>, config(Some("id"), 2, None));
    let (pipeline, sink) = pipeline_and_sink();
    let log_source = log_source();

    let first = receiver.pull_once(&pipeline, &log_source, 10).await;
    assert!(first.is_ok(), "{first:?}");
    let Ok(first) = first else { return };
    assert_eq!(first.rows, 2, "batch 上限必须生效");
    assert_eq!(first.persisted, 2);
    assert_eq!(receiver.cursor().as_deref(), Some("2"), "游标推进到本批最后一行");
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(2));

    // 第二轮从游标继续（不跳行、不重拉）
    let second = receiver.pull_once(&pipeline, &log_source, 10).await;
    assert_eq!(second.map(|r| r.rows).unwrap_or(0), 2);
    assert_eq!(receiver.cursor().as_deref(), Some("4"));
    let third = receiver.pull_once(&pipeline, &log_source, 10).await;
    assert_eq!(third.map(|r| r.rows).unwrap_or(0), 1);
    assert_eq!(receiver.cursor().as_deref(), Some("5"));
    let fourth = receiver.pull_once(&pipeline, &log_source, 10).await;
    assert_eq!(fourth.map(|r| r.rows).unwrap_or(99), 0, "无新行时不再拉取");
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(5), "5 行恰好 5 条事件");

    // 第一轮 SQL 不带 $1，后续轮必须带游标绑定
    let calls = source.calls();
    assert!(calls.len() >= 4, "{calls:?}");
    assert!(calls.first().is_some_and(|(sql, cursor)| cursor.is_none() && !sql.contains("$1")), "{calls:?}");
    assert!(
        calls.get(1).is_some_and(|(sql, cursor)| sql.contains("$1") && cursor.as_deref() == Some("2")),
        "{calls:?}"
    );
}

#[tokio::test]
async fn cursor_file_prevents_reprocessing_after_restart() {
    let dir = std::env::temp_dir().join(format!("agf-sqlcursor-{}", uuid::Uuid::new_v4()));
    assert!(std::fs::create_dir_all(&dir).is_ok());
    let path = dir.join("cursor.json");
    let source = Arc::new(FakeSqlSource::default());
    source.seed(3);
    let source_trait = Arc::clone(&source) as Arc<dyn SqlSource>;
    let (pipeline, sink) = pipeline_and_sink();

    let first = JdbcReceiver::new(Arc::clone(&source_trait), config(Some("id"), 10, Some(path.clone())));
    assert_eq!(first.pull_once(&pipeline, &log_source(), 10).await.map(|r| r.rows).unwrap_or(0), 3);
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(3));
    drop(first);

    let restarted = JdbcReceiver::new(source_trait, config(Some("id"), 10, Some(path.clone())));
    assert_eq!(restarted.cursor().as_deref(), Some("3"), "游标必须从磁盘恢复");
    assert_eq!(restarted.pull_once(&pipeline, &log_source(), 10).await.map(|r| r.rows).unwrap_or(99), 0);
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(3), "重启后不得重复落库");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn query_failure_is_surfaced_without_losing_cursor() {
    let source = Arc::new(FakeSqlSource::default());
    source.seed(2);
    let receiver = JdbcReceiver::new(Arc::clone(&source) as Arc<dyn SqlSource>, config(Some("id"), 10, None));
    let (pipeline, _sink) = pipeline_and_sink();
    assert!(receiver.pull_once(&pipeline, &log_source(), 10).await.is_ok());
    assert_eq!(receiver.cursor().as_deref(), Some("2"));

    source.set_failing(true);
    let failed = receiver.pull_once(&pipeline, &log_source(), 10).await;
    assert!(matches!(failed, Err(DomainError::DependencyUnavailable { .. })), "{failed:?}");
    assert_eq!(receiver.cursor().as_deref(), Some("2"), "查询失败不得回退游标");
}

#[test]
fn describe_reports_ready_with_honest_todo() {
    let source = Arc::new(FakeSqlSource::default());
    let receiver = JdbcReceiver::new(source, config(Some("id"), 10, None));
    let descriptor = receiver.describe();
    assert_eq!(descriptor.status, ReceiverStatus::Ready);
    assert_eq!(descriptor.protocol, IngestProtocol::Jdbc);
    assert!(descriptor.note.contains("PostgreSQL"), "{}", descriptor.note);
    assert!(descriptor.note.contains("dialect=postgres"), "{}", descriptor.note);
    assert!(descriptor.todo.unwrap_or_default().contains("TODO ingest-jdbc-oracle"));
    assert_eq!(receiver.protocol(), IngestProtocol::Jdbc);
    assert_eq!(receiver.dialect(), SqlDialect::Postgres);
    assert!(receiver.preview_sql().is_ok());
    // 由日志源构造配置（缺 sql 必须报配置错误）
    assert!(SqlPullConfig::from_source(&log_source()).is_ok());
    let mut broken = log_source();
    broken.connection.sql = None;
    assert!(SqlPullConfig::from_source(&broken).is_err());
}

#[test]
fn mysql_receiver_describes_mysql_dialect() {
    let source = Arc::new(FakeSqlSource::mysql());
    let receiver = JdbcReceiver::new(source, config(Some("id"), 10, None));
    assert_eq!(receiver.dialect(), SqlDialect::MySql);
    let descriptor = receiver.describe();
    assert!(descriptor.note.contains("sqlx/MySQL"), "{}", descriptor.note);
    assert!(descriptor.note.contains("dialect=mysql"), "{}", descriptor.note);
    assert!(descriptor.note.contains("mysql://agf:***@mysql:3306/aiguardfabric"), "{}", descriptor.note);
    let sql = receiver.preview_sql().unwrap_or_default();
    // 首轮预览（无游标）不含 WHERE；但方言特征必须已经生效：无 $1、无 row_to_json
    assert!(!sql.contains("$1"), "MySQL 不能用 $1 占位符：{sql}");
    assert!(!sql.contains("row_to_json"), "MySQL 没有 row_to_json：{sql}");
    assert!(sql.ends_with("LIMIT 10"), "{sql}");
}

#[tokio::test]
async fn mysql_mode_pull_advances_cursor_exactly_like_postgres() {
    // 与 PostgreSQL 用例**同一口径**：首次 5 行 → 再插 2 行 → 只拉新增 2 行、游标前进
    let source = Arc::new(FakeSqlSource::mysql());
    source.seed(5);
    let receiver = JdbcReceiver::new(Arc::clone(&source) as Arc<dyn SqlSource>, config(Some("id"), 10, None));
    let (pipeline, sink) = pipeline_and_sink();
    let log_source = log_source();

    let first = receiver.pull_once(&pipeline, &log_source, 10).await;
    assert_eq!(first.map(|r| (r.rows, r.persisted)).ok(), Some((5, 5)), "首轮 5 行 ⇒ 5 条事件");
    assert_eq!(receiver.cursor().as_deref(), Some("5"));

    // 增量：再插 2 行，只应拉到新增的 id=6,7
    source.append(6, 7);
    let second = receiver.pull_once(&pipeline, &log_source, 10).await;
    assert_eq!(second.map(|r| r.rows).ok(), Some(2), "只应拉到新增的 2 行");
    assert_eq!(receiver.cursor().as_deref(), Some("7"), "游标必须前进到 7");
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(7), "5 + 2 恰好 7 条事件");
    // 第三轮无新行
    assert_eq!(receiver.pull_once(&pipeline, &log_source, 10).await.map(|r| r.rows).ok(), Some(0));

    // SQL 形态：首轮无 WHERE，后续轮带 CAST + ?
    let calls = source.calls();
    assert!(calls.len() >= 3, "{calls:?}");
    assert!(calls.first().is_some_and(|(sql, cursor)| cursor.is_none() && !sql.contains("WHERE")), "{calls:?}");
    assert!(
        calls.get(1).is_some_and(|(sql, cursor)| sql.contains("CAST(? AS signed)") && cursor.as_deref() == Some("5")),
        "{calls:?}"
    );
}

#[tokio::test]
async fn pull_metrics_track_rows_drops_cursor_and_errors() {
    let source = Arc::new(FakeSqlSource::mysql());
    source.seed(3);
    let receiver = JdbcReceiver::new(Arc::clone(&source) as Arc<dyn SqlSource>, config(Some("id"), 10, None));
    let (pipeline, _sink) = pipeline_and_sink();
    assert_eq!(receiver.pull_metrics().snapshot(), SqlPullMetricsSnapshot::default());

    let _ = receiver.pull_once(&pipeline, &log_source(), 10).await;
    let snapshot = receiver.pull_metrics().snapshot();
    assert_eq!(snapshot.rows_pulled, 3);
    assert_eq!(snapshot.batches, 1);
    assert_eq!(snapshot.cursor_advanced, 1);
    assert_eq!(snapshot.rows_dropped, 0);
    assert_eq!(snapshot.errors, 0);

    // 查询失败必须计数，且游标不回退
    source.set_failing(true);
    let _ = receiver.pull_once(&pipeline, &log_source(), 10).await;
    assert_eq!(receiver.pull_metrics().snapshot().errors, 1);
    assert_eq!(receiver.cursor().as_deref(), Some("3"));

    // Prometheus 文本：指标名 + 方言标签都在
    let text = receiver.pull_metrics().prometheus(receiver.dialect(), "jdbc");
    assert!(text.contains("agf_ingest_jdbc_rows_pulled_total{receiver=\"jdbc\",dialect=\"mysql\"} 3"), "{text}");
    assert!(text.contains("agf_ingest_jdbc_errors_total{receiver=\"jdbc\",dialect=\"mysql\"} 1"), "{text}");
    assert!(text.contains("# TYPE agf_ingest_jdbc_batches_total counter"), "{text}");
    assert!(text.contains("agf_ingest_jdbc_cursor_advanced_total"), "{text}");
    assert!(text.contains("agf_ingest_jdbc_rows_dropped_total"), "{text}");
}
