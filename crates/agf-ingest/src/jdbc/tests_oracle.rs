//! Oracle 方言专项单元测试：SQL 生成（占位符/转型/标识符/分页）、DSN 解析与口令脱敏、
//! 行 → JSON 解码三态、OCI 库目录解析、以及"**与 PostgreSQL/MySQL 共用同一份游标逻辑**"的守卫断言。
//!
//! 全部离线：解码用假 [`OracleCellReader`]，取数用内存 [`FakeSqlSource`]；
//! 真机（Docker 里的 Oracle Free）验证见 `tools/simulators/run_oracle_e2e.ps1` 与
//! `tests/oracle_live.rs`。

use chrono::{DateTime, Utc};

use super::tests_support::{FakeSqlSource, config, limit_of, log_source, pipeline_and_sink};
use super::*;
use crate::pipeline::Sink as _;
use agf_core::ids::TenantId;

// ---------------------------------------------------------------------------
// 假的一格取值（把驱动侧的"候选类型能否取到值"直接建模出来 ⇒ 解码决策表可离线断言）
// ---------------------------------------------------------------------------

/// 一格的所有候选取值：`null` 为真 ⇒ SQL NULL；全 `None` 且非 NULL ⇒ 类型全不匹配。
#[derive(Debug, Clone, Default)]
struct FakeValue {
    null: bool,
    i64: Option<i64>,
    u64: Option<u64>,
    f64: Option<f64>,
    flag: Option<bool>,
    timestamp: Option<DateTime<Utc>>,
    text: Option<String>,
    bytes: Option<Vec<u8>>,
}

/// 假的一列。
#[derive(Debug, Clone)]
struct FakeCell {
    name: String,
    type_name: String,
    kind: OracleColumnKind,
    value: FakeValue,
}

/// 假的一行。
#[derive(Debug, Default)]
struct FakeRow {
    cells: Vec<FakeCell>,
}

/// 三态装配：NULL 优先；取得到 ⇒ `Value`，取不到 ⇒ `Mismatch`。
fn pick<T>(cell: Option<&FakeCell>, get: impl FnOnce(&FakeCell) -> Option<T>) -> CellAttempt<T> {
    let Some(cell) = cell else {
        return CellAttempt::Mismatch;
    };
    if cell.value.null {
        return CellAttempt::Null;
    }
    match get(cell) {
        Some(value) => CellAttempt::Value(value),
        None => CellAttempt::Mismatch,
    }
}

impl OracleCellReader for FakeRow {
    fn len(&self) -> usize {
        self.cells.len()
    }

    fn name(&self, index: usize) -> String {
        self.cells.get(index).map(|cell| cell.name.clone()).unwrap_or_default()
    }

    fn type_name(&self, index: usize) -> String {
        self.cells.get(index).map(|cell| cell.type_name.clone()).unwrap_or_default()
    }

    fn kind(&self, index: usize) -> OracleColumnKind {
        self.cells.get(index).map_or(OracleColumnKind::Other, |cell| cell.kind)
    }

    fn is_null(&self, index: usize) -> bool {
        self.cells.get(index).is_some_and(|cell| cell.value.null)
    }

    fn try_i64(&self, index: usize) -> CellAttempt<i64> {
        pick(self.cells.get(index), |cell| cell.value.i64)
    }

    fn try_u64(&self, index: usize) -> CellAttempt<u64> {
        pick(self.cells.get(index), |cell| cell.value.u64)
    }

    fn try_f64(&self, index: usize) -> CellAttempt<f64> {
        pick(self.cells.get(index), |cell| cell.value.f64)
    }

    fn try_bool(&self, index: usize) -> CellAttempt<bool> {
        pick(self.cells.get(index), |cell| cell.value.flag)
    }

    fn try_datetime_utc(&self, index: usize) -> CellAttempt<DateTime<Utc>> {
        pick(self.cells.get(index), |cell| cell.value.timestamp)
    }

    fn try_text(&self, index: usize) -> CellAttempt<String> {
        pick(self.cells.get(index), |cell| cell.value.text.clone())
    }

    fn try_bytes(&self, index: usize) -> CellAttempt<Vec<u8>> {
        pick(self.cells.get(index), |cell| cell.value.bytes.clone())
    }
}

fn cell(name: &str, type_name: &str, kind: OracleColumnKind) -> FakeCell {
    FakeCell { name: name.to_string(), type_name: type_name.to_string(), kind, value: FakeValue::default() }
}

fn number_kind(integral: bool, narrow: bool) -> OracleColumnKind {
    OracleColumnKind::Number { integral, narrow }
}

/// 解析 RFC3339 文本为 UTC 时间（测试内部构造用；失败返回 `None`）。
fn ts(text: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text).ok().map(|value| value.with_timezone(&Utc))
}

/// 文本是否形如 `YYYY-MM-DDTHH:MM:SS.FF3Z`（与 SQL 侧 `TO_CHAR` 格式模型同形 ⇒ 字符串序即时间序）。
fn is_iso_millis_z(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 24
        && bytes.iter().enumerate().all(|(i, b)| match i {
            4 | 7 => *b == b'-',
            10 => *b == b'T',
            13 | 16 => *b == b':',
            19 => *b == b'.',
            23 => *b == b'Z',
            _ => b.is_ascii_digit(),
        })
}

fn parse(json: &str) -> Value {
    serde_json::from_str(json).unwrap_or(Value::Null)
}

// ---------------------------------------------------------------------------
// 1. SQL 生成：占位符 / 转型 / 标识符 / 分页
// ---------------------------------------------------------------------------

#[test]
fn oracle_dialect_sql_uses_colon_placeholder_cast_and_fetch_clause() {
    // 有游标：`:1` 占位符 + `CAST("id" AS NUMBER)` + 双引号标识符 + ORDER BY + OFFSET…FETCH NEXT
    let sql = build_pull_sql_for(SqlDialect::Oracle, "SELECT id FROM t;", Some("id"), CursorType::Int, 100);
    assert!(sql.is_ok(), "{sql:?}");
    let Ok(sql) = sql else { return };
    assert!(sql.starts_with("SELECT * FROM (SELECT id FROM t) t"), "{sql}");
    assert!(sql.contains(r#"WHERE CAST("id" AS NUMBER) > CAST(:1 AS NUMBER)"#), "{sql}");
    assert!(sql.contains(r#"ORDER BY CAST("id" AS NUMBER) ASC"#), "{sql}");
    assert!(sql.ends_with("OFFSET 0 ROWS FETCH NEXT 100 ROWS ONLY"), "{sql}");
    assert!(!sql.contains("LIMIT"), "Oracle 没有 LIMIT：{sql}");
    assert!(!sql.contains('$'), "Oracle 用 :1 而不是 $1：{sql}");
    assert!(!sql.contains("row_to_json"), "Oracle 没有 row_to_json：{sql}");

    // 无游标谓词（首轮）：没有可排序的列 ⇒ `OFFSET` 非法，必须用 `FETCH FIRST`
    let plain = build_pull_sql_for(SqlDialect::Oracle, "SELECT id FROM t", None, CursorType::Int, 7);
    assert_eq!(plain.ok().as_deref(), Some("SELECT * FROM (SELECT id FROM t) t FETCH FIRST 7 ROWS ONLY"));
    assert!(
        build_pull_sql_for(SqlDialect::Oracle, "SELECT 1", None, CursorType::Int, 1)
            .map(|s| !s.contains(":1") && !s.contains("WHERE"))
            .unwrap_or(false)
    );
    // 标识符：Oracle 用双引号（与 PostgreSQL 同形），点号分段；注入一律拒绝
    assert_eq!(quote_identifier_for("id", SqlDialect::Oracle).unwrap_or_default(), r#""id""#);
    assert_eq!(quote_identifier_for("t.id", SqlDialect::Oracle).unwrap_or_default(), r#""t"."id""#);
    assert!(build_pull_sql_for(SqlDialect::Oracle, "SELECT 1", Some("id\"; DROP"), CursorType::Int, 1).is_err());
    assert!(build_pull_sql_for(SqlDialect::Oracle, "   ", Some("id"), CursorType::Int, 1).is_err());
    // 转型矩阵
    assert_eq!(CursorType::Int.as_sql_cast_for(SqlDialect::Oracle), "NUMBER");
    assert_eq!(CursorType::Timestamp.as_sql_cast_for(SqlDialect::Oracle), "TIMESTAMP");
    assert_eq!(CursorType::Text.as_sql_cast_for(SqlDialect::Oracle), "VARCHAR2(4000)");
    assert_eq!(SqlDialect::Oracle.placeholder(), ":1");
    assert_eq!(SqlDialect::Oracle.as_str(), "oracle");
    assert_eq!(SqlDialect::Oracle.driver_label(), "oracle/OCI");
}

#[test]
fn oracle_timestamp_cursor_normalizes_both_sides_with_same_to_char_format() {
    // 时间游标：列侧 TO_CHAR 归一；绑定侧先 TO_TIMESTAMP 解析再 TO_CHAR 渲染回同一格式
    let sql = build_pull_sql_for(SqlDialect::Oracle, "SELECT * FROM t", Some("ts"), CursorType::Timestamp, 10);
    assert!(sql.is_ok(), "{sql:?}");
    let Ok(sql) = sql else { return };
    let quoted = format!("'{ORACLE_TIMESTAMP_FORMAT}'");
    assert!(sql.contains(&format!(r#"TO_CHAR("ts", {quoted})"#)), "{sql}");
    assert!(sql.contains(&format!(r"TO_CHAR(TO_TIMESTAMP(:1, {quoted}), {quoted})")), "{sql}");
    assert!(sql.contains("ORDER BY"), "{sql}");
    assert!(sql.ends_with("OFFSET 0 ROWS FETCH NEXT 10 ROWS ONLY"), "{sql}");
    // 格式模型：ISO-8601 + 毫秒 + 字面量 Z
    assert_eq!(ORACLE_TIMESTAMP_FORMAT, "YYYY-MM-DD\"T\"HH24:MI:SS.FF3\"Z\"");
    // 文本游标：CAST(col AS VARCHAR2(4000))
    let text = build_pull_sql_for(SqlDialect::Oracle, "SELECT * FROM t", Some("k"), CursorType::Text, 10);
    assert!(text.map(|s| s.contains(r#"CAST("k" AS VARCHAR2(4000))"#)).unwrap_or(false));
}

// ---------------------------------------------------------------------------
// 2. DSN 解析与口令脱敏
// ---------------------------------------------------------------------------

#[test]
fn oracle_dsn_is_parsed_into_ez_connect_or_tcps_descriptor() {
    // scheme 选择：oracle:// 与 oracle+tcps:// 都归 Oracle 方言（不再 NotImplemented/Config 报错）
    assert_eq!(SqlDialect::from_dsn("oracle://agf:pw@127.0.0.1:1521/FREEPDB1").ok(), Some(SqlDialect::Oracle));
    assert_eq!(SqlDialect::from_dsn("ORACLE+TCPS://agf@db:1521/svc").ok(), Some(SqlDialect::Oracle));

    // EZ Connect：口令里的 @ / : 必须能写（百分号解码）
    let params = oracle_connect_params_from_dsn("oracle://agf:Agf%40Test%3A2024@127.0.0.1:11521/FREEPDB1");
    assert!(params.is_ok(), "{params:?}");
    let Ok(params) = params else { return };
    assert_eq!(params.user(), "agf");
    assert_eq!(params.password(), "Agf@Test:2024");
    assert_eq!(params.connect_string(), "//127.0.0.1:11521/FREEPDB1");
    // 默认端口 1521（DSN 里不写端口也能连）
    let default_port = oracle_connect_params_from_dsn("oracle://agf:pw@db/FREEPDB1");
    assert!(default_port.map(|p| p.connect_string() == "//db:1521/FREEPDB1").unwrap_or(false));

    // TCPS：拼 TNS 描述符（PROTOCOL=TCPS）；`?tcps=1` 与 `oracle+tcps://` 等价
    let tcps = oracle_connect_params_from_dsn("oracle+tcps://agf:pw@db:2484/svc");
    assert!(
        tcps.map(|p| p.connect_string()
            == "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST=db)(PORT=2484))(CONNECT_DATA=(SERVICE_NAME=svc)))")
            .unwrap_or(false)
    );
    let query_tcps = oracle_connect_params_from_dsn("oracle://agf:pw@db:2484/svc?tcps=on");
    assert!(query_tcps.map(|p| p.connect_string().contains("PROTOCOL=TCPS")).unwrap_or(false));
    // 高级形态：完整 TNS 描述符原样透传
    let custom = oracle_connect_params_from_dsn(
        "oracle://agf:pw@db:1521/svc?descriptor=(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db)(PORT=1521)))",
    );
    assert!(
        custom
            .map(|p| p.connect_string() == "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db)(PORT=1521)))")
            .unwrap_or(false)
    );

    // 配置错误一律显式（不静默当别的库连）
    for bad in [
        "oracle://db/svc",                               // 缺用户名
        "oracle://agf:pw@/svc",                          // 缺主机
        "oracle://agf:pw@db:1521/",                      // 缺服务名
        "oracle://agf:pw@db:1521/svc?bogus=1",           // 不支持的查询参数
        "oracle://agf:pw@db:1521/svc?tcps=maybe",        // 非布尔值
        "oracle://agf:pw@db:1521/svc))((CONNECT_DATA=x", // 服务名含非法字符（描述符注入面）
        "postgres://agf:pw@db:5432/x",                   // scheme 不是 Oracle
        "not a dsn",
    ] {
        assert!(oracle_connect_params_from_dsn(bad).is_err(), "{bad:?} 必须显式报错");
    }
}

#[test]
fn oracle_password_never_leaks_into_debug_or_error_text() {
    let params = oracle_connect_params_from_dsn("oracle://agf:S3cret%40Pw@db:1521/svc");
    let Ok(params) = params else { return };
    let debug = format!("{params:?}");
    assert!(debug.contains("***"), "{debug}");
    assert!(!debug.contains("S3cret"), "Debug 泄露了口令: {debug}");
    assert!(debug.contains("//db:1521/svc"), "连接串应可见（便于排障）: {debug}");
    // DSN 脱敏（/readyz 与日志用）
    assert_eq!(redact_dsn("oracle://agf:S3cret@127.0.0.1:1521/FREEPDB1"), "oracle://agf:***@127.0.0.1:1521/FREEPDB1");
    assert_eq!(redact_dsn("oracle+tcps://agf:pw@db:2484/svc"), "oracle+tcps://agf:***@db:2484/svc");
    // 非法 DSN 的错误文本里出现的也必须是脱敏形态（不含口令）
    let err = oracle_connect_params_from_dsn("oracle://agf:S3cret@db:notaport/svc").map_err(|e| e.to_string());
    if let Err(message) = err {
        assert!(!message.contains("S3cret"), "错误文本泄露了口令: {message}");
    }
}

// ---------------------------------------------------------------------------
// 3. 行 → JSON 解码（三态 + 类型贪婪匹配）
// ---------------------------------------------------------------------------

#[test]
fn oracle_row_decoding_distinguishes_null_value_and_undecodable() {
    // 三态：SQL NULL ⇒ JSON null；解得出 ⇒ 值；类型全不匹配 ⇒ `<undecodable:类型>`（**不丢列**）
    let mut null_cell = cell("N", "Number(10, 0)", number_kind(true, true));
    null_cell.value = FakeValue { null: true, i64: None, text: None, ..FakeValue::default() };
    let mut undecodable = cell("CUR", "RefCursor", OracleColumnKind::Other);
    undecodable.value = FakeValue::default(); // 所有候选都取不到 ⇒ Mismatch
    let mut number = cell("ID", "Number(10, 0)", number_kind(true, true));
    number.value = FakeValue { i64: Some(42), text: Some("42".to_string()), ..FakeValue::default() };

    let row = FakeRow { cells: vec![null_cell, undecodable, number] };
    let json = parse(&oracle_row_to_json(&row));
    assert_eq!(json.get("N"), Some(&Value::Null), "SQL NULL 必须渲染为 JSON null：{json}");
    assert_eq!(json.get("CUR"), Some(&Value::from("<undecodable:RefCursor>")), "解不出的列必须带类型名出现：{json}");
    assert_eq!(json.get("ID"), Some(&Value::from(42)), "{json}");
    // 列名与顺序保真（Oracle 未加引号的标识符是大写，这里如实保留）；**不静默丢列**
    assert_eq!(json.as_object().map(serde_json::Map::len), Some(3), "{json}");
}

#[test]
fn oracle_number_decoding_prefers_exact_integers_and_keeps_text_columns_as_text() {
    // 宽整数（38 位）：i64/u64 取不到 ⇒ **优先进文本**（转 f64 会静默丢精度）
    let mut wide = cell("BIG", "Number(38, 0)", number_kind(true, false));
    wide.value = FakeValue {
        text: Some("123456789012345678901234567890".to_string()),
        f64: Some(1.234_567_890_123_456_8e29),
        ..FakeValue::default()
    };
    // 小数：整型取不到 ⇒ f64
    let mut decimal = cell("AMT", "Number(10, 2)", number_kind(false, false));
    decimal.value = FakeValue { i64: None, f64: Some(1.5), text: Some("1.5".to_string()), ..FakeValue::default() };
    // VARCHAR2 里的 "42" 必须保持字符串（不能被"贪婪数字匹配"改成 42）
    let mut numeric_text = cell("CODE", "Varchar2(8)", OracleColumnKind::Text);
    numeric_text.value = FakeValue { i64: Some(42), text: Some("42".to_string()), ..FakeValue::default() };
    // 窄整数：i64 优先（即使驱动也能给出文本）
    let mut narrow = cell("ID", "Number(10, 0)", number_kind(true, true));
    narrow.value = FakeValue { i64: Some(7), text: Some("7".to_string()), ..FakeValue::default() };

    let row = FakeRow { cells: vec![wide, decimal, numeric_text, narrow] };
    let json = parse(&oracle_row_to_json(&row));
    assert_eq!(json.get("BIG"), Some(&Value::from("123456789012345678901234567890")), "宽整数必须精确保真：{json}");
    assert_eq!(json.get("AMT"), Some(&Value::from(1.5)), "{json}");
    assert_eq!(json.get("CODE"), Some(&Value::from("42")), "VARCHAR2 必须仍是字符串：{json}");
    assert_eq!(json.get("ID"), Some(&Value::from(7)), "{json}");
}

#[test]
fn oracle_timestamp_and_binary_decoding_are_normalized() {
    // 时间列归一为 ISO-8601 毫秒 + 字面量 Z（与 SQL 侧 TO_CHAR 格式同形）
    let mut when = cell("TS", "Timestamp(6)", OracleColumnKind::Timestamp);
    when.value = FakeValue { timestamp: ts("2026-02-21T10:23:45.123Z"), ..FakeValue::default() };
    // 无时区的 DATE/TIMESTAMP 由驱动按 UTC 解释 ⇒ 同一格式
    let mut day = cell("D", "Date", OracleColumnKind::Timestamp);
    day.value = FakeValue { timestamp: ts("2026-02-21T00:00:00Z"), ..FakeValue::default() };
    // RAW/BLOB ⇒ 可打印直出、否则 hex（与 MySQL/MSSQL 共用同一份渲染）
    let mut raw = cell("R", "Raw(4)", OracleColumnKind::Binary);
    raw.value = FakeValue { bytes: Some(vec![0xde, 0xad, 0xbe, 0xef]), ..FakeValue::default() };
    let mut flag = cell("B", "Boolean", OracleColumnKind::Boolean);
    flag.value = FakeValue { flag: Some(true), ..FakeValue::default() };

    let row = FakeRow { cells: vec![when, day, raw, flag] };
    let json = parse(&oracle_row_to_json(&row));
    let rendered = json.get("TS").and_then(Value::as_str).unwrap_or_default();
    assert_eq!(rendered, "2026-02-21T10:23:45.123Z", "{json}");
    assert!(is_iso_millis_z(rendered), "必须与 TO_CHAR 格式模型同形: {rendered}");
    assert_eq!(json.get("D"), Some(&Value::from("2026-02-21T00:00:00.000Z")), "{json}");
    assert_eq!(json.get("R"), Some(&Value::from("deadbeef")), "{json}");
    assert_eq!(json.get("B"), Some(&Value::from(true)), "{json}");
    // 游标提取仍然只认 JSON（与其它方言同一条路径）
    assert_eq!(cursor_from_row(&oracle_row_to_json(&FakeRow::default()), "x"), None);
}

// ---------------------------------------------------------------------------
// 4. OCI 运行库目录解析（**不写全局 PATH、不污染机器**）
// ---------------------------------------------------------------------------

#[test]
fn oracle_client_lib_dir_resolution_never_writes_global_state() {
    // 显式给定（`AGF_ORACLE_CLIENT_LIB_DIR`）**永远优先**：目录不存在也原样采用，
    // 由驱动在连接时明确报"OCI 运行库加载失败（路径）"——比静默换目录更好诊断。
    assert_eq!(
        oracle_client_lib_dir(Some(r"D:\custom\instantclient")).map(|p| p.to_string_lossy().to_string()),
        Some(r"D:\custom\instantclient".to_string())
    );
    // 空白视同未配置
    assert_eq!(oracle_client_lib_dir(Some("   ")), oracle_client_lib_dir(None));
    // 未配置 ⇒ 只认**仓库内相对路径**（存在才返回；不存在 ⇒ None，交给 ODPI-C 按 PATH/ORACLE_HOME 找）。
    // 这条路径不需要写全局 PATH，也不需要往系统目录塞文件。
    match oracle_client_lib_dir(None) {
        Some(dir) => {
            assert_eq!(dir.as_path(), std::path::Path::new(DEFAULT_ORACLE_CLIENT_LIB_DIR));
            assert!(
                dir.join("oci.dll").is_file() || dir.join("libclntsh.so").is_file(),
                "命中默认目录时必须真是一份 Instant Client: {}",
                dir.display()
            );
        }
        None => assert!(!std::path::Path::new(DEFAULT_ORACLE_CLIENT_LIB_DIR).is_dir(), "目录存在却没被采用"),
    }
    assert_eq!(ORACLE_CLIENT_LIB_DIR_ENV, "AGF_ORACLE_CLIENT_LIB_DIR");
    assert_eq!(DEFAULT_ORACLE_CLIENT_LIB_DIR, "tools/oracle/instantclient_23_5");
}

// ---------------------------------------------------------------------------
// 5. 游标推进：与 PG/MySQL **共用同一份实现** 的守卫断言
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oracle_cursor_advances_exactly_like_postgres_and_mysql() {
    // 与 `mysql_mode_pull_advances_cursor_exactly_like_postgres` **同一口径**：
    // 首次 5 行 ⇒ 5 条事件 + 游标 "5"；再插 2 行 ⇒ 只 +2 + 游标 "7"；第三轮 0 行。
    let source = Arc::new(FakeSqlSource::oracle());
    source.seed(5);
    let receiver = JdbcReceiver::new(Arc::clone(&source) as Arc<dyn SqlSource>, config(Some("id"), 10, None));
    let (pipeline, sink) = pipeline_and_sink();
    let log_source = log_source();
    assert_eq!(receiver.dialect(), SqlDialect::Oracle);

    let first = receiver.pull_once(&pipeline, &log_source, 10).await;
    assert_eq!(first.map(|r| (r.rows, r.persisted)).ok(), Some((5, 5)), "首轮 5 行 ⇒ 5 条事件");
    assert_eq!(receiver.cursor().as_deref(), Some("5"));
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(5));

    source.append(6, 7);
    let second = receiver.pull_once(&pipeline, &log_source, 10).await;
    assert_eq!(second.map(|r| r.rows).ok(), Some(2), "只应拉到新增的 2 行");
    assert_eq!(receiver.cursor().as_deref(), Some("7"), "游标必须前进到 7");
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(7), "5 + 2 恰好 7 条事件");
    assert_eq!(receiver.pull_once(&pipeline, &log_source, 10).await.map(|r| r.rows).ok(), Some(0));

    // SQL 形态：首轮无 WHERE/占位符；后续轮带 CAST(:1 AS NUMBER)，且**不含** LIMIT/TOP/$1/反引号
    let calls = source.calls();
    assert!(calls.len() >= 3, "{calls:?}");
    assert!(
        calls.first().is_some_and(|(sql, cursor)| cursor.is_none() && !sql.contains("WHERE") && !sql.contains(":1")),
        "{calls:?}"
    );
    assert!(
        calls.get(1).is_some_and(|(sql, cursor)| sql.contains("CAST(:1 AS NUMBER)")
            && cursor.as_deref() == Some("5")
            && !sql.contains("LIMIT")
            && !sql.contains('`')
            && !sql.contains('$')),
        "{calls:?}"
    );
}

#[tokio::test]
async fn oracle_batch_limit_uses_fetch_clause_and_cursor_never_skips_rows() {
    // 分页（`OFFSET … FETCH NEXT`）必须真的生效：单轮上限 2 ⇒ 三批拉完 5 行，游标逐批推进
    let source = Arc::new(FakeSqlSource::oracle());
    source.seed(5);
    let receiver = JdbcReceiver::new(Arc::clone(&source) as Arc<dyn SqlSource>, config(Some("id"), 2, None));
    let (pipeline, sink) = pipeline_and_sink();
    let log_source = log_source();

    let mut cursors = Vec::new();
    let mut rows = Vec::new();
    for _ in 0..3 {
        let report = receiver.pull_once(&pipeline, &log_source, 10).await;
        assert!(report.is_ok(), "{report:?}");
        let Ok(report) = report else { return };
        rows.push(report.rows);
        cursors.push(receiver.cursor().unwrap_or_default());
    }
    assert_eq!(rows, vec![2, 2, 1], "5 行按单轮上限 2 分三批拉完");
    assert_eq!(cursors, vec!["2".to_string(), "4".to_string(), "5".to_string()], "游标只推进到本批最后一行");
    assert_eq!(sink.event_count(TenantId::default_tenant()).await.ok(), Some(5), "5 行恰好 5 条事件（不重不漏）");
    let calls = source.calls();
    assert!(
        calls.iter().all(|(sql, _)| sql.contains("FETCH NEXT 2 ROWS ONLY") || sql.contains("FETCH FIRST 2 ROWS ONLY")),
        "分页子句必须由方言给出：{calls:?}"
    );
    // 守卫：同一个 fake 在四种方言下解析出的单轮上限一致（分页语义与方言无关，只有拼装不同）
    for dialect in [SqlDialect::Postgres, SqlDialect::MySql, SqlDialect::MsSql, SqlDialect::Oracle] {
        let sql = build_pull_sql_for(dialect, "SELECT id FROM t", Some("id"), CursorType::Int, 13).unwrap_or_default();
        assert_eq!(limit_of(&sql), 13, "{dialect:?} 的单轮上限必须被内存源正确解析: {sql}");
    }
}

#[tokio::test]
async fn oracle_driver_failure_degrades_without_killing_the_receiver() {
    // 驱动/连接不可用 ⇒ 只报 `DependencyUnavailable`（**不是** Config/NotImplemented），游标不回退、
    // 错误计数 +1：调用方（apps/ingest 的 `sql_pull`）据此只 warn，进程与其余接收器不受影响。
    let source = Arc::new(FakeSqlSource::oracle());
    source.seed(3);
    let receiver = JdbcReceiver::new(Arc::clone(&source) as Arc<dyn SqlSource>, config(Some("id"), 10, None));
    let (pipeline, _sink) = pipeline_and_sink();
    assert!(receiver.pull_once(&pipeline, &log_source(), 10).await.is_ok());
    assert_eq!(receiver.cursor().as_deref(), Some("3"));

    source.set_failing(true);
    let failed = receiver.pull_once(&pipeline, &log_source(), 10).await;
    assert!(matches!(failed, Err(DomainError::DependencyUnavailable { .. })), "{failed:?}");
    assert_eq!(receiver.cursor().as_deref(), Some("3"), "故障不得回退游标");
    assert_eq!(receiver.pull_metrics().snapshot().errors, 1);
    // 指标标签必须是 oracle（/metrics 与 /readyz 同源）
    let text = receiver.pull_metrics().prometheus(receiver.dialect(), "jdbc");
    assert!(text.contains(r#"dialect="oracle""#), "{text}");
}

#[test]
fn oracle_receiver_describe_reports_oci_driver_honestly() {
    let source = Arc::new(FakeSqlSource::oracle());
    let receiver = JdbcReceiver::new(source, config(Some("id"), 10, None));
    let descriptor = receiver.describe();
    assert_eq!(descriptor.status, ReceiverStatus::Ready);
    assert!(descriptor.note.contains("oracle/OCI"), "{}", descriptor.note);
    assert!(descriptor.note.contains("dialect=oracle"), "{}", descriptor.note);
    assert!(descriptor.note.contains("oracle://agf:***@oracle:1521/FREEPDB1"), "{}", descriptor.note);
    let todo = descriptor.todo.unwrap_or_default();
    assert!(todo.contains("TODO ingest-jdbc-oracle"), "未覆盖项必须如实列出：{todo}");
    assert!(!todo.contains("Oracle 未实现"), "Oracle 已接线，不能再写未实现：{todo}");
    // 预览 SQL：首轮（无游标）不带 WHERE，但方言特征已生效
    let sql = receiver.preview_sql().unwrap_or_default();
    assert!(sql.ends_with("FETCH FIRST 10 ROWS ONLY"), "{sql}");
    assert!(!sql.contains("LIMIT"), "{sql}");
    assert!(sql.contains("SELECT * FROM ("), "{sql}");
}
