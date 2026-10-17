//! SQL 方言与语句构造：方言/游标类型、标识符引号、增量 SQL 组装与游标取值（纯函数，可离线断言）。

use super::*;

/// SQL 方言：决定占位符、游标转型、标识符引号与"行 → JSON"的落地方式。
///
/// **只有这一个枚举承载数据库差异**：游标推进、批上限、游标落盘、幂等全部与方言无关。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SqlDialect {
    /// PostgreSQL（`sqlx::PgPool`，`row_to_json` + `$1` + `::cast`）。
    #[default]
    Postgres,
    /// MySQL / MariaDB（`sqlx::MySqlPool`，`?` + `CAST(x AS t)`，行 JSON 由列元数据解码）。
    MySql,
    /// Microsoft SQL Server（`tiberius`，`@P1` + `CAST(x AS t)`，行 JSON 由列元数据解码）。
    ///
    /// T-SQL 没有 `::` 转型运算符、没有 `LIMIT`（用 `TOP (n)` 或
    /// `ORDER BY … OFFSET 0 ROWS FETCH NEXT n ROWS ONLY`），标识符用方括号 `[col]`。
    MsSql,
    /// Oracle Database（`oracle` crate / OCI，`:1` + `CAST(x AS NUMBER|VARCHAR2(n))`，
    /// 行 JSON 由列元数据解码；时间列走 `TO_CHAR` 归一）。
    ///
    /// 与其它方言的两处 Oracle 特有语义（都落在本文件，不在接收器里）：
    /// * **分页**：12c+ 的行限制子句。有游标谓词时已有 `ORDER BY` ⇒
    ///   `ORDER BY … OFFSET 0 ROWS FETCH NEXT n ROWS ONLY`；无游标谓词时没有排序项 ⇒
    ///   `FETCH FIRST n ROWS ONLY`（Oracle 允许无 `ORDER BY` 的 `FETCH FIRST`，`OFFSET` 则不允许）；
    /// * **时间列**：Oracle 的 `DATE`/`TIMESTAMP` 无时区，`CAST(x AS TIMESTAMP)` 的比较会牵扯
    ///   会话 NLS 设置 ⇒ 游标两侧统一 `TO_CHAR(…, 'YYYY-MM-DD"T"HH24:MI:SS.FF3"Z"')` 归一成
    ///   **同一段 ISO 文本**（与行 JSON 的渲染逐字节一致 ⇒ 字符串序即时间序，游标重启后自洽）。
    ///
    /// **标识符大小写（Oracle 特有，必读）**：未加引号的 Oracle 标识符**折叠为大写**，
    /// 而本方言按配置原样加双引号（`"col"`）⇒ 基础 SQL 里请用带引号的别名把列名固定下来，
    /// 例如 `SELECT id AS "id", ts AS "ts", message FROM audit_log`，并配 `cursor_field=id`。
    /// 否则结果为列名会是 `ID`、而谓词里的 `"id"` 会直接 ORA-00904（**显式报错，不静默**）。
    Oracle,
}

impl SqlDialect {
    /// 由 DSN scheme 推断驱动（这是"自动选驱动"的唯一判据）。
    ///
    /// # Errors
    /// DSN 为空、无 scheme，或 scheme 不受支持。
    pub fn from_dsn(dsn: &str) -> DomainResult<Self> {
        let trimmed = dsn.trim();
        if trimmed.is_empty() {
            return Err(DomainError::Config("SQL DSN 为空，无法判定驱动".to_string()));
        }
        let scheme = trimmed.split("://").next().unwrap_or_default().trim().to_ascii_lowercase();
        match scheme.as_str() {
            "postgres" | "postgresql" => Ok(Self::Postgres),
            "mysql" | "mariadb" => Ok(Self::MySql),
            "mssql" | "sqlserver" | "tds" => Ok(Self::MsSql),
            // `oracle+tcps://` 是同一驱动的 TLS 形态（连接串由 `oracle_connect_params_from_dsn` 决定）
            "oracle" | "oracle+tcps" => Ok(Self::Oracle),
            other => Err(DomainError::Config(format!(
                "不支持的 SQL DSN scheme {other:?}：当前驱动为 postgres:// (PostgreSQL)、\
                 mysql:// (MySQL)、mssql://|sqlserver:// (MSSQL) 与 oracle://|oracle+tcps:// (Oracle)"
            ))),
        }
    }

    /// 绑定占位符（PostgreSQL `$1` / MySQL `?` / MSSQL `@P1` / Oracle `:1`）。
    #[must_use]
    pub const fn placeholder(self) -> &'static str {
        match self {
            Self::Postgres => "$1",
            Self::MySql => "?",
            Self::MsSql => "@P1",
            Self::Oracle => ":1",
        }
    }

    /// 稳定名称（日志 / `/readyz` / 能力矩阵）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::MySql => "mysql",
            Self::MsSql => "mssql",
            Self::Oracle => "oracle",
        }
    }

    /// 驱动描述（人读）。
    #[must_use]
    pub const fn driver_label(self) -> &'static str {
        match self {
            Self::Postgres => "sqlx/PostgreSQL",
            Self::MySql => "sqlx/MySQL",
            Self::MsSql => "tiberius/MSSQL",
            Self::Oracle => "oracle/OCI",
        }
    }
}

/// Oracle 时间列的归一格式（`TO_CHAR` 格式模型字面量）：ISO-8601、毫秒精度、字面量 `Z`。
///
/// 与行 JSON 的渲染格式 [`ORACLE_TIMESTAMP_RENDER`] **逐字节一致**，因此
/// **字符串比较即时间比较**：游标落盘的是这段文本，重启后不需要会话时区参与即可继续增量。
pub const ORACLE_TIMESTAMP_FORMAT: &str = "YYYY-MM-DD\"T\"HH24:MI:SS.FF3\"Z\"";

/// 行 JSON 里时间列的渲染格式（chrono），与 [`ORACLE_TIMESTAMP_FORMAT`] 对齐。
pub const ORACLE_TIMESTAMP_RENDER: &str = "%Y-%m-%dT%H:%M:%S%.3fZ";

/// 游标列的类型（决定 SQL 里的显式转型，保证比较语义正确）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CursorType {
    /// 整数列（`id` / 递增主键）：数字比较。
    #[default]
    Int,
    /// 时间列：时间比较（含时区）。
    Timestamp,
    /// 文本列（形如 `20260221T102345` 的有序字符串）。
    Text,
}

impl CursorType {
    /// 解析文本（未知值 ⇒ `None`，由调用方决定是报错还是取默认）。
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "int" | "integer" | "bigint" | "i64" | "number" => Some(Self::Int),
            "ts" | "timestamp" | "timestamptz" | "datetime" | "time" => Some(Self::Timestamp),
            "text" | "string" | "varchar" => Some(Self::Text),
            _ => None,
        }
    }

    /// PostgreSQL 转型文本（等价于 `as_sql_cast_for(SqlDialect::Postgres)`）。
    #[must_use]
    pub const fn as_sql_cast(self) -> &'static str {
        self.as_sql_cast_for(SqlDialect::Postgres)
    }

    /// 按方言给出游标转型目标类型。
    ///
    /// MySQL 没有 `timestamptz`：`TIMESTAMP` / `DATETIME` 列统一转 `datetime` 参与比较
    /// （`CAST(? AS datetime)` 会把绑定参数字符串按会话时区解释为时间，语义与列类型一致）。
    /// MSSQL 同理：统一转 `datetime2`（比 `datetime` 精度更高、无 1753 年下界），
    /// 文本转 `nvarchar(max)`（T-SQL 的 `CAST(x AS nvarchar(max))` 是唯一能容纳任意长度字符串的形式）。
    /// Oracle：数值转 `NUMBER`、文本转 `VARCHAR2(4000)`；时间的目标类型是 `TIMESTAMP`，
    /// 但实际渲染走 `TO_CHAR` 归一（见 [`Self::cast_column`]）。
    #[must_use]
    pub const fn as_sql_cast_for(self, dialect: SqlDialect) -> &'static str {
        match (self, dialect) {
            (Self::Int, SqlDialect::Postgres) => "bigint",
            (Self::Timestamp, SqlDialect::Postgres) => "timestamptz",
            (Self::Text, SqlDialect::Postgres) => "text",
            (Self::Int, SqlDialect::MySql) => "signed",
            (Self::Timestamp, SqlDialect::MySql) => "datetime",
            (Self::Text, SqlDialect::MySql) => "char",
            (Self::Int, SqlDialect::MsSql) => "bigint",
            (Self::Timestamp, SqlDialect::MsSql) => "datetime2",
            (Self::Text, SqlDialect::MsSql) => "nvarchar(max)",
            (Self::Int, SqlDialect::Oracle) => "NUMBER",
            (Self::Timestamp, SqlDialect::Oracle) => "TIMESTAMP",
            (Self::Text, SqlDialect::Oracle) => "VARCHAR2(4000)",
        }
    }

    /// 把**列**表达式渲染成"转型后的可比较值"
    /// （PG `(col)::bigint`；MySQL / MSSQL / Oracle `CAST(col AS t)`；Oracle 时间列 `TO_CHAR(col, fmt)`）。
    fn cast_column(self, dialect: SqlDialect, column: &str) -> String {
        let target = self.as_sql_cast_for(dialect);
        match (self, dialect) {
            // Oracle 时间列：`DATE` / `TIMESTAMP` / `TIMESTAMP WITH [LOCAL] TIME ZONE`
            // 一律 `TO_CHAR` 归一成 ISO 文本（与行 JSON 的渲染同格式 ⇒ 两侧可直接按文本比较）
            (Self::Timestamp, SqlDialect::Oracle) => {
                format!("TO_CHAR({column}, '{ORACLE_TIMESTAMP_FORMAT}')")
            }
            (_, SqlDialect::Postgres) => format!("({column})::{target}"),
            (_, SqlDialect::MySql | SqlDialect::MsSql | SqlDialect::Oracle) => {
                format!("CAST({column} AS {target})")
            }
        }
    }

    /// 把**绑定参数**渲染成同类型表达式
    /// （PG `$1::bigint`；MySQL / MSSQL / Oracle `CAST(? AS t)`；Oracle 时间列走 `TO_CHAR`+`TO_TIMESTAMP`）。
    fn cast_placeholder(self, dialect: SqlDialect) -> String {
        let target = self.as_sql_cast_for(dialect);
        let placeholder = dialect.placeholder();
        match (self, dialect) {
            // 先把游标文本按同一格式**解析**成 TIMESTAMP（格式不符立刻报错，不静默比较垃圾值），
            // 再按同一格式渲染回文本 —— 与列侧逐字节同构，因此 `>` 就是时间比较。
            (Self::Timestamp, SqlDialect::Oracle) => format!(
                "TO_CHAR(TO_TIMESTAMP({placeholder}, '{ORACLE_TIMESTAMP_FORMAT}'), '{ORACLE_TIMESTAMP_FORMAT}')"
            ),
            (_, SqlDialect::Postgres) => format!("{placeholder}::{target}"),
            (_, SqlDialect::MySql | SqlDialect::MsSql | SqlDialect::Oracle) => {
                format!("CAST({placeholder} AS {target})")
            }
        }
    }

    /// 配置文本。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Int => "int",
            Self::Timestamp => "timestamptz",
            Self::Text => "text",
        }
    }
}

/// 校验并加引号一个（可带表别名的）SQL 标识符。
///
/// # Errors
/// 空标识符或含非法字符（`;` / 引号 / 空格 / 逗号 …）。
pub fn quote_identifier(field: &str) -> DomainResult<String> {
    quote_identifier_for(field, SqlDialect::Postgres)
}

/// 按方言给标识符加引号。
///
/// PostgreSQL 与 Oracle 用双引号 `"col"`；MySQL 默认 sql_mode 不认双引号标识符，必须用反引号；
/// MSSQL 用方括号 `[col]`（`QUOTED_IDENTIFIER` 为 OFF 时双引号不是标识符）。
///
/// **Oracle 特有**：未加引号的标识符折叠为**大写**，因此这里保留配置原样的大小写，
/// 基础 SQL 需用 `AS "col"` 把列名固定住（见 [`SqlDialect::Oracle`]）。
///
/// # Errors
/// 空标识符或含非法字符（`;` / 引号 / 反引号 / 空格 / 逗号 …）。
pub fn quote_identifier_for(field: &str, dialect: SqlDialect) -> DomainResult<String> {
    let trimmed = field.trim();
    if trimmed.is_empty() {
        return Err(DomainError::Config("游标列不能为空".to_string()));
    }
    let (open, close) = match dialect {
        SqlDialect::Postgres | SqlDialect::Oracle => ('"', '"'),
        SqlDialect::MySql => ('`', '`'),
        SqlDialect::MsSql => ('[', ']'),
    };
    let mut parts = Vec::new();
    for part in trimmed.split('.') {
        let ok = !part.is_empty()
            && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
            && part.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
        if !ok {
            return Err(DomainError::Validation(format!(
                "游标列 {field:?} 含非法标识符片段 {part:?}（只允许字母/数字/下划线，点号分隔）"
            )));
        }
        parts.push(format!("{open}{part}{close}"));
    }
    Ok(parts.join("."))
}

/// 拼装 PostgreSQL 拉取 SQL（保持既有签名：老调用方与老单测不变）。
///
/// # Errors
/// 基础 SQL 为空或游标列非法。
pub fn build_pull_sql(
    base_sql: &str,
    cursor_field: Option<&str>,
    cursor_type: CursorType,
    limit: usize,
) -> DomainResult<String> {
    build_pull_sql_for(SqlDialect::Postgres, base_sql, cursor_field, cursor_type, limit)
}

/// 按方言拼装拉取 SQL（纯函数，便于单测与审计）。
///
/// 四种方言只在三处分叉，游标语义完全一致：
/// * 行 → JSON：PostgreSQL `row_to_json(t)::text`；MySQL / MSSQL / Oracle 无等价函数，直接取原始列，
///   由对应的 `MySqlSource` / `MsSqlSource` / `OracleSource` 按列元数据解码（见 [`mysql_row_to_json`]）；
/// * 转型：PostgreSQL `(col)::bigint`；MySQL `CAST(col AS signed)`；MSSQL `CAST(col AS bigint)`
///   （T-SQL 没有 `::` 运算符）；Oracle `CAST(col AS NUMBER|VARCHAR2(4000))`、时间列
///   `TO_CHAR(col, 'YYYY-MM-DD"T"HH24:MI:SS.FF3"Z"')`（Oracle 的 DATE/TIMESTAMP 无时区，
///   归一成 ISO 文本后字符串序即时间序）；
/// * 分页：PostgreSQL / MySQL 用 `LIMIT n`；MSSQL 用 `TOP (n)`（无 ORDER BY 时）或
///   `ORDER BY … OFFSET 0 ROWS FETCH NEXT n ROWS ONLY`（有游标谓词时，T-SQL 的 `OFFSET/FETCH`
///   **强制要求** `ORDER BY`，而无游标谓词就没有排序项）；Oracle 12c+ 用
///   `OFFSET 0 ROWS FETCH NEXT n ROWS ONLY`（有游标谓词时）或 `FETCH FIRST n ROWS ONLY`
///   （无游标谓词时，Oracle 允许无 `ORDER BY` 的 `FETCH FIRST` 而不允许 `OFFSET`）。
///
/// # Errors
/// 基础 SQL 为空或游标列非法。
pub fn build_pull_sql_for(
    dialect: SqlDialect,
    base_sql: &str,
    cursor_field: Option<&str>,
    cursor_type: CursorType,
    limit: usize,
) -> DomainResult<String> {
    let base = base_sql.trim().trim_end_matches(';').trim();
    if base.is_empty() {
        return Err(DomainError::Config("SQL 拉取需要非空的 connection.sql / AGF_INGEST_SQL_QUERY".to_string()));
    }
    let field = cursor_field.map(str::trim).filter(|f| !f.is_empty());
    let mut sql = match dialect {
        SqlDialect::Postgres => format!("SELECT row_to_json(t)::text FROM ({base}) t"),
        SqlDialect::MySql | SqlDialect::Oracle => format!("SELECT * FROM ({base}) t"),
        SqlDialect::MsSql if field.is_some() => format!("SELECT * FROM ({base}) t"),
        SqlDialect::MsSql => format!("SELECT TOP ({}) * FROM ({base}) t", limit.max(1)),
    };
    if let Some(field) = field {
        let column = quote_identifier_for(field, dialect)?;
        let lhs = cursor_type.cast_column(dialect, &column);
        let rhs = cursor_type.cast_placeholder(dialect);
        sql.push_str(&format!(" WHERE {lhs} > {rhs} ORDER BY {lhs} ASC"));
    }
    match dialect {
        SqlDialect::Postgres | SqlDialect::MySql => sql.push_str(&format!(" LIMIT {}", limit.max(1))),
        SqlDialect::MsSql if field.is_some() => {
            sql.push_str(&format!(" OFFSET 0 ROWS FETCH NEXT {} ROWS ONLY", limit.max(1)));
        }
        SqlDialect::MsSql => {}
        // Oracle 12c+ 行限制子句（必须排在 ORDER BY 之后）
        SqlDialect::Oracle if field.is_some() => {
            sql.push_str(&format!(" OFFSET 0 ROWS FETCH NEXT {} ROWS ONLY", limit.max(1)));
        }
        SqlDialect::Oracle => sql.push_str(&format!(" FETCH FIRST {} ROWS ONLY", limit.max(1))),
    }
    Ok(sql)
}

/// 从行 JSON 中取游标值（支持 `a.b` 形式的嵌套键；数字/布尔按文本渲染）。
#[must_use]
pub fn cursor_from_row(row_json: &str, cursor_field: &str) -> Option<String> {
    let value: Value = serde_json::from_str(row_json).ok()?;
    let mut current = &value;
    for part in cursor_field.split('.') {
        current = current.get(part.trim())?;
    }
    match current {
        Value::Null => None,
        Value::String(text) => Some(text.clone()),
        other => Some(other.to_string()),
    }
}
