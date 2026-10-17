//! SQL 数据源抽象与三个驱动实现：`SqlSource`、PostgreSQL / MySQL / MSSQL
//! （DSN 选择驱动、行 → JSON、DSN 脱敏）。

use super::*;

// MSSQL（`tiberius`）走 `futures_util` 的 AsyncRead/AsyncWrite 抽象，`tokio::net::TcpStream`
// 需要用 `tokio-util` 的 compat 层适配（`compat_write()` 给的是写侧 compat，
// 读侧由 `Compat` 类型本身承担）。
use tokio_util::compat::Compat;
use tokio_util::compat::TokioAsyncWriteCompatExt as _;

/// SQL 数据源抽象（真实实现走 `sqlx::PgPool`；测试注入内存实现，**测试不依赖数据库**）。
#[async_trait]
pub trait SqlSource: Send + Sync + std::fmt::Debug {
    /// 执行拉取语句，返回每行的 JSON 文本。
    ///
    /// `cursor` 为 `None` 时**不绑定 `$1`**（调用方保证此时 SQL 里没有占位符）。
    ///
    /// # Errors
    /// 连接失败、SQL 语法/权限错误、类型不匹配。
    async fn fetch_rows(&self, sql: &str, cursor: Option<&str>) -> DomainResult<Vec<String>>;

    /// 描述（`/readyz` 与日志用）。
    fn describe(&self) -> String;

    /// 本方言的 SQL 拼装规则（默认 PostgreSQL；MySQL 实现覆写）。
    fn dialect(&self) -> SqlDialect {
        SqlDialect::Postgres
    }
}

/// `sqlx` 的 PostgreSQL 实现。
#[derive(Debug, Clone)]
pub struct PgSqlSource {
    pool: sqlx::PgPool,
    label: String,
}

impl PgSqlSource {
    /// 连接数据库（连接失败 ⇒ 明确错误，由调用方决定是否降级为"接收器不启用"）。
    ///
    /// # Errors
    /// DSN 非法或数据库不可达。
    pub async fn connect(dsn: &str, max_connections: u32) -> DomainResult<Self> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(max_connections.max(1))
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(dsn)
            .await
            .map_err(|e| DomainError::DependencyUnavailable {
                dependency: "jdbc-postgres".to_string(),
                cause: format!("连接 PostgreSQL 失败: {e}"),
            })?;
        Ok(Self { pool, label: redact_dsn(dsn) })
    }

    /// 底层连接池。
    #[must_use]
    pub const fn pool(&self) -> &sqlx::PgPool {
        &self.pool
    }
}

/// 去掉 DSN 里的口令（**日志与 /readyz 不得出现明文口令**）。
#[must_use]
pub fn redact_dsn(dsn: &str) -> String {
    let Some((scheme, rest)) = dsn.split_once("://") else {
        return "<dsn 非法或缺失 scheme>".to_string();
    };
    let Some((credentials, host)) = rest.rsplit_once('@') else {
        return format!("{scheme}://{rest}");
    };
    let user = credentials.split(':').next().unwrap_or("user");
    format!("{scheme}://{user}:***@{host}")
}

/// 按 DSN scheme 选驱动并连接（**唯一的"自动选驱动"入口**）。
///
/// * `postgres://` / `postgresql://` ⇒ [`PgSqlSource`]；
/// * `mysql://` / `mariadb://` ⇒ [`MySqlSource`]；
/// * `mssql://` / `sqlserver://` / `tds://` ⇒ [`MsSqlSource`]（`tiberius`，TDS 7.3+）；
/// * `oracle://` / `oracle+tcps://` ⇒ [`OracleSource`]（`oracle` crate / OCI + 项目内 instantclient）；
/// * 其余 scheme ⇒ 配置错误。
///
/// 返回 `dyn SqlSource`：调用方（`JdbcReceiver`）拿到的抽象完全一致，
/// **游标/分页/落盘/幂等逻辑对四种数据库只有一份**。
///
/// # Errors
/// scheme 不受支持，或数据库不可达 / 认证失败 / 驱动（OCI 运行库）不可用。
pub async fn connect_from_dsn(dsn: &str, max_connections: u32) -> DomainResult<Arc<dyn SqlSource>> {
    match SqlDialect::from_dsn(dsn)? {
        SqlDialect::Postgres => Ok(Arc::new(PgSqlSource::connect(dsn, max_connections).await?)),
        SqlDialect::MySql => Ok(Arc::new(MySqlSource::connect(dsn, max_connections).await?)),
        SqlDialect::MsSql => Ok(Arc::new(MsSqlSource::connect(dsn).await?)),
        SqlDialect::Oracle => Ok(Arc::new(OracleSource::connect(dsn).await?)),
    }
}

/// `sqlx` 的 MySQL 实现。
///
/// MySQL 没有 `row_to_json`，因此这里**不做 SQL 侧行序列化**：拉原始列，
/// 由 [`mysql_row_to_json`] 按结果集列元数据解码成 JSON 对象——列名与顺序保真，
/// 下游（游标提取 + 解析流水线）与 PostgreSQL 路径完全同构。
#[derive(Debug, Clone)]
pub struct MySqlSource {
    pool: sqlx::MySqlPool,
    label: String,
}

impl MySqlSource {
    /// 连接 MySQL（连接失败 ⇒ 明确错误，由调用方决定是否降级为"接收器不启用"）。
    ///
    /// # Errors
    /// DSN 非法、认证失败或数据库不可达。
    pub async fn connect(dsn: &str, max_connections: u32) -> DomainResult<Self> {
        let pool = sqlx::mysql::MySqlPoolOptions::new()
            .max_connections(max_connections.max(1))
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(dsn)
            .await
            .map_err(|e| DomainError::DependencyUnavailable {
                dependency: "jdbc-mysql".to_string(),
                cause: format!("连接 MySQL 失败: {e}"),
            })?;
        Ok(Self { pool, label: redact_dsn(dsn) })
    }

    /// 底层连接池。
    #[must_use]
    pub const fn pool(&self) -> &sqlx::MySqlPool {
        &self.pool
    }
}

/// 把一行 MySQL 结果按**列元数据类型**解码为 JSON 文本。
///
/// 解码顺序即"类型贪婪匹配"：依次尝试 `i64 → u64 → f64 → bool → NaiveDateTime →
/// DateTime<Utc> → String → Vec<u8>(hex)`，全部失败才落到 `"<undecodable:{type}>"`。
/// **绝不 panic、绝不静默丢列**：解不出的列也会带着类型名出现在 JSON 里。
#[must_use]
pub fn mysql_row_to_json(row: &sqlx::mysql::MySqlRow) -> String {
    use sqlx::{Column, Row, TypeInfo, ValueRef};
    let mut map = serde_json::Map::new();
    for (index, column) in row.columns().iter().enumerate() {
        let type_name = column.type_info().name().to_string();
        let is_null = row.try_get_raw(index).map(|value| value.is_null()).unwrap_or(true);
        let value = if is_null {
            Value::Null
        } else if let Ok(v) = row.try_get::<i64, _>(index) {
            Value::from(v)
        } else if let Ok(v) = row.try_get::<u64, _>(index) {
            Value::from(v)
        } else if let Ok(v) = row.try_get::<f64, _>(index) {
            Value::from(v)
        } else if let Ok(v) = row.try_get::<bool, _>(index) {
            Value::from(v)
        } else if let Ok(v) = row.try_get::<chrono::NaiveDateTime, _>(index) {
            // MySQL 的 DATETIME/TIMESTAMP 无时区：统一按 ISO-8601 无偏移输出（不臆造时区）
            Value::from(v.format("%Y-%m-%dT%H:%M:%S%.f").to_string())
        } else if let Ok(v) = row.try_get::<chrono::DateTime<chrono::Utc>, _>(index) {
            Value::from(v.to_rfc3339())
        } else if let Ok(v) = row.try_get::<String, _>(index) {
            Value::from(v)
        } else if let Ok(v) = row.try_get::<Vec<u8>, _>(index) {
            Value::from(render_binary(&v))
        } else {
            Value::from(format!("<undecodable:{type_name}>"))
        };
        map.insert(column.name().to_string(), value);
    }
    Value::Object(map).to_string()
}

/// 二进制列渲染：可打印 ASCII 直出，否则 hex（避免把二进制塞进事件正文）。
///
/// MySQL / MSSQL / Oracle 三条"按列元数据解码"的路径**共用这一份**渲染。
pub(crate) fn render_binary(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let printable = !bytes.is_empty() && bytes.iter().all(|b| b.is_ascii_graphic() || *b == b' ' || *b == b'\t');
    if printable {
        String::from_utf8_lossy(bytes).to_string()
    } else {
        let mut out = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}

#[async_trait]
impl SqlSource for MySqlSource {
    async fn fetch_rows(&self, sql: &str, cursor: Option<&str>) -> DomainResult<Vec<String>> {
        let mut query = sqlx::query(sql);
        if let Some(cursor) = cursor {
            query = query.bind(cursor.to_string());
        }
        let rows = query.fetch_all(&self.pool).await.map_err(|e| DomainError::DependencyUnavailable {
            dependency: "jdbc-mysql".to_string(),
            cause: format!("执行拉取语句失败: {e}"),
        })?;
        Ok(rows.iter().map(mysql_row_to_json).collect())
    }

    fn describe(&self) -> String {
        self.label.clone()
    }

    fn dialect(&self) -> SqlDialect {
        SqlDialect::MySql
    }
}

#[async_trait]
impl SqlSource for PgSqlSource {
    async fn fetch_rows(&self, sql: &str, cursor: Option<&str>) -> DomainResult<Vec<String>> {
        let mut query = sqlx::query_scalar::<sqlx::Postgres, String>(sql);
        if let Some(cursor) = cursor {
            query = query.bind(cursor.to_string());
        }
        query.fetch_all(&self.pool).await.map_err(|e| DomainError::DependencyUnavailable {
            dependency: "jdbc-postgres".to_string(),
            cause: format!("执行拉取语句失败: {e}"),
        })
    }

    fn describe(&self) -> String {
        self.label.clone()
    }
}

// ---------------------------------------------------------------------------
// MSSQL（tiberius，TDS 7.3+）
// ---------------------------------------------------------------------------

/// `tiberius` 的 MSSQL 实现（**纯 Rust**，无 ODBC / FreeTDS / ODPI-C 之类的 C 依赖）。
///
/// MSSQL 与 MySQL 一样没有 `row_to_json` 等价物，因此同样**不做 SQL 侧行序列化**：
/// 拉原始列，由 [`mssql_row_to_json`] 按结果集列元数据解码成 JSON 对象——列名与顺序保真，
/// 下游（游标提取 + 解析流水线）与 PostgreSQL / MySQL 路径完全同构。
///
/// **连接数与 PostgreSQL/MySQL 的差异（如实）**：`tiberius::Client` 是**单连接**句柄
/// （不是连接池），因此这里的 `max_connections` 口径对它不适用；`JdbcReceiver` 的单轮
/// 语义本来就是"一次查询"，这里再用 [`tokio::sync::Mutex`] 把并发访问串行化。
pub struct MsSqlSource {
    client: tokio::sync::Mutex<tiberius::Client<Compat<tokio::net::TcpStream>>>,
    label: String,
}

impl std::fmt::Debug for MsSqlSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MsSqlSource").field("label", &self.label).finish_non_exhaustive()
    }
}

impl MsSqlSource {
    /// 连接 MSSQL（`mssql://` / `sqlserver://` / `jdbc:sqlserver://`）。
    ///
    /// # Errors
    /// DSN 非法、TCP 连接超时（5s）、TLS/登录握手失败。
    pub async fn connect(dsn: &str) -> DomainResult<Self> {
        let config = mssql_config_from_dsn(dsn)?;
        let addr = config.get_addr();
        let tcp =
            tokio::time::timeout(std::time::Duration::from_secs(5), tokio::net::TcpStream::connect(addr.as_str()))
                .await
                .map_err(|_| DomainError::DependencyUnavailable {
                    dependency: "jdbc-mssql".to_string(),
                    cause: format!("连接 {addr} 超时（5s）"),
                })?
                .map_err(|e| DomainError::DependencyUnavailable {
                    dependency: "jdbc-mssql".to_string(),
                    cause: format!("连接 {addr} 失败: {e}"),
                })?;
        // Nagle 关闭：拉取型工作负载是一条连接上的请求/响应往返，攒包只会加延迟
        let _ = tcp.set_nodelay(true);
        let client = tiberius::Client::connect(config, tcp.compat_write()).await.map_err(|e| {
            DomainError::DependencyUnavailable {
                dependency: "jdbc-mssql".to_string(),
                cause: format!("MSSQL 登录/握手失败: {e}"),
            }
        })?;
        Ok(Self { client: tokio::sync::Mutex::new(client), label: redact_dsn(dsn) })
    }
}

/// MSSQL 错误包装（**不含 DSN 明文**：只带动作与驱动原文）。
fn mssql_err(action: &str, error: impl std::fmt::Display) -> DomainError {
    DomainError::DependencyUnavailable { dependency: "jdbc-mssql".to_string(), cause: format!("{action}: {error}") }
}

#[async_trait]
impl SqlSource for MsSqlSource {
    async fn fetch_rows(&self, sql: &str, cursor: Option<&str>) -> DomainResult<Vec<String>> {
        // 两条 `String` 都活到函数结束：`tiberius::Query<'a>` 的参数借用期因此可以统一
        let sql = sql.to_string();
        let cursor = cursor.map(str::to_string);
        let mut guard = self.client.lock().await;
        let mut query = tiberius::Query::new(sql.as_str());
        if let Some(cursor) = cursor.as_deref() {
            query.bind(cursor);
        }
        let stream = query.query(&mut guard).await.map_err(|e| mssql_err("执行拉取语句失败", e))?;
        let rows = stream.into_first_result().await.map_err(|e| mssql_err("读取结果集失败", e))?;
        Ok(rows.iter().map(mssql_row_to_json).collect())
    }

    fn describe(&self) -> String {
        self.label.clone()
    }

    fn dialect(&self) -> SqlDialect {
        SqlDialect::MsSql
    }
}

/// 把一行 MSSQL 结果按**列类型**解码为 JSON 文本。
///
/// 与 [`mysql_row_to_json`] 同一套"类型贪婪匹配"口径：依次尝试
/// `i64 → f64 → bool → NaiveDateTime → DateTime<Utc> → Uuid → String → Vec<u8>(hex)`，
/// 全部失败才落到 `"<undecodable:{type}>"`。**绝不 panic、绝不静默丢列**。
///
/// `Ok(None)`（该列的 NULL）与 `Err(...)`（类型不匹配）必须区分开：前者是 SQL NULL
/// （渲染为 JSON `null`），后者才继续尝试下一个类型——混为一谈会把 NULL 误判成解不出的列。
#[must_use]
pub fn mssql_row_to_json(row: &tiberius::Row) -> String {
    let mut map = serde_json::Map::new();
    for (index, column) in row.columns().iter().enumerate() {
        let value = match mssql_cell_to_json(row, index) {
            MssqlCell::Null => Value::Null,
            MssqlCell::Value(value) => value,
            MssqlCell::Mismatch => Value::from(format!("<undecodable:{:?}>", column.column_type())),
        };
        map.insert(column.name().to_string(), value);
    }
    Value::Object(map).to_string()
}

/// 一格的解码结果：SQL NULL / 已解出 / 类型全不匹配（三态必须分开，见 [`mssql_row_to_json`]）。
#[derive(Debug, Clone)]
enum MssqlCell {
    /// SQL NULL。
    Null,
    /// 已解出的 JSON 值。
    Value(Value),
    /// 所有候选类型都不匹配（渲染为 `<undecodable:...>`，不静默丢列）。
    Mismatch,
}

/// 单格解码（尝试顺序即"类型贪婪匹配"）。
fn mssql_cell_to_json(row: &tiberius::Row, index: usize) -> MssqlCell {
    macro_rules! attempt {
        ($ty:ty, $convert:expr) => {
            match row.try_get::<$ty, _>(index) {
                Ok(Some(value)) => return MssqlCell::Value($convert(value)),
                Ok(None) => return MssqlCell::Null,
                Err(_) => {}
            }
        };
    }
    attempt!(i64, Value::from);
    attempt!(i32, Value::from);
    attempt!(f64, Value::from);
    attempt!(bool, Value::from);
    // MSSQL 的 `datetime` / `datetime2` 无时区：统一按 ISO-8601 无偏移输出（不臆造时区）
    attempt!(chrono::NaiveDateTime, |value: chrono::NaiveDateTime| Value::from(
        value.format("%Y-%m-%dT%H:%M:%S%.f").to_string()
    ));
    attempt!(chrono::DateTime<chrono::Utc>, |value: chrono::DateTime<chrono::Utc>| Value::from(value.to_rfc3339()));
    attempt!(tiberius::Uuid, |value: tiberius::Uuid| Value::from(value.to_string()));
    // `tiberius` 的 `FromSql` 只有借用形态（`&str` / `&[u8]`；owned 形态走 `FromSqlOwned`，
    // 而 `Row::try_get` 要的是 `FromSql`）——这里立刻转成 owned 的 `Value`，不把借用带出去。
    attempt!(&str, Value::from);
    attempt!(&[u8], |value: &[u8]| Value::from(render_binary(value)));
    MssqlCell::Mismatch
}

/// 把 `mssql://user:pass@host:1433/db?encrypt=off` 规范化为 `tiberius::Config`。
///
/// 只映射 **tiberius 真正认识的 ADO 键**（未知键在 tiberius 侧会解析失败，
/// 那会把"连接串写错"变成含糊的驱动错误），因此未知查询参数在这里就**显式报错**。
/// 错误文本里的口令一律 `***` 占位（[`tiberius::Config::from_ado_string`] 的错误可能回显连接串）。
///
/// # Errors
/// DSN 非法、缺少主机，或含不受支持的查询参数。
pub fn mssql_config_from_dsn(dsn: &str) -> DomainResult<tiberius::Config> {
    let trimmed = dsn.trim();
    if trimmed.to_ascii_lowercase().starts_with("jdbc:sqlserver://") {
        return tiberius::Config::from_jdbc_string(trimmed)
            .map_err(|e| DomainError::Config(format!("MSSQL JDBC DSN 非法: {}", redact_secret(&e.to_string()))));
    }
    let url = url::Url::parse(trimmed)
        .map_err(|e| DomainError::Config(format!("MSSQL DSN 非法: {}", redact_secret(&e.to_string()))))?;
    let host = url
        .host_str()
        .ok_or_else(|| DomainError::Config("MSSQL DSN 缺少主机（形如 mssql://user:pass@host:1433/db）".to_string()))?;
    let port = url.port().unwrap_or(1433);
    // ADO 的 server 值形如 `tcp:host,1433`（**逗号**分隔端口，不是冒号）
    let mut ado = format!("server=tcp:{host},{port};");
    let user = percent_decode(url.username());
    if !user.is_empty() {
        ado.push_str(&format!("user={user};"));
    }
    let password = url.password().map(percent_decode);
    if let Some(password) = &password {
        ado.push_str(&format!("password={password};"));
    }
    let database = percent_decode(url.path().trim_start_matches('/'));
    if !database.is_empty() {
        ado.push_str(&format!("database={database};"));
    }
    // 自建/容器内的 SQL Server 用自签证书：默认信任（与 `AGF_INGEST_KAFKA_TLS_INSECURE_SKIP_VERIFY`
    // 同类的"内网自签"取舍），要严格校验就用 trust_server_certificate=false 显式关掉。
    ado.push_str("trustservercertificate=true;");
    for (key, value) in url.query_pairs() {
        match key.trim().to_ascii_lowercase().as_str() {
            // `tiberius` 的 ADO 解析只认 bool 词（true/false/yes/no），
            // 但 JDBC/其它驱动的习惯写法是 required/optional/mandatory，这里统一归一化。
            "encrypt" | "encryption" => {
                let normalized = match value.trim().to_ascii_lowercase().as_str() {
                    "required" | "mandatory" | "true" | "yes" | "on" => "true".to_string(),
                    "optional" | "off" | "false" | "no" | "disabled" => "false".to_string(),
                    _ => value.to_string(),
                };
                ado.push_str(&format!("encrypt={normalized};"));
            }
            "trustservercertificate" | "trust_server_certificate" | "trust_cert" => {
                ado.push_str(&format!("trustservercertificate={value};"));
            }
            "database" | "databasename" | "db" => ado.push_str(&format!("database={value};")),
            "applicationname" | "application_name" => ado.push_str(&format!("applicationname={value};")),
            "applicationintent" | "readonly" => ado.push_str(&format!("applicationintent={value};")),
            other => {
                return Err(DomainError::Config(format!(
                    "MSSQL DSN 查询参数 {other:?} 不受支持（支持 encrypt / trust_server_certificate / \
                     database / application_name / applicationintent）"
                )));
            }
        }
    }
    tiberius::Config::from_ado_string(&ado).map_err(|e| {
        // 口令绝不出现在错误文本里
        DomainError::Config(format!("MSSQL 连接串非法: {}", redact_with(&e.to_string(), password.as_deref())))
    })
}

/// 把错误文本里可能出现的口令替换为 `***`。
pub(crate) fn redact_with(text: &str, secret: Option<&str>) -> String {
    match secret.filter(|secret| !secret.is_empty()) {
        Some(secret) => text.replace(secret, "***"),
        None => text.to_string(),
    }
}

/// 尽力而为的口令脱敏（无已知口令时按 `password=...` 形态兜底）。
fn redact_secret(text: &str) -> String {
    let lowered = text.to_ascii_lowercase();
    match (lowered.find("password="), lowered.find(';')) {
        (Some(start), Some(end)) if end > start => {
            let mut out = text.to_string();
            out.replace_range(start + "password=".len()..end, "***");
            out
        }
        _ => text.to_string(),
    }
}

/// `%XX` 百分号解码（DSN 里带 `@` / `:` / `/` 的用户名与口令必须解码后才能交给驱动）。
pub(crate) fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let digits = std::str::from_utf8(&bytes[index + 1..index + 3]).ok();
            if let Some(byte) = digits.and_then(|digits| u8::from_str_radix(digits, 16).ok()) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}
