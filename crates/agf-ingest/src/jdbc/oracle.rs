//! Oracle 数据源：DSN → OCI 连接串、`oracle::Row` → JSON 适配、驱动不可用时的降级。
//!
//! ## 驱动与运行库（**铁律：不污染机器**）
//!
//! 用 `oracle` crate（rust-oracle / ODPI-C）。它把 ODPI-C 的 C 源码**随包编译**（构建期需要
//! C 编译器，**不需要** Oracle SDK 头文件），OCI 运行库在**运行期**动态加载。
//! 本项目把 Instant Client 放在**仓库内** `tools/oracle/instantclient_23_5/`，通过
//! [`ORACLE_CLIENT_LIB_DIR_ENV`]（`AGF_ORACLE_CLIENT_LIB_DIR`）交给
//! `oracle::InitParams::oracle_client_lib_dir` —— **不写全局 `PATH`、不往系统目录塞文件**
//! （见 `tools/oracle/README.md`）。未配置该变量时回落仓库相对路径
//! [`DEFAULT_ORACLE_CLIENT_LIB_DIR`]；两者都不可用时**不指定目录**，交给 ODPI-C 自己按
//! `PATH` / `ORACLE_HOME` 找（部署机装了完整 Oracle 客户端时就是这条路）。
//!
//! ## 阻塞驱动怎么进 async 接收器
//!
//! OCI 是 C 库，`oracle::Connection` **没有 async API**（阻塞句柄）。因此这里一律
//! `tokio::task::spawn_blocking` + `std::sync::Mutex`：流水线的 async 工作线程**不会被阻塞调用占住**，
//! 同一连接上的并发访问被串行化（`JdbcReceiver` 的单轮语义本就是"一次查询"）。
//! `AGF_INGEST_SQL_MAX_CONNECTIONS` 对单连接句柄不适用（与 [`MsSqlSource`] 同一取舍，如实标注）。
//!
//! ## 口令永不外泄
//!
//! [`OracleConnectParams`] 的 `Debug` 是手写的（口令恒为 `***`），错误文本里也只出现
//! [`redact_dsn`] 的脱敏 DSN 与驱动原文（驱动错误不会回显口令，但我们仍显式替换一次）。

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ::oracle::sql_type::OracleType;

use super::*;

/// 项目内 OCI 运行库目录的默认位置（相对**进程当前工作目录**，即仓库根）。
pub const DEFAULT_ORACLE_CLIENT_LIB_DIR: &str = "tools/oracle/instantclient_23_5";

/// 指定 OCI 运行库目录的环境变量（显式覆盖 [`DEFAULT_ORACLE_CLIENT_LIB_DIR`]）。
pub const ORACLE_CLIENT_LIB_DIR_ENV: &str = "AGF_ORACLE_CLIENT_LIB_DIR";

/// Oracle 连接参数：用户名、口令、OCI 连接串。
///
/// `Debug` **手写**：口令永远渲染成 `***` —— 口令不进日志、不进错误文本、不进 `Debug`。
#[derive(Clone)]
pub struct OracleConnectParams {
    user: String,
    password: String,
    connect_string: String,
}

impl OracleConnectParams {
    /// 构造（只给本模块与测试用；外部一律走 [`oracle_connect_params_from_dsn`]）。
    fn new(user: String, password: String, connect_string: String) -> Self {
        Self { user, password, connect_string }
    }

    /// 用户名（OCI 登录用）。
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// 口令（**只给驱动**；不日志、不 `Debug`、不进错误文本）。
    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }

    /// OCI 连接串：`//host:port/service`（EZ Connect）或 `(DESCRIPTION=…)`（TCPS / 完整描述符）。
    #[must_use]
    pub fn connect_string(&self) -> &str {
        &self.connect_string
    }
}

impl std::fmt::Debug for OracleConnectParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OracleConnectParams")
            .field("user", &self.user)
            .field("password", &"***")
            .field("connect_string", &self.connect_string)
            .finish()
    }
}

/// 把 `oracle://user:pass@host:port/service` 解析成驱动需要的三段（纯函数，可离线断言）。
///
/// 支持的形态：
/// * `oracle://agf:pw@127.0.0.1:1521/FREEPDB1` ⇒ EZ Connect `//127.0.0.1:1521/FREEPDB1`；
/// * `oracle+tcps://…` 或 `oracle://…?tcps=1` ⇒ TCPS 的 TNS 描述符；
/// * `oracle://user:pw@host:1521/svc?descriptor=(DESCRIPTION=…)` ⇒ 完整描述符原样透传
///   （钱包 / `tnsnames` / 自定义 `SECURITY` 段等高级形态）。
///
/// 用户名、口令、服务名都做 `%XX` 百分号解码（口令里的 `@` / `:` / `/` 必须能写进来）。
///
/// # Errors
/// scheme 不是 `oracle`/`oracle+tcps`、缺用户名/主机/服务名、端口或查询参数非法、
/// 或服务名含非法字符（组装 TNS 描述符时的注入面）。
pub fn oracle_connect_params_from_dsn(dsn: &str) -> DomainResult<OracleConnectParams> {
    let trimmed = dsn.trim();
    // `url::ParseError` 的 Display 不回显输入串（如 "invalid port number"），因此不含口令
    let url = url::Url::parse(trimmed).map_err(|e| {
        DomainError::Config(format!("Oracle DSN 非法: {e}（形如 oracle://user:pass@host:1521/service）"))
    })?;
    let scheme = url.scheme().to_ascii_lowercase();
    if scheme != "oracle" && scheme != "oracle+tcps" {
        return Err(DomainError::Config(format!(
            "Oracle DSN scheme {scheme:?} 不受支持：应为 oracle:// 或 oracle+tcps://"
        )));
    }
    let user = percent_decode(url.username());
    if user.is_empty() {
        return Err(DomainError::Config(
            "Oracle DSN 缺少用户名（形如 oracle://user:pass@host:1521/service）".to_string(),
        ));
    }
    let password = url.password().map(percent_decode).unwrap_or_default();
    let host = url.host_str().ok_or_else(|| {
        DomainError::Config("Oracle DSN 缺少主机（形如 oracle://user:pass@host:1521/service）".to_string())
    })?;
    let port = url.port().unwrap_or(1521);

    let mut tcps = scheme == "oracle+tcps";
    let mut descriptor: Option<String> = None;
    for (key, value) in url.query_pairs() {
        match key.trim().to_ascii_lowercase().as_str() {
            "tcps" | "ssl" | "tls" => {
                tcps = parse_bool_flag(&value).ok_or_else(|| {
                    DomainError::Config(format!(
                        "Oracle DSN 参数 {key:?}={value:?} 不是布尔值（1/0/true/false/on/off）"
                    ))
                })?;
            }
            "descriptor" | "connect_string" => descriptor = Some(value.to_string()),
            other => {
                return Err(DomainError::Config(format!(
                    "Oracle DSN 查询参数 {other:?} 不受支持（支持 tcps / descriptor）"
                )));
            }
        }
    }

    let service = percent_decode(url.path().trim_start_matches('/'));
    let connect_string = match descriptor {
        Some(descriptor) => descriptor,
        None => {
            if service.is_empty() {
                return Err(DomainError::Config(
                    "Oracle DSN 缺少服务名（形如 oracle://user:pass@host:1521/FREEPDB1）".to_string(),
                ));
            }
            // 服务名要拼进 TNS 描述符 ⇒ 只允许 Oracle 服务名合法字符（杜绝括号注入）
            let valid = service.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '$'));
            if !valid {
                return Err(DomainError::Validation(format!(
                    "Oracle 服务名 {service:?} 含非法字符（只允许字母/数字/下划线/减号/点/美元符）"
                )));
            }
            if tcps {
                format!(
                    "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST={host})(PORT={port}))\
                     (CONNECT_DATA=(SERVICE_NAME={service})))"
                )
            } else {
                format!("//{host}:{port}/{service}")
            }
        }
    };
    Ok(OracleConnectParams::new(user, password, connect_string))
}

/// 布尔开关解析（`1`/`0`/`true`/`false`/`on`/`off`/`yes`/`no`）。
fn parse_bool_flag(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" => Some(true),
        "0" | "false" | "off" | "no" => Some(false),
        _ => None,
    }
}

/// OCI 运行库目录：显式给定的（[`ORACLE_CLIENT_LIB_DIR_ENV`]）优先，否则回落仓库内
/// [`DEFAULT_ORACLE_CLIENT_LIB_DIR`]（不存在 ⇒ `None`，交给 ODPI-C 自己按 `PATH`/`ORACLE_HOME` 找）。
#[must_use]
pub fn oracle_client_lib_dir(explicit: Option<&str>) -> Option<PathBuf> {
    if let Some(dir) = explicit.map(str::trim).filter(|dir| !dir.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    let candidate = PathBuf::from(DEFAULT_ORACLE_CLIENT_LIB_DIR);
    candidate.is_dir().then_some(candidate)
}

/// 驱动不可用 / 连接失败（**只 warn 不致命**：调用方照常启动进程并写 `/readyz` notes）。
fn oracle_unavailable(cause: impl Into<String>) -> DomainError {
    DomainError::DependencyUnavailable { dependency: "jdbc-oracle".to_string(), cause: cause.into() }
}

/// 显式把 OCI 运行库目录交给 ODPI-C（**唯一**的库加载口，进程级只生效一次）。
///
/// 不指定目录时直接返回：ODPI-C 按 `PATH` / `ORACLE_HOME` 自己找。
fn init_oracle_client(lib_dir: Option<&Path>) -> DomainResult<()> {
    let Some(dir) = lib_dir else {
        return Ok(());
    };
    let mut params = ::oracle::InitParams::new();
    params
        .oracle_client_lib_dir(dir)
        .and_then(|params| params.init().map(|_initialized_now| ()))
        .map_err(|e| oracle_unavailable(format!("OCI 运行库加载失败（{}）: {e}", dir.display())))
}

/// `oracle` crate（ODPI-C / OCI）的 Oracle 实现。
///
/// 游标/分页/落盘/幂等**不在本文件**：那些只有一份实现（[`JdbcReceiver`]），
/// 这里只贡献方言差异（SQL 拼装见 [`SqlDialect::Oracle`]，行解码见 [`oracle_row_to_json`]）。
pub struct OracleSource {
    conn: Arc<Mutex<::oracle::Connection>>,
    label: String,
}

impl std::fmt::Debug for OracleSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OracleSource").field("label", &self.label).finish_non_exhaustive()
    }
}

impl OracleSource {
    /// 连接 Oracle（OCI 运行库目录见 [`oracle_client_lib_dir`]）。
    ///
    /// # Errors
    /// DSN 非法（配置错误）、OCI 运行库加载失败、认证失败或服务不可达（依赖不可用）。
    pub async fn connect(dsn: &str) -> DomainResult<Self> {
        let params = oracle_connect_params_from_dsn(dsn)?;
        let label = redact_dsn(dsn);
        let lib_dir = oracle_client_lib_dir(std::env::var(ORACLE_CLIENT_LIB_DIR_ENV).ok().as_deref());
        // 阻塞连接丢进阻塞线程池：数据库不可达时绝不占住 async 工作线程（更不阻塞进程启动）
        let conn = tokio::task::spawn_blocking(move || connect_blocking(&params, lib_dir.as_deref()))
            .await
            .map_err(|e| oracle_unavailable(format!("Oracle 连接任务异常结束: {e}")))??;
        Ok(Self { conn: Arc::new(Mutex::new(conn)), label })
    }
}

/// 同步连接（在 `spawn_blocking` 里跑）：库加载 → 登录 → 明文口令脱敏的错误包装。
fn connect_blocking(params: &OracleConnectParams, lib_dir: Option<&Path>) -> DomainResult<::oracle::Connection> {
    init_oracle_client(lib_dir)?;
    ::oracle::Connection::connect(params.user(), params.password(), params.connect_string()).map_err(|e| {
        // 口令绝不出现在错误文本里（驱动错误不回显口令，这里仍显式替换一次兜底）
        oracle_unavailable(format!("连接 Oracle 失败: {}", redact_with(&e.to_string(), Some(params.password()))))
    })
}

#[async_trait]
impl SqlSource for OracleSource {
    async fn fetch_rows(&self, sql: &str, cursor: Option<&str>) -> DomainResult<Vec<String>> {
        let conn = Arc::clone(&self.conn);
        let sql = sql.to_string();
        let cursor = cursor.map(str::to_string);
        // 阻塞驱动（OCI）一律走阻塞线程池；连接上的并发访问由 Mutex 串行化
        tokio::task::spawn_blocking(move || fetch_rows_blocking(&conn, &sql, cursor.as_deref()))
            .await
            .map_err(|e| oracle_unavailable(format!("Oracle 拉取任务异常结束: {e}")))?
    }

    fn describe(&self) -> String {
        self.label.clone()
    }

    fn dialect(&self) -> SqlDialect {
        SqlDialect::Oracle
    }
}

/// 同步取数（在 `spawn_blocking` 里跑）：一行一个 JSON 文本，列名与顺序保真。
fn fetch_rows_blocking(
    conn: &Mutex<::oracle::Connection>,
    sql: &str,
    cursor: Option<&str>,
) -> DomainResult<Vec<String>> {
    let guard = match conn.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let result = match cursor {
        // 占位符 `:1` 由方言给出：无游标时**不绑定**（调用方保证此时 SQL 里没有占位符）
        Some(cursor) => guard.query(sql, &[&cursor]),
        None => guard.query(sql, &[]),
    };
    let rows = result.map_err(|e| oracle_unavailable(format!("执行拉取语句失败: {e}")))?;
    let mut out = Vec::new();
    for row in rows {
        let row = row.map_err(|e| oracle_unavailable(format!("读取结果集失败: {e}")))?;
        out.push(oracle_row_to_json(&row));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// `oracle::Row` → 纯解码层（[`OracleCellReader`]）的适配
// ---------------------------------------------------------------------------

/// `oracle::Row::get` 的三态归一：`Ok(Some)` 取到值 / `Ok(None)` 是 SQL NULL / `Err` 类型不匹配。
fn attempt<T>(result: ::oracle::Result<Option<T>>) -> CellAttempt<T> {
    match result {
        Ok(Some(value)) => CellAttempt::Value(value),
        Ok(None) => CellAttempt::Null,
        Err(_) => CellAttempt::Mismatch,
    }
}

impl OracleCellReader for ::oracle::Row {
    fn len(&self) -> usize {
        self.column_info().len()
    }

    fn name(&self, index: usize) -> String {
        self.column_info().get(index).map(|info| info.name().to_string()).unwrap_or_default()
    }

    fn type_name(&self, index: usize) -> String {
        self.column_info().get(index).map(|info| format!("{:?}", info.oracle_type())).unwrap_or_default()
    }

    fn kind(&self, index: usize) -> OracleColumnKind {
        self.column_info().get(index).map_or(OracleColumnKind::Other, |info| classify_oracle_type(info.oracle_type()))
    }

    fn is_null(&self, index: usize) -> bool {
        // `SqlValue::is_null()` 是**唯一**能把 SQL NULL 与"类型不匹配"分开的判据
        self.sql_values().get(index).and_then(|value| value.is_null().ok()).unwrap_or(true)
    }

    fn try_i64(&self, index: usize) -> CellAttempt<i64> {
        attempt(self.get(index))
    }

    fn try_u64(&self, index: usize) -> CellAttempt<u64> {
        attempt(self.get(index))
    }

    fn try_f64(&self, index: usize) -> CellAttempt<f64> {
        attempt(self.get(index))
    }

    fn try_bool(&self, index: usize) -> CellAttempt<bool> {
        attempt(self.get(index))
    }

    fn try_datetime_utc(&self, index: usize) -> CellAttempt<chrono::DateTime<chrono::Utc>> {
        // `DATE` / `TIMESTAMP`（无时区）按 UTC 解释；`TIMESTAMP WITH [LOCAL] TIME ZONE` 由驱动转 UTC
        attempt(self.get(index))
    }

    fn try_text(&self, index: usize) -> CellAttempt<String> {
        attempt(self.get(index))
    }

    fn try_bytes(&self, index: usize) -> CellAttempt<Vec<u8>> {
        attempt(self.get(index))
    }
}

/// Oracle 列类型 → 解码分类（决定"类型贪婪匹配"的尝试顺序）。
fn classify_oracle_type(oracle_type: &OracleType) -> OracleColumnKind {
    match oracle_type {
        // `NUMBER(precision, scale)`：精度 < 18 且无小数位时驱动按 int64 取（不必担心精度）
        OracleType::Number(precision, scale) => {
            OracleColumnKind::Number { integral: *scale == 0, narrow: *precision > 0 && *precision < 18 }
        }
        // `FLOAT` 是 NUMBER 的子类型（十进制存储）⇒ 走数值分支
        OracleType::Float(_) => OracleColumnKind::Number { integral: false, narrow: false },
        OracleType::BinaryFloat | OracleType::BinaryDouble => OracleColumnKind::Float,
        OracleType::Varchar2(_)
        | OracleType::NVarchar2(_)
        | OracleType::Char(_)
        | OracleType::NChar(_)
        | OracleType::Long
        | OracleType::CLOB
        | OracleType::NCLOB
        | OracleType::Rowid
        | OracleType::Json
        | OracleType::Xml => OracleColumnKind::Text,
        OracleType::Date | OracleType::Timestamp(_) | OracleType::TimestampTZ(_) | OracleType::TimestampLTZ(_) => {
            OracleColumnKind::Timestamp
        }
        OracleType::Raw(_) | OracleType::LongRaw | OracleType::BLOB | OracleType::BFILE => OracleColumnKind::Binary,
        OracleType::Boolean => OracleColumnKind::Boolean,
        // 对象/集合/间隔/REF CURSOR/未知（含 `Int64`/`UInt64` 这类内部类型）：按字符串兜底
        _ => OracleColumnKind::Other,
    }
}
