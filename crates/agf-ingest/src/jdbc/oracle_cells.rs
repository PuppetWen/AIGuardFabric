//! Oracle 行 → JSON 的**纯逻辑**：列分类、类型贪婪匹配（三态）、时间归一渲染。
//!
//! 本模块**不碰数据库**：驱动侧（[`super::oracle`]）把 `oracle::Row` 适配成
//! [`OracleCellReader`]，测试注入假实现 ⇒ 解码规则可离线断言。口径与 MySQL / MSSQL 完全一致：
//! **绝不 panic、绝不静默丢列**；解不出的列带着类型名出现在 JSON 里（`<undecodable:类型>`）。

use chrono::{DateTime, Utc};

use super::*;

/// 一格的取值结果**三态**：SQL NULL / 已解出 / 类型全不匹配。
///
/// NULL 与"类型不匹配"必须分开：混为一谈会把 SQL NULL 误判成解不出的列，
/// 或把解不出的列误渲染成 `null`（丢失"这里有个没处理的类型"这个事实）。
#[derive(Debug, Clone, PartialEq)]
pub enum CellAttempt<T> {
    /// 已解出的值。
    Value(T),
    /// SQL NULL（渲染为 JSON `null`）。
    Null,
    /// 所有候选类型都不匹配（渲染为 `<undecodable:类型>`，**不静默丢列**）。
    Mismatch,
}

impl<T> CellAttempt<T> {
    /// 变换已解出的值（`Null` / `Mismatch` 原样透传，保持三态不被压平）。
    #[must_use]
    pub fn map_value<U>(self, convert: impl FnOnce(T) -> U) -> CellAttempt<U> {
        match self {
            Self::Value(value) => CellAttempt::Value(convert(value)),
            Self::Null => CellAttempt::Null,
            Self::Mismatch => CellAttempt::Mismatch,
        }
    }
}

/// 列的分类（由结果集元数据类型给出）：决定"类型贪婪匹配"的尝试顺序。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OracleColumnKind {
    /// `NUMBER` / `FLOAT`：`integral` = 小数位为 0；`narrow` = 精度 < 18（驱动按 int64 取）。
    Number {
        /// 小数位为 0（`NUMBER(p, 0)` / `FLOAT` 的整数形态）。
        integral: bool,
        /// 精度足够窄（`0 < p < 18`）：驱动已按 int64 取值，不必担心精度。
        narrow: bool,
    },
    /// `BINARY_FLOAT` / `BINARY_DOUBLE`（IEEE 浮点）。
    Float,
    /// `VARCHAR2` / `NVARCHAR2` / `CHAR` / `NCHAR` / `LONG` / `CLOB` / `NCLOB` / `ROWID`。
    Text,
    /// `DATE` / `TIMESTAMP` / `TIMESTAMP WITH [LOCAL] TIME ZONE`。
    Timestamp,
    /// `RAW` / `LONG RAW` / `BLOB` / `BFILE`。
    Binary,
    /// `BOOLEAN`（PL/SQL 侧）。
    Boolean,
    /// 其它（对象/集合/间隔/REF CURSOR/未知类型）：按字符串兜底。
    Other,
}

/// 一行结果的取值抽象（真实实现是 [`super::oracle`] 里的 `impl OracleCellReader for oracle::Row`）。
///
/// 每个 `try_*` 都必须返回三态：`Ok` 取到了值、值本身是 NULL、还是**类型不匹配**。
pub trait OracleCellReader {
    /// 列数。
    fn len(&self) -> usize;

    /// 列是否为空（`len() == 0`）；`clippy::len_without_is_empty` 要求成对出现。
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 列名（Oracle 未加引号的标识符折叠为大写 ⇒ 这里通常是 `ID` 这样的形态）。
    fn name(&self, index: usize) -> String;

    /// 列类型名（诊断与 `<undecodable:类型>` 用）。
    fn type_name(&self, index: usize) -> String;

    /// 列分类。
    fn kind(&self, index: usize) -> OracleColumnKind;

    /// 该格是否为 SQL NULL。
    fn is_null(&self, index: usize) -> bool;

    /// 按 `i64` 取值。
    fn try_i64(&self, index: usize) -> CellAttempt<i64>;

    /// 按 `u64` 取值（`NUMBER` 可超过 `i64::MAX`）。
    fn try_u64(&self, index: usize) -> CellAttempt<u64>;

    /// 按 `f64` 取值。
    fn try_f64(&self, index: usize) -> CellAttempt<f64>;

    /// 按布尔取值。
    fn try_bool(&self, index: usize) -> CellAttempt<bool>;

    /// 按时间取值（`DATE` / `TIMESTAMP` / `TIMESTAMP WITH [LOCAL] TIME ZONE`）。
    fn try_datetime_utc(&self, index: usize) -> CellAttempt<DateTime<Utc>>;

    /// 按文本取值（含 `CLOB` / `ROWID`）。
    fn try_text(&self, index: usize) -> CellAttempt<String>;

    /// 按字节取值（`RAW` / `BLOB`）。
    fn try_bytes(&self, index: usize) -> CellAttempt<Vec<u8>>;
}

/// 把一行结果按**列元数据类型**解码为 JSON 文本（列名与顺序保真；**绝不 panic、绝不静默丢列**）。
///
/// 与 PostgreSQL 的 `row_to_json` 是同一份下游口径：JSON 的每个字段都保真进入解析流水线，
/// 游标提取（[`cursor_from_row`]）也仍然只认 JSON。
pub fn oracle_row_to_json<R: OracleCellReader + ?Sized>(row: &R) -> String {
    let mut map = serde_json::Map::new();
    for index in 0..row.len() {
        let value = decode_cell(row, index);
        map.insert(row.name(index), value);
    }
    Value::Object(map).to_string()
}

/// 命中即返回（`Null` 也立即返回 ⇒ 三态不被后续候选覆盖）。
macro_rules! take {
    ($attempt:expr) => {
        match $attempt {
            CellAttempt::Value(value) => return value,
            CellAttempt::Null => return Value::Null,
            CellAttempt::Mismatch => {}
        }
    };
}

/// 单格解码：先看 NULL，再按列分类做"类型贪婪匹配"。
fn decode_cell<R: OracleCellReader + ?Sized>(row: &R, index: usize) -> Value {
    if row.is_null(index) {
        return Value::Null;
    }
    match row.kind(index) {
        // NUMBER：整型优先（`to_i64` 对 `NATIVE_TYPE_NUMBER` 是按十进制文本 parse ⇒ 整数精确、
        // 小数自然落空）；**宽整数**（精度 ≥ 18，可能是 38 位）整型失败后优先进文本 ——
        // 转 f64 会在 2^53 以上静默丢精度，只有小数/浮点才走 f64。
        OracleColumnKind::Number { integral, narrow } => {
            take!(row.try_i64(index).map_value(Value::from));
            if integral && narrow {
                take!(row.try_f64(index).map_value(Value::from));
            } else if integral {
                take!(row.try_u64(index).map_value(Value::from));
                take!(row.try_text(index).map_value(Value::from));
                take!(row.try_f64(index).map_value(Value::from));
            } else {
                take!(row.try_u64(index).map_value(Value::from));
                take!(row.try_f64(index).map_value(Value::from));
                take!(row.try_text(index).map_value(Value::from));
            }
        }
        OracleColumnKind::Float => {
            take!(row.try_f64(index).map_value(Value::from));
            take!(row.try_text(index).map_value(Value::from));
        }
        // 文本列**文本优先**：`VARCHAR2` 里的 `"42"` 必须保持字符串，
        // 不能被"贪婪数字匹配"改成 `42`（与 MySQL / MSSQL 按列类型解码同一口径）。
        OracleColumnKind::Text => {
            take!(row.try_text(index).map_value(Value::from));
            take!(row.try_i64(index).map_value(Value::from));
            take!(row.try_f64(index).map_value(Value::from));
            take!(row.try_bytes(index).map_value(|bytes| Value::from(render_binary(&bytes))));
        }
        OracleColumnKind::Timestamp => {
            take!(row.try_datetime_utc(index).map_value(render_timestamp));
            take!(row.try_text(index).map_value(Value::from));
        }
        OracleColumnKind::Binary => {
            take!(row.try_bytes(index).map_value(|bytes| Value::from(render_binary(&bytes))));
            take!(row.try_text(index).map_value(Value::from));
        }
        OracleColumnKind::Boolean => {
            take!(row.try_bool(index).map_value(Value::from));
            take!(row.try_text(index).map_value(Value::from));
        }
        OracleColumnKind::Other => {
            take!(row.try_text(index).map_value(Value::from));
            take!(row.try_datetime_utc(index).map_value(render_timestamp));
            take!(row.try_f64(index).map_value(Value::from));
            take!(row.try_bytes(index).map_value(|bytes| Value::from(render_binary(&bytes))));
        }
    }
    Value::from(format!("<undecodable:{}>", row.type_name(index)))
}

/// 时间列渲染：ISO-8601、毫秒精度、字面量 `Z`（UTC 语义）。
///
/// 与 SQL 侧的 [`ORACLE_TIMESTAMP_FORMAT`]（`TO_CHAR` 格式）**逐字节一致** ⇒
/// 游标（本格式的文本）与列（同一格式的文本）可直接按字符串比较。
/// Oracle 的 `DATE` / `TIMESTAMP` 不带时区，按平台口径视为 UTC；带时区的列由驱动转 UTC 后落到同一格式。
fn render_timestamp(value: DateTime<Utc>) -> Value {
    Value::from(value.format(ORACLE_TIMESTAMP_RENDER).to_string())
}
