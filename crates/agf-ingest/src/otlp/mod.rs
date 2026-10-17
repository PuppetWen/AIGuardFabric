//! OTLP/HTTP 三信号（logs / traces / metrics）共享底座：protobuf wire-format 读取器、
//! `AnyValue`/`KeyValue`/Resource/Scope 解码、OTLP/JSON 键查找、gzip 解压与编码归一。
//!
//! 三个信号**同源**（同一套底层解码、同一流水线、同一上限保护），只有信号级消息树不同：
//!
//! | 子模块 | 信号 | HTTP 路径 | 归一化 |
//! |---|---|---|---|
//! | [`logs`] | `ExportLogsServiceRequest` | `POST /v1/logs` | LogRecord → Event（既有行为） |
//! | [`traces`] | `ExportTraceServiceRequest` | `POST /v1/traces` | Span → 归一化载荷（`event.category='trace'`） |
//! | [`metrics_signal`] | `ExportMetricsServiceRequest` | `POST /v1/metrics` | data point → 归一化载荷（`event.category='metric'`） |
//!
//! ## 装配（"写了"必须真的"挂上"）
//!
//! 三信号的路由由 [`signal_router`] **一次性**拼装，装配点（`apps/ingest`）只允许通过
//! 它挂载——这样"路由构造函数存在"与"路由真的挂在服务上"是同一件事。
//! 装配完成后必须调用 [`crate::receiver::declare_wired`] 登记 `otlp-traces` /
//! `otlp-metrics`；未登记时能力矩阵按 [`crate::receiver::ReceiverStatus::NotWired`] 报，
//! 不会出现"`ready` 但 `/v1/traces` 返回 404"。
//!
//! ## gRPC（如实）
//!
//! [`crate::otlp_grpc`] 只实现官方 `LogsService/Export`；**gRPC 侧
//! `TraceService/Export` 与 `MetricsService/Export` 未实现**（调用会得到 `Unimplemented`）。
//! traces/metrics 目前只有 OTLP/HTTP 通道。

pub(crate) mod http_response;
pub mod logs;
pub mod metrics_receiver;
pub mod metrics_signal;
pub mod traces;
pub mod traces_receiver;

pub use logs::{
    OtlpIngestReport, OtlpLogRecord, OtlpLogsReceiver, otlp_router, parse_json, parse_logs, parse_protobuf,
};
pub use metrics_receiver::{OtlpMetricsReceiver, OtlpMetricsReport, metrics_router};
pub use metrics_signal::{OtlpMetricRecord, parse_metrics, parse_metrics_json, parse_metrics_protobuf};
pub use traces::{OtlpSpanRecord, parse_traces, parse_traces_json, parse_traces_protobuf, span_payload};
pub use traces_receiver::{OtlpTracesReceiver, OtlpTracesReport, traces_router};

use std::collections::BTreeMap;
use std::io::Read as _;
use std::sync::Arc;

use agf_core::error::{DomainError, DomainResult};
use axum::Router;
use axum::http::HeaderMap;
use serde_json::{Map, Value};

// 注意：三个接收器类型已在上面的 `pub use` 中引入到本模块作用域，
// 这里**不要**再 `use logs::OtlpLogsReceiver;` 之类重复导入（E0252）。

// ---------------------------------------------------------------------------
// 三信号路由的**唯一装配点**
// ---------------------------------------------------------------------------

/// 一次性拼装 OTLP/HTTP 三信号路由（`/v1/logs` + `/v1/traces` + `/v1/metrics`）。
///
/// **为什么集中在一处**：此前 `traces_router` / `metrics_router` 全仓零调用方，能力矩阵却
/// 报 `ready`——"写了但没挂"完全不可观测。现在装配点只允许调用本函数，
/// 缺哪个信号一眼可见（传 `None` 就是不挂，能力矩阵随之显示 `not-wired`）。
///
/// 返回 `(router, 已挂载的模块名清单)`；调用方须把清单交给
/// [`crate::receiver::declare_wired`] 登记（`apps/ingest` 已如此）。
#[must_use = "路由构造后必须挂到服务上，直接丢弃等于没有接入点"]
pub fn signal_router(
    logs: Option<Arc<OtlpLogsReceiver>>,
    traces: Option<Arc<OtlpTracesReceiver>>,
    metrics: Option<Arc<OtlpMetricsReceiver>>,
) -> (Router, Vec<&'static str>) {
    let mut mounted = Vec::new();
    let mut app = Router::new();
    if let Some(logs) = logs {
        app = app.merge(logs::otlp_router(logs));
        mounted.push("otlp");
    }
    if let Some(traces) = traces {
        app = app.merge(traces_receiver::traces_router(traces));
        mounted.push("otlp-traces");
    }
    if let Some(metrics) = metrics {
        app = app.merge(metrics_receiver::metrics_router(metrics));
        mounted.push("otlp-metrics");
    }
    (app, mounted)
}

// ---------------------------------------------------------------------------
// 共享小工具（JSON 键查找 / 字符串映射 / gzip / 编码归一）
// ---------------------------------------------------------------------------

/// `BTreeMap<String,String>` → `serde_json::Map`。
fn string_map(input: &BTreeMap<String, String>) -> Map<String, Value> {
    input.iter().map(|(k, v)| (k.clone(), Value::from(v.clone()))).collect()
}

/// 容忍 `camelCase` 与 `snake_case` 的键查找。
fn get<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    let object = value.as_object()?;
    keys.iter().find_map(|key| object.get(*key)).filter(|v| !v.is_null())
}

/// 解析 `repeated KeyValue`。
fn parse_key_values(value: Option<&Value>, out: &mut BTreeMap<String, String>) {
    let Some(items) = value.and_then(Value::as_array) else { return };
    for item in items {
        let Some(key) = get(item, &["key"]).and_then(Value::as_str) else { continue };
        let rendered = get(item, &["value"]).map_or_else(String::new, logs::any_value_to_string);
        out.insert(key.to_string(), rendered);
    }
}

/// gzip 解压（`Content-Encoding: gzip`；上限用于防止解压炸弹）。
///
/// # Errors
/// 解压失败或超过上限。
pub fn gunzip(body: &[u8], max_bytes: usize) -> DomainResult<Vec<u8>> {
    let decoder = flate2::read::GzDecoder::new(body);
    let mut out = Vec::new();
    let mut limited = decoder.take(u64::try_from(max_bytes).unwrap_or(u64::MAX).saturating_add(1));
    limited.read_to_end(&mut out).map_err(|e| DomainError::Parse(format!("gzip 解压失败: {e}")))?;
    if out.len() > max_bytes {
        return Err(DomainError::Validation(format!("gzip 解压后超过上限 {max_bytes} 字节")));
    }
    Ok(out)
}

/// 是否声明了 gzip 编码。
#[must_use]
pub fn is_gzip(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().contains("gzip"))
}

/// 按 `Content-Type` 归一为受支持的媒体类型（`application/json` / `application/x-protobuf`）。
/// 缺省按 JSON（规范里 JSON 是最低要求）；带参数（`charset=utf-8` 等）按前缀归一。
///
/// # Errors
/// 编码不受支持（属调用方错误，OTLP 规范要求 415/4xx）。
fn supported_media(content_type: Option<&str>) -> DomainResult<&'static str> {
    let normalized = content_type.unwrap_or("application/json").to_ascii_lowercase();
    let media = normalized.split(';').next().unwrap_or("").trim();
    match media {
        "" | "application/json" | "application/json+otlp" | "text/json" => Ok("application/json"),
        "application/x-protobuf" | "application/protobuf" | "application/x-google-protobuf" => {
            Ok("application/x-protobuf")
        }
        other => Err(DomainError::Validation(format!(
            "OTLP 编码 {other} 不受支持（支持 application/json 与 application/x-protobuf）"
        ))),
    }
}

// ---------------------------------------------------------------------------
// OTLP/Protobuf（手写 wire-format 解码，logs/traces/metrics 同源）
// ---------------------------------------------------------------------------

/// 极简 protobuf wire-format 读取器（只实现 OTLP 用到的类型）。
pub mod proto {
    use agf_core::error::{DomainError, DomainResult};

    /// wire type：varint。
    pub const WIRE_VARINT: u8 = 0;
    /// wire type：64 位定长。
    pub const WIRE_I64: u8 = 1;
    /// wire type：长度前缀。
    pub const WIRE_LEN: u8 = 2;
    /// wire type：32 位定长。
    pub const WIRE_I32: u8 = 5;

    /// 游标式读取器。
    #[derive(Debug, Clone)]
    pub struct Reader<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl<'a> Reader<'a> {
        /// 构造。
        #[must_use]
        pub const fn new(buf: &'a [u8]) -> Self {
            Self { buf, pos: 0 }
        }

        /// 是否已读完。
        #[must_use]
        pub const fn eof(&self) -> bool {
            self.pos >= self.buf.len()
        }

        /// 剩余字节。
        #[must_use]
        pub const fn remaining(&self) -> usize {
            self.buf.len().saturating_sub(self.pos)
        }

        /// 读一个 varint。
        ///
        /// # Errors
        /// 越界或超过 10 字节（protobuf varint 上限）。
        pub fn varint(&mut self) -> DomainResult<u64> {
            let mut result = 0_u64;
            let mut shift = 0_u32;
            loop {
                let Some(byte) = self.buf.get(self.pos).copied() else {
                    return Err(DomainError::Parse("protobuf varint 越界".to_string()));
                };
                self.pos += 1;
                result |= u64::from(byte & 0x7f) << shift;
                if byte & 0x80 == 0 {
                    return Ok(result);
                }
                shift += 7;
                if shift >= 64 {
                    return Err(DomainError::Parse("protobuf varint 超过 10 字节".to_string()));
                }
            }
        }

        /// 读 tag：返回 `(字段号, wire type)`；已读完返回 `None`。
        ///
        /// # Errors
        /// 字段号为 0 或 varint 非法。
        pub fn tag(&mut self) -> DomainResult<Option<(u32, u8)>> {
            if self.eof() {
                return Ok(None);
            }
            let key = self.varint()?;
            let field = u32::try_from(key >> 3).unwrap_or(0);
            let wire = u8::try_from(key & 0x07).unwrap_or(255);
            if field == 0 {
                return Err(DomainError::Parse("protobuf 字段号为 0（非法 tag）".to_string()));
            }
            Ok(Some((field, wire)))
        }

        /// 读长度前缀字节串。
        ///
        /// # Errors
        /// 越界。
        pub fn bytes(&mut self) -> DomainResult<&'a [u8]> {
            let len = usize::try_from(self.varint()?).unwrap_or(usize::MAX);
            let end = self.pos.saturating_add(len);
            if end > self.buf.len() {
                return Err(DomainError::Parse(format!("protobuf 长度前缀 {len} 越界（剩余 {}）", self.remaining())));
            }
            let slice = self.buf.get(self.pos..end).unwrap_or_default();
            self.pos = end;
            Ok(slice)
        }

        /// 读 UTF-8 长度前缀字符串（非法 UTF-8 用 lossy 兜底，不丢整条记录）。
        ///
        /// # Errors
        /// 越界。
        pub fn string(&mut self) -> DomainResult<String> {
            Ok(String::from_utf8_lossy(self.bytes()?).to_string())
        }

        /// 读 64 位定长（小端）。
        ///
        /// # Errors
        /// 越界。
        pub fn fixed64(&mut self) -> DomainResult<u64> {
            let end = self.pos.saturating_add(8);
            if end > self.buf.len() {
                return Err(DomainError::Parse("protobuf fixed64 越界".to_string()));
            }
            let mut raw = [0_u8; 8];
            raw.copy_from_slice(self.buf.get(self.pos..end).unwrap_or_default());
            self.pos = end;
            Ok(u64::from_le_bytes(raw))
        }

        /// 读 32 位定长（小端）。
        ///
        /// # Errors
        /// 越界。
        pub fn fixed32(&mut self) -> DomainResult<u32> {
            let end = self.pos.saturating_add(4);
            if end > self.buf.len() {
                return Err(DomainError::Parse("protobuf fixed32 越界".to_string()));
            }
            let mut raw = [0_u8; 4];
            raw.copy_from_slice(self.buf.get(self.pos..end).unwrap_or_default());
            self.pos = end;
            Ok(u32::from_le_bytes(raw))
        }

        /// 跳过未知字段（protobuf 前向兼容要求）。
        ///
        /// # Errors
        /// wire type 不支持或越界。
        pub fn skip(&mut self, wire: u8) -> DomainResult<()> {
            match wire {
                WIRE_VARINT => {
                    let _ = self.varint()?;
                }
                WIRE_I64 => {
                    let _ = self.fixed64()?;
                }
                WIRE_LEN => {
                    let _ = self.bytes()?;
                }
                WIRE_I32 => {
                    let _ = self.fixed32()?;
                }
                other => {
                    return Err(DomainError::Parse(format!("protobuf 未知 wire type {other}")));
                }
            }
            Ok(())
        }
    }

    /// 读 `fixed64` 时间戳字段（同时兼容 varint 编码的等价写法）。
    ///
    /// # Errors
    /// 越界。
    pub fn read_time(reader: &mut Reader<'_>, wire: u8) -> DomainResult<u64> {
        match wire {
            WIRE_I64 => reader.fixed64(),
            WIRE_VARINT => reader.varint(),
            other => Err(DomainError::Parse(format!("OTLP 时间戳字段 wire type 非预期: {other}"))),
        }
    }

    /// 8 字节 `trace_id` / 8 字节 `span_id` → hex。
    #[must_use]
    pub fn to_hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    /// hex 是否全零（OTLP 用全零表示"无"）。
    #[must_use]
    pub fn is_zero_hex(text: &str) -> bool {
        text.is_empty() || text.chars().all(|c| c == '0')
    }
}

/// 解析 `AnyValue`（protobuf）。
///
/// # Errors
/// wire-format 非法。
pub fn decode_any_value(buf: &[u8]) -> DomainResult<String> {
    let mut reader = proto::Reader::new(buf);
    let mut rendered = String::new();
    while let Some((field, wire)) = reader.tag()? {
        match (field, wire) {
            (1, proto::WIRE_LEN) => rendered = reader.string()?,
            (2, proto::WIRE_VARINT) => rendered = (reader.varint()? != 0).to_string(),
            (3, proto::WIRE_VARINT) => {
                // int_value 是 int64（二补码 varint）
                let raw = reader.varint()?;
                rendered = i64::from_ne_bytes(raw.to_ne_bytes()).to_string();
            }
            (4, proto::WIRE_I64) => rendered = format!("{}", f64::from_bits(reader.fixed64()?)),
            (5, proto::WIRE_LEN) => {
                let inner = reader.bytes()?;
                let items = decode_array_value(inner)?;
                rendered = Value::from(items).to_string();
            }
            (6, proto::WIRE_LEN) => {
                let inner = reader.bytes()?;
                let pairs = decode_key_value_list(inner)?;
                let map: Map<String, Value> = pairs.into_iter().map(|(k, v)| (k, Value::from(v))).collect();
                rendered = Value::Object(map).to_string();
            }
            (7, proto::WIRE_LEN) => rendered = format!("base64:{}", base64_encode(reader.bytes()?)),
            (_, other) => reader.skip(other)?,
        }
    }
    Ok(rendered)
}

/// base64 编码（bytes value 用）。
fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// `ArrayValue`。
///
/// # Errors
/// wire-format 非法。
pub fn decode_array_value(buf: &[u8]) -> DomainResult<Vec<String>> {
    let mut reader = proto::Reader::new(buf);
    let mut out = Vec::new();
    while let Some((field, wire)) = reader.tag()? {
        if field == 1 && wire == proto::WIRE_LEN {
            out.push(decode_any_value(reader.bytes()?)?);
        } else {
            reader.skip(wire)?;
        }
    }
    Ok(out)
}

/// `KeyValueList`。
///
/// # Errors
/// wire-format 非法。
pub fn decode_key_value_list(buf: &[u8]) -> DomainResult<Vec<(String, String)>> {
    let mut reader = proto::Reader::new(buf);
    let mut out = Vec::new();
    while let Some((field, wire)) = reader.tag()? {
        if field == 1 && wire == proto::WIRE_LEN {
            out.push(decode_key_value(reader.bytes()?)?);
        } else {
            reader.skip(wire)?;
        }
    }
    Ok(out)
}

/// `KeyValue`。
///
/// # Errors
/// wire-format 非法。
pub fn decode_key_value(buf: &[u8]) -> DomainResult<(String, String)> {
    let mut reader = proto::Reader::new(buf);
    let mut key = String::new();
    let mut value = String::new();
    while let Some((field, wire)) = reader.tag()? {
        match (field, wire) {
            (1, proto::WIRE_LEN) => key = reader.string()?,
            (2, proto::WIRE_LEN) => value = decode_any_value(reader.bytes()?)?,
            (_, other) => reader.skip(other)?,
        }
    }
    Ok((key, value))
}

/// `Resource`（attributes → `BTreeMap`）。
fn decode_resource(buf: &[u8], out: &mut BTreeMap<String, String>) -> DomainResult<()> {
    let mut reader = proto::Reader::new(buf);
    while let Some((field, wire)) = reader.tag()? {
        if field == 1 && wire == proto::WIRE_LEN {
            let (key, value) = decode_key_value(reader.bytes()?)?;
            out.insert(key, value);
        } else {
            reader.skip(wire)?;
        }
    }
    Ok(())
}

/// `InstrumentationScope`（name/version）。
fn decode_scope(buf: &[u8]) -> DomainResult<(Option<String>, Option<String>)> {
    let mut reader = proto::Reader::new(buf);
    let mut name = None;
    let mut version = None;
    while let Some((field, wire)) = reader.tag()? {
        match (field, wire) {
            (1, proto::WIRE_LEN) => name = Some(reader.string()?).filter(|s| !s.is_empty()),
            (2, proto::WIRE_LEN) => version = Some(reader.string()?).filter(|s| !s.is_empty()),
            (_, other) => reader.skip(other)?,
        }
    }
    Ok((name, version))
}
